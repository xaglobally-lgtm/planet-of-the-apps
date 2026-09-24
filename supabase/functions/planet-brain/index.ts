// Planet of the Apps — "brain" (Supabase Edge Function)
// Server-side jobs Planet's browser app must not do itself: holding service tokens and the Anthropic key,
// health/deploy/error monitoring, customer API keys, payment-provider sync, and the AI features.
//
// Security model
// - Every request must carry the signed-in user's Supabase token; we verify it and only ever touch rows owned by that user.
// - Service tokens live in Edge Function secrets (set by the owner in the Supabase dashboard), never in the browser.
// - Payment-provider keys are AES-GCM encrypted with a key derived (HKDF) from a server-only secret and stored in a
//   table the browser cannot read. They are never returned to the client.
// - AI features are read-only: they summarise and explain; they cannot change apps.
import { createClient } from 'npm:@supabase/supabase-js@2.46.1';

const env = (k: string) => Deno.env.get(k) || '';
const SUPABASE_URL = env('SUPABASE_URL');
const SERVICE_KEY = env('SUPABASE_SERVICE_ROLE_KEY');
const ANTHROPIC_KEY = env('ANTHROPIC_API_KEY');
const MODEL = env('PLANET_MODEL') || 'claude-sonnet-5';
const VERCEL_TOKEN = env('VERCEL_TOKEN');
const VERCEL_SLUG = env('VERCEL_TEAM_SLUG') || 'xaglobally-lgtm';
const RENDER_KEY = env('RENDER_API_KEY');
const GITHUB_TOKEN = env('GITHUB_TOKEN');
const ORIGINS = (env('PLANET_ORIGINS') || 'https://planet-of-the-apps.vercel.app,http://localhost:5173,http://localhost:3000').split(',');

const db = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

// ---------- http helpers ----------
function cors(req: Request) {
  const o = req.headers.get('origin') || '';
  return {
    'Access-Control-Allow-Origin': ORIGINS.includes(o) ? o : ORIGINS[0],
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    Vary: 'Origin',
  };
}
class HttpError extends Error { constructor(public status: number, msg: string) { super(msg); } }
const bad = (msg: string, status = 400) => new HttpError(status, msg);
const clip = (s: unknown, n = 300) => String(s ?? '').slice(0, n);
async function timed(url: string, init: RequestInit = {}, ms = 10000) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, { ...init, signal: AbortSignal.timeout(ms), redirect: 'follow' });
    return { r, ms: Date.now() - t0, timeout: false };
  } catch (e) {
    return { r: null as Response | null, ms: Date.now() - t0, timeout: (e as Error).name === 'TimeoutError', err: String(e) };
  }
}
function must<T>(res: { data: T; error: unknown }): T { if (res.error) throw res.error; return res.data; }

// ---------- per-user data ----------
async function apps(uid: string) { return must(await db.from('planet_apps').select('*').eq('owner', uid).order('sort_order')) as any[]; }
async function ownApp(uid: string, appId: string) {
  const a = must(await db.from('planet_apps').select('*').eq('owner', uid).eq('id', appId).maybeSingle());
  if (!a) throw bad('App not found', 404);
  return a as any;
}
const slugOf = (a: any) => (a.slug || '').trim();

// ---------- encryption for payment keys ----------
let _key: CryptoKey | null = null;
async function encKey() {
  if (_key) return _key;
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(env('PLANET_ENC_KEY') || SERVICE_KEY), 'HKDF', false, ['deriveKey']);
  _key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('planet-of-the-apps'), info: new TextEncoder().encode('payment-secrets-v1') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return _key;
}
const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function seal(text: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await encKey(), new TextEncoder().encode(text)));
  return { ciphertext: b64(ct), iv: b64(iv) };
}
async function unseal(ct: string, iv: string) {
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await encKey(), unb64(ct)));
}

// ---------- Claude ----------
async function claude(system: string, messages: { role: string; content: string }[], max_tokens = 1200) {
  if (!ANTHROPIC_KEY) throw bad('The Anthropic key is not set up yet. Add ANTHROPIC_API_KEY in Supabase → Edge Functions → Secrets.', 412);
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: MODEL, max_tokens, system, messages }),
    signal: AbortSignal.timeout(90000),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw bad(`Claude API error ${r.status}: ${clip(j?.error?.message || JSON.stringify(j), 200)}`, 502);
  return (j.content || []).filter((c: any) => c.type === 'text').map((c: any) => c.text).join('\n').trim();
}

// ---------- monitoring ----------
async function runChecks(uid: string, appId?: string) {
  const list = appId ? [await ownApp(uid, appId)] : await apps(uid);
  const rows: any[] = [];
  await Promise.all(list.map(async (a) => {
    if (a.frontend_url) {
      const { r, ms, timeout } = await timed(a.frontend_url, { method: 'GET' }, 10000);
      rows.push({ owner: uid, app_id: a.id, target: 'website', ms, status_code: r?.status ?? null,
        state: r && r.ok ? 'up' : 'down', detail: r ? (r.ok ? null : `HTTP ${r.status}`) : timeout ? 'No reply in 10s' : 'Unreachable' });
    }
    if (a.backend_url) {
      const url = a.backend_url.replace(/\/$/, '') + '/health';
      const { r, ms, timeout } = await timed(url, {}, 15000);
      let state = 'down', detail: string | null = null;
      if (r && r.ok) {
        const j = await r.json().catch(() => null);
        state = 'up';
        if (j?.status && j.status !== 'healthy') detail = `Reports "${j.status}"`;
      } else if (timeout || (r && (r.status === 502 || r.status === 503))) {
        state = 'asleep'; detail = 'Free service asleep or waking (normal on the free plan). This check wakes it.';
      } else detail = r ? `HTTP ${r.status}` : 'Unreachable';
      rows.push({ owner: uid, app_id: a.id, target: 'api', ms, status_code: r?.status ?? null, state, detail });
    }
  }));
  if (rows.length) must(await db.from('planet_checks').insert(rows));
  return rows;
}

async function addEvents(rows: any[]) {
  if (!rows.length) return 0;
  const { error } = await db.from('planet_events').upsert(rows, { onConflict: 'owner,source,external_id', ignoreDuplicates: true });
  if (error) throw error;
  return rows.length;
}

async function syncDeploys(uid: string) {
  const list = await apps(uid);
  const out: any = { vercel: VERCEL_TOKEN ? 'ok' : 'not configured', render: RENDER_KEY ? 'ok' : 'not configured', latest: {} };
  const events: any[] = [];
  await Promise.all(list.map(async (a) => {
    const latest: any = {};
    if (VERCEL_TOKEN && a.vercel_project) {
      const { r } = await timed(`https://api.vercel.com/v6/deployments?projectId=${encodeURIComponent(a.vercel_project)}&target=production&limit=1&slug=${VERCEL_SLUG}`,
        { headers: { Authorization: `Bearer ${VERCEL_TOKEN}` } }, 12000);
      const d = r && r.ok ? (await r.json()).deployments?.[0] : null;
      if (d) {
        latest.vercel = { state: d.state || d.readyState, at: d.created, message: d.meta?.githubCommitMessage || '' };
        events.push({ owner: uid, app_id: a.id, source: 'vercel', kind: 'deploy', external_id: d.uid,
          severity: (d.state || d.readyState) === 'ERROR' ? 'critical' : 'info',
          title: `Website deploy ${String(d.state || d.readyState).toLowerCase()}`, detail: clip(d.meta?.githubCommitMessage, 200),
          created_at: new Date(d.created).toISOString() });
      }
    }
    if (RENDER_KEY && a.render_service) {
      const h = { Authorization: `Bearer ${RENDER_KEY}`, Accept: 'application/json' };
      const { r } = await timed(`https://api.render.com/v1/services?name=${encodeURIComponent(a.render_service)}&limit=5`, { headers: h }, 12000);
      const svc = r && r.ok ? ((await r.json()) as any[]).map((x) => x.service).find((s) => s?.name === a.render_service) : null;
      if (svc) {
        const { r: r2 } = await timed(`https://api.render.com/v1/services/${svc.id}/deploys?limit=1`, { headers: h }, 12000);
        const d = r2 && r2.ok ? ((await r2.json()) as any[])[0]?.deploy : null;
        latest.render = { plan: svc.serviceDetails?.plan, suspended: svc.suspended, state: d?.status, at: d?.finishedAt || d?.createdAt };
        if (d) events.push({ owner: uid, app_id: a.id, source: 'render', kind: 'deploy', external_id: d.id,
          severity: /failed/.test(d.status) ? 'critical' : 'info',
          title: `API deploy ${String(d.status).replace(/_/g, ' ')}`, detail: clip(d.commit?.message, 200),
          created_at: d.finishedAt || d.createdAt });
      }
    }
    out.latest[a.id] = latest;
  }));
  await addEvents(events);
  return out;
}

async function syncErrors(uid: string) {
  const list = await apps(uid);
  const bySlug = new Map(list.filter(slugOf).map((a) => [slugOf(a), a]));
  if (!bySlug.size) return { errors: 0 };
  const since = new Date(Date.now() - 7 * 864e5).toISOString();
  const rows = must(await db.from('app_errors').select('id, app, error_code, message, severity, created_at')
    .in('app', [...bySlug.keys()]).gte('created_at', since).order('created_at', { ascending: false }).limit(300)) as any[];
  await addEvents(rows.map((e) => ({ owner: uid, app_id: bySlug.get(e.app)?.id, source: 'backend', kind: 'error', external_id: `err:${e.id}`,
    severity: e.severity === 'critical' ? 'critical' : 'warn', title: `API error: ${clip(e.error_code || 'UNKNOWN', 60)}`,
    detail: clip(e.message, 300), created_at: e.created_at })));
  return { errors: rows.length };
}

// ---------- customer API keys (xag_api_keys; app = slug) ----------
async function sha256hex(s: string) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
  return [...h].map((x) => x.toString(16).padStart(2, '0')).join('');
}
async function keysList(uid: string, appId: string) {
  const a = await ownApp(uid, appId);
  return must(await db.from('xag_api_keys').select('id, label, key_prefix, active, created_at, last_used_at, expires_at')
    .eq('app', slugOf(a)).order('created_at', { ascending: false }));
}
async function keysCreate(uid: string, appId: string, label?: string, expires_at?: string) {
  const a = await ownApp(uid, appId);
  if (!slugOf(a)) throw bad('This app has no short name (slug), which its backend uses to find its keys.');
  const raw = crypto.getRandomValues(new Uint8Array(24));
  const key = 'xag_' + b64(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const row = must(await db.from('xag_api_keys').insert({ app: slugOf(a), label: clip(label, 100) || null, key_prefix: key.slice(0, 10),
    key_hash: await sha256hex(key), expires_at: expires_at ? new Date(expires_at).toISOString() : null })
    .select('id, label, key_prefix, created_at, expires_at').single());
  return { ...row, key };
}
async function keysRevoke(uid: string, appId: string, keyId: string) {
  const a = await ownApp(uid, appId);
  const rows = must(await db.from('xag_api_keys').update({ active: false }).eq('id', keyId).eq('app', slugOf(a)).select('id')) as any[];
  if (!rows.length) throw bad('Key not found', 404);
  return { revoked: keyId, note: 'Backends cache key checks for up to 60 seconds.' };
}

// ---------- payments ----------
async function validateProvider(provider: string, apiKey: string) {
  if (provider === 'stripe') {
    const { r } = await timed('https://api.stripe.com/v1/balance', { headers: { Authorization: `Bearer ${apiKey}` } }, 12000);
    if (!r || !r.ok) throw bad('Stripe rejected that key. Use a restricted key with read access to Charges, Customers and Subscriptions.');
    return apiKey.startsWith('rk_') || apiKey.startsWith('sk_') ? (apiKey.includes('_test_') ? 'Stripe (test mode)' : 'Stripe (live)') : 'Stripe';
  }
  if (provider === 'lemonsqueezy') {
    const { r } = await timed('https://api.lemonsqueezy.com/v1/stores', { headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/vnd.api+json' } }, 12000);
    if (!r || !r.ok) throw bad('Lemon Squeezy rejected that key.');
    const j = await r.json(); return `Lemon Squeezy: ${(j.data || []).map((s: any) => s.attributes?.name).join(', ') || 'store'}`;
  }
  throw bad('Unknown provider');
}
async function payConnect(uid: string, b: any) {
  const a = await ownApp(uid, b.app_id);
  const provider = String(b.provider);
  const apiKey = String(b.api_key || '').trim();
  if (!apiKey) throw bad('Paste the API key');
  const label = await validateProvider(provider, apiKey);
  const filter = typeof b.filter === 'object' && b.filter ? b.filter : {};
  const link = must(await db.from('planet_payment_links').upsert({ owner: uid, app_id: a.id, provider, account_label: b.account_label || label,
    filter, status: 'connected', last_error: null }, { onConflict: 'app_id,provider' }).select().single()) as any;
  const sealed = await seal(apiKey);
  must(await db.from('planet_payment_secrets').upsert({ link_id: link.id, owner: uid, ...sealed }));
  return { link: { ...link }, synced: await paySync(uid, a.id).catch((e) => ({ error: String(e.message || e) })) };
}
async function payDisconnect(uid: string, appId: string, provider: string) {
  await ownApp(uid, appId);
  must(await db.from('planet_payment_links').delete().eq('owner', uid).eq('app_id', appId).eq('provider', provider));
  return { disconnected: true, note: 'Past revenue stays in Planet. Delete it separately if you want it gone.' };
}
const monthly = (amount: number, interval: string, count = 1) =>
  Math.round(amount * ({ day: 365 / 12, week: 52 / 12, month: 1, year: 1 / 12 } as any)[interval] / (count || 1));

async function stripeGet(key: string, path: string, params: Record<string, string>) {
  const out: any[] = [];
  let after = '';
  for (let page = 0; page < 20; page++) {
    const q = new URLSearchParams({ limit: '100', ...params, ...(after ? { starting_after: after } : {}) });
    const { r } = await timed(`https://api.stripe.com/v1/${path}?${q}`, { headers: { Authorization: `Bearer ${key}` } }, 20000);
    if (!r || !r.ok) throw new Error(`Stripe ${path} failed${r ? ' (' + r.status + ')' : ''}`);
    const j = await r.json(); out.push(...j.data);
    if (!j.has_more || !j.data.length) break;
    after = j.data[j.data.length - 1].id;
  }
  return out;
}
async function lsGet(key: string, path: string, params: Record<string, string>) {
  const out: any[] = [];
  for (let page = 1; page <= 20; page++) {
    const q = new URLSearchParams({ 'page[size]': '100', 'page[number]': String(page), ...params });
    const { r } = await timed(`https://api.lemonsqueezy.com/v1/${path}?${q}`, { headers: { Authorization: `Bearer ${key}`, Accept: 'application/vnd.api+json' } }, 20000);
    if (!r || !r.ok) throw new Error(`Lemon Squeezy ${path} failed${r ? ' (' + r.status + ')' : ''}`);
    const j = await r.json(); out.push(...(j.data || []));
    if (!j.meta?.page || page >= j.meta.page.lastPage) break;
  }
  return out;
}
async function paySync(uid: string, appId?: string) {
  let q = db.from('planet_payment_links').select('*').eq('owner', uid);
  if (appId) q = q.eq('app_id', appId);
  const links = must(await q) as any[];
  const results: any[] = [];
  for (const L of links) {
    try {
      const sec = must(await db.from('planet_payment_secrets').select('*').eq('link_id', L.id).maybeSingle()) as any;
      if (!sec) throw new Error('Key missing; reconnect this provider');
      const key = await unseal(sec.ciphertext, sec.iv);
      const since = L.last_sync_at ? Math.floor(new Date(L.last_sync_at).getTime() / 1000) - 86400 * 3 : Math.floor(Date.now() / 1000) - 86400 * 400;
      const rev: any[] = [], cust: any[] = [];
      const f = L.filter || {};
      if (L.provider === 'stripe') {
        const charges = (await stripeGet(key, 'charges', { 'created[gte]': String(since) }))
          .filter((c) => c.paid && c.status === 'succeeded' && (!f.metadata_app || c.metadata?.app === f.metadata_app));
        for (const c of charges) {
          const at = new Date(c.created * 1000).toISOString();
          rev.push({ owner: uid, app_id: L.app_id, provider: 'stripe', external_id: c.id, kind: c.invoice ? 'subscription_payment' : 'sale',
            amount_cents: c.amount_captured ?? c.amount, currency: c.currency, customer_ref: c.customer || null, occurred_at: at });
          if (c.amount_refunded > 0) rev.push({ owner: uid, app_id: L.app_id, provider: 'stripe', external_id: `${c.id}:refund`, kind: 'refund',
            amount_cents: -c.amount_refunded, currency: c.currency, customer_ref: c.customer || null, occurred_at: at });
          if (!c.invoice) cust.push({ owner: uid, app_id: L.app_id, provider: 'stripe', external_id: c.customer || `guest:${c.id}`, status: 'one_time', mrr_cents: 0, started_at: at });
        }
        const subs = (await stripeGet(key, 'subscriptions', { status: 'all' }))
          .filter((s) => !f.metadata_app || s.metadata?.app === f.metadata_app);
        for (const s of subs) {
          const mrr = ['active', 'trialing', 'past_due'].includes(s.status)
            ? (s.items?.data || []).reduce((t: number, it: any) => t + monthly((it.price?.unit_amount || 0) * (it.quantity || 1), it.price?.recurring?.interval || 'month', it.price?.recurring?.interval_count), 0) : 0;
          cust.push({ owner: uid, app_id: L.app_id, provider: 'stripe', external_id: s.customer, status: s.status, mrr_cents: mrr, started_at: new Date(s.start_date * 1000).toISOString() });
        }
      } else {
        const store: Record<string, string> = f.store_id ? { 'filter[store_id]': String(f.store_id) } : {};
        const orders = (await lsGet(key, 'orders', store)).filter((o) => !f.product_id || String(o.attributes?.first_order_item?.product_id) === String(f.product_id));
        for (const o of orders) {
          const at = o.attributes.created_at;
          if (o.attributes.status === 'pending' || o.attributes.status === 'failed') continue;
          rev.push({ owner: uid, app_id: L.app_id, provider: 'lemonsqueezy', external_id: `order:${o.id}`, kind: 'sale', amount_cents: o.attributes.total,
            currency: String(o.attributes.currency || 'usd').toLowerCase(), customer_ref: String(o.attributes.customer_id || ''), occurred_at: at });
          if (o.attributes.refunded_amount > 0) rev.push({ owner: uid, app_id: L.app_id, provider: 'lemonsqueezy', external_id: `order:${o.id}:refund`, kind: 'refund',
            amount_cents: -o.attributes.refunded_amount, currency: String(o.attributes.currency || 'usd').toLowerCase(), customer_ref: String(o.attributes.customer_id || ''), occurred_at: at });
        }
        const subs = (await lsGet(key, 'subscriptions', store)).filter((s) => !f.product_id || String(s.attributes?.product_id) === String(f.product_id));
        for (const s of subs) cust.push({ owner: uid, app_id: L.app_id, provider: 'lemonsqueezy', external_id: `cust:${s.attributes.customer_id}`,
          status: s.attributes.status, mrr_cents: 0, started_at: s.attributes.created_at });
      }
      const dedupe = (arr: any[], k: (x: any) => string) => [...new Map(arr.map((x) => [k(x), x])).values()];
      if (rev.length) must(await db.from('planet_revenue').upsert(dedupe(rev, (x) => x.provider + x.external_id), { onConflict: 'provider,external_id' }));
      if (cust.length) must(await db.from('planet_customers').upsert(dedupe(cust, (x) => x.provider + x.external_id + x.app_id), { onConflict: 'provider,external_id,app_id' }));
      must(await db.from('planet_payment_links').update({ last_sync_at: new Date().toISOString(), last_error: null, status: 'connected' }).eq('id', L.id));
      results.push({ app_id: L.app_id, provider: L.provider, revenue_rows: rev.length, customers: cust.length });
    } catch (e) {
      await db.from('planet_payment_links').update({ last_error: clip((e as Error).message, 300), status: 'error' }).eq('id', L.id);
      results.push({ app_id: L.app_id, provider: L.provider, error: (e as Error).message });
    }
  }
  return results;
}

// ---------- AI context & features ----------
async function snapshot(uid: string) {
  const list = await apps(uid);
  const since30 = new Date(Date.now() - 30 * 864e5).toISOString();
  const [checks, events, revenue, customers, expenses, links, perms] = await Promise.all([
    db.from('planet_checks').select('app_id, target, state, detail, checked_at').eq('owner', uid).order('checked_at', { ascending: false }).limit(200),
    db.from('planet_events').select('app_id, source, kind, severity, title, detail, created_at').eq('owner', uid).order('created_at', { ascending: false }).limit(60),
    db.from('planet_revenue').select('app_id, kind, amount_cents, currency, occurred_at').eq('owner', uid).gte('occurred_at', since30),
    db.from('planet_customers').select('app_id, status, mrr_cents').eq('owner', uid),
    db.from('planet_expenses').select('app_id, vendor, category, amount_cents, currency, cadence, ends_on').eq('owner', uid),
    db.from('planet_payment_links').select('app_id, provider, status, last_sync_at, last_error').eq('owner', uid),
    db.from('planet_permissions').select('app_id, service, scope, level, granted_to').eq('owner', uid),
  ]);
  const name = new Map(list.map((a) => [a.id, a.name]));
  const latest: Record<string, any> = {};
  for (const c of checks.data || []) { const k = c.app_id + c.target; if (!latest[k]) latest[k] = c; }
  return {
    today: new Date().toISOString().slice(0, 10),
    apps: list.map((a) => ({ name: a.name, slug: a.slug, category: a.category, status: a.status, website: a.frontend_url, api: a.backend_url,
      repo: a.github_repo, ai_level: a.ai_level, tags: a.tags, website_check: latest[a.id + 'website'] || 'never checked', api_check: latest[a.id + 'api'] || 'never checked',
      payments: (links.data || []).filter((l) => l.app_id === a.id).map((l) => ({ provider: l.provider, status: l.status, last_sync_at: l.last_sync_at, error: l.last_error })) })),
    recent_events: (events.data || []).map((e) => ({ ...e, app: name.get(e.app_id) || 'portfolio', app_id: undefined })),
    revenue_last_30_days: (revenue.data || []).map((r) => ({ app: name.get(r.app_id), kind: r.kind, amount: r.amount_cents / 100, currency: r.currency, at: r.occurred_at })),
    customers: (customers.data || []).map((c) => ({ app: name.get(c.app_id), status: c.status, mrr: (c.mrr_cents || 0) / 100 })),
    expenses: (expenses.data || []).map((x) => ({ ...x, app: x.app_id ? name.get(x.app_id) : 'shared', app_id: undefined, amount: x.amount_cents / 100, amount_cents: undefined })),
    access_records: (perms.data || []).length,
  };
}
const PERSONA = `You are Planet, the operations assistant inside "Planet of the Apps", a private control centre for one person's portfolio of web apps.
Speak plainly and warmly to a capable non-programmer. Be concise. Never invent numbers or facts: use only the data provided, and say clearly when something is not connected or has never been checked.
You are read-only: you cannot change apps, deploy, or move money. When asked to do something, say which Planet screen or step does it.
Free-plan API services sleep when idle; an "asleep" check is normal, not an outage. Money amounts are in the currency given.`;

async function ask(uid: string, question: string) {
  question = clip(question, 2000).trim();
  if (!question) throw bad('Ask a question');
  const snap = await snapshot(uid);
  const hist = (must(await db.from('planet_chat').select('role, content').eq('owner', uid).order('created_at', { ascending: false }).limit(10)) as any[]).reverse();
  const answer = await claude(`${PERSONA}\n\nCurrent portfolio data (JSON):\n${JSON.stringify(snap)}`,
    [...hist.map((h) => ({ role: h.role, content: h.content })), { role: 'user', content: question }], 1200);
  must(await db.from('planet_chat').insert([{ owner: uid, role: 'user', content: question }, { owner: uid, role: 'assistant', content: answer }]));
  return { answer };
}
async function briefing(uid: string, force = false) {
  const last = must(await db.from('planet_briefings').select('*').eq('owner', uid).order('created_at', { ascending: false }).limit(1).maybeSingle()) as any;
  if (!force && last && Date.now() - new Date(last.created_at).getTime() < 20 * 3600e3) return { briefing: last, fresh: false };
  const snap = await snapshot(uid);
  const content = await claude(`${PERSONA}\n\nPortfolio data (JSON):\n${JSON.stringify(snap)}`, [{ role: 'user', content:
    `Write my daily briefing. Format exactly:
Line 1: a one-sentence overall status.
Then up to 5 numbered items, most important first, each one line: what needs attention and the next step in Planet. If nothing needs attention, say so in one line.
Last line: one sentence on money (revenue/expenses), or say payments aren't connected yet.
Plain text only, no markdown symbols, under 170 words.` }], 700);
  const row = must(await db.from('planet_briefings').insert({ owner: uid, content }).select().single());
  return { briefing: row, fresh: true };
}
async function fetchRepoFile(repo: string, path: string) {
  const h: Record<string, string> = GITHUB_TOKEN ? { Authorization: `Bearer ${GITHUB_TOKEN}` } : {};
  const { r } = await timed(`https://raw.githubusercontent.com/${repo}/HEAD/${path}`, { headers: h }, 12000);
  return r && r.ok ? (await r.text()).slice(0, 20000) : null;
}
async function explain(uid: string, appId: string) {
  const a = await ownApp(uid, appId);
  if (!a.github_repo) throw bad('Add this app\'s GitHub repo (owner/name) first');
  const files = ['README.md', 'backend/src/server.ts', 'frontend/src/App.tsx', 'backend/package.json', 'frontend/package.json'];
  const got = (await Promise.all(files.map(async (p) => [p, await fetchRepoFile(a.github_repo, p)] as const))).filter(([, t]) => t);
  if (!got.length) throw bad('Could not read the repo. If it is private, add a GITHUB_TOKEN secret.');
  const text = await claude(`${PERSONA}\nYou explain software to its non-technical owner using the source files provided.`, [{ role: 'user', content:
    `Explain the app "${a.name}" in plain English for its owner.\nSections (plain text headings followed by a colon): What it does, The main parts, Where its data lives, What it connects to, What is still a placeholder or missing, Risks to know about.\nShort sentences. No code. Under 400 words.\n\n` +
    got.map(([p, t]) => `=== ${p} ===\n${t}`).join('\n\n') }], 1500);
  const title = 'Plain-English explanation (AI)';
  await db.from('planet_items').delete().eq('owner', uid).eq('app_id', a.id).eq('title', title);
  must(await db.from('planet_items').insert({ owner: uid, app_id: a.id, kind: 'doc', title, body: text }));
  return { explanation: text };
}

// ---------- router ----------
Deno.serve(async (req) => {
  const h = cors(req);
  if (req.method === 'OPTIONS') return new Response('ok', { headers: h });
  const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { ...h, 'Content-Type': 'application/json' } });
  try {
    if (req.method !== 'POST') throw bad('POST only', 405);
    const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const { data: u, error: ue } = await db.auth.getUser(token);
    if (ue || !u?.user) throw bad('Please sign in again', 401);
    const uid = u.user.id;
    const b = await req.json().catch(() => ({}));
    switch (b.action) {
      case 'status': return json({ model: MODEL, configured: { anthropic: !!ANTHROPIC_KEY, vercel: !!VERCEL_TOKEN, render: !!RENDER_KEY, github: !!GITHUB_TOKEN } });
      case 'run_checks': return json({ checks: await runChecks(uid, b.app_id) });
      case 'sync_deploys': return json(await syncDeploys(uid));
      case 'sync_errors': return json(await syncErrors(uid));
      case 'refresh_all': {
        const r: any = {};
        const lastCheck = must(await db.from('planet_checks').select('checked_at').eq('owner', uid).order('checked_at', { ascending: false }).limit(1).maybeSingle()) as any;
        const hours = Math.max(1, Number(b.check_every_hours) || 6);
        if (b.force_checks || !lastCheck || Date.now() - new Date(lastCheck.checked_at).getTime() > hours * 3600e3) r.checks = (await runChecks(uid)).length;
        else r.checks = 'skipped (checked recently)';
        r.deploys = await syncDeploys(uid).then((x) => ({ vercel: x.vercel, render: x.render })).catch((e) => String(e.message || e));
        r.errors = await syncErrors(uid).catch((e) => String(e.message || e));
        r.payments = await paySync(uid).catch((e) => String(e.message || e));
        return json(r);
      }
      case 'keys_list': return json({ keys: await keysList(uid, b.app_id) });
      case 'keys_create': return json(await keysCreate(uid, b.app_id, b.label, b.expires_at));
      case 'keys_revoke': return json(await keysRevoke(uid, b.app_id, b.key_id));
      case 'pay_connect': return json(await payConnect(uid, b));
      case 'pay_disconnect': return json(await payDisconnect(uid, b.app_id, b.provider));
      case 'pay_sync': return json({ results: await paySync(uid, b.app_id) });
      case 'ask': return json(await ask(uid, b.question));
      case 'chat_clear': must(await db.from('planet_chat').delete().eq('owner', uid)); return json({ cleared: true });
      case 'briefing': return json(await briefing(uid, !!b.force));
      case 'explain': return json(await explain(uid, b.app_id));
      default: throw bad('Unknown action');
    }
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    const msg = e instanceof HttpError ? e.message : `Something went wrong: ${clip((e as any)?.message || e, 200)}`;
    if (status === 500) console.error(e);
    return json({ error: msg }, status);
  }
});

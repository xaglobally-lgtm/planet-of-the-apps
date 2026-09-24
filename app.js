// Planet of the Apps — "One app to rule them all"
// Static PWA: no build step. Data lives in Supabase (planet_* tables, owner-only RLS).
// Secret values are encrypted in the browser (PBKDF2 + AES-GCM) before they are saved;
// the database only ever holds ciphertext, and the vault passphrase is never stored.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.46.1';

const SUPABASE_URL = 'https://iwpfhalextbzbvcajtxu.supabase.co';
// Public (anon) key: safe in a browser; row-level security limits every row to its owner.
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Iml3cGZoYWxleHRiemJ2Y2FqdHh1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODk4NzY1MjcsImV4cCI6MjEwNTQ1MjUyN30.Gi717bXdX-WFCAc6wd7uAY-DiOokH5htMbX4bD7psZo';
const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true } });

// ---------- defaults ----------
const DEFAULT_PREFS = {
  theme: 'auto',
  labels: false,
  categories: ['Vertical SaaS', 'XAG capability', 'Education', 'Business', 'Personal', 'Uncategorised'],
  statuses: ['Idea', 'Building', 'Frontend live', 'Fully live', 'Paused', 'Retired'],
  liveStatuses: ['Frontend live', 'Fully live'],
  fields: [
    { key: 'price', label: 'Price / plan', type: 'text' },
    { key: 'launch_date', label: 'Launch date', type: 'date' },
  ],
};
const PALETTE = ['#7c5cff', '#f2b84b', '#62d6c6', '#ff8193', '#6aa8ff', '#b784f7', '#8fd46b', '#ff9f5a'];
const ITEM_KINDS = { note: 'Note', link: 'Link', code: 'Code snippet', doc: 'Document', contact: 'Contact', task: 'Task' };
const LEVELS = ['read', 'write', 'admin', 'owner'];

const V = (name) => `https://${name}.vercel.app`;
const STARTER = [
  ['ReputationPilot — Med Spas', 'reputationpilot-med-spas', 'Vertical SaaS', '⭐'],
  ['QuoteFlow — Home Builders', 'quoteflow-home-builders', 'Vertical SaaS', '🏗️'],
  ['ComplyTrack — HVAC Contractors', 'complytrack-hvac-contractors', 'Vertical SaaS', '🌡️'],
  ['PipelineDesk — Insurance Agents', 'pipelinedesk-insurance-agents', 'Vertical SaaS', '🛡️'],
  ['MemberFlow — Personal Trainers', 'memberflow-personal-trainers', 'Vertical SaaS', '🏋️'],
  ['Dispute Arbiter', 'xag-dispute-arbiter', 'XAG capability', '⚖️'],
  ['Spend Guardian', 'xag-spend-guardian', 'XAG capability', '💳'],
  ['Webhook Promise Monitor', 'xag-webhook-promise-monitor', 'XAG capability', '🪝'],
  ['Schema Contract Guard', 'xag-schema-contract-guard', 'XAG capability', '📐'],
  ['Replay Attack Detector', 'xag-replay-attack-detector', 'XAG capability', '🔁'],
  ['Cost Anomaly Meter', 'xag-cost-anomaly-meter', 'XAG capability', '📈'],
  ['Delegation Expiry Watch', 'xag-delegation-expiry-watch', 'XAG capability', '⏳'],
  ['Escrow Signal', 'xag-escrow-signal', 'XAG capability', '🔐'],
  ['Capability SLA Bond', 'xag-capability-sla-bond', 'XAG capability', '📜'],
].map(([name, slug, category, icon], i) => ({
  name, slug, category, icon, status: 'Fully live', color: PALETTE[i % PALETTE.length],
  frontend_url: V(slug), backend_url: `https://${slug}-api.onrender.com`, render_service: `${slug}-api`,
  github_repo: `xaglobally-lgtm/${slug}`, vercel_project: slug,
  supabase_prefix: slug.replace(/^xag-/, 'xag_').replace(/-/g, '_') + '_',
  tech: ['React', 'Vite', 'Express', 'Supabase'], tags: [], sort_order: i,
}));

// ---------- state ----------
const S = {
  session: null, apps: [], perms: [], items: [], secrets: [], settings: null, prefs: { ...DEFAULT_PREFS },
  page: localStorage.getItem('planet.page') || 'orbit', q: '', cat: '', status: '', sort: 'name',
  openId: null, tab: 'overview', focusCat: '', vaultKey: null, revealed: {}, installPrompt: null,
};

// ---------- helpers ----------
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeUrl = (u) => { try { const x = new URL(u); return /^https?:$/.test(x.protocol) ? x.href : ''; } catch { return ''; } };
const csv = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
const byId = (id) => S.apps.find((a) => a.id === id);
const isLive = (a) => (S.prefs.liveStatuses || []).includes(a.status);
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove('show'), 2600); }
function fail(e) { console.error(e); toast(e?.message || String(e)); }
function applyTheme() { document.documentElement.dataset.theme = S.prefs.theme || 'auto'; }

// ---------- crypto (vault) ----------
const te = new TextEncoder(), td = new TextDecoder();
const b64 = (buf) => { const b = new Uint8Array(buf); let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function deriveKey(pass, saltB64) {
  const base = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: unb64(saltB64), iterations: 310000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encrypt(key, text) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(text)); return { ciphertext: b64(ct), iv: b64(iv) }; }
async function decrypt(key, ct, iv) { return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(ct))); }
const VAULT_CHECK = 'planet-vault-ok';

// ---------- data ----------
async function loadAll() {
  const [apps, perms, items, secrets, settings] = await Promise.all([
    sb.from('planet_apps').select('*').order('sort_order').order('name'),
    sb.from('planet_permissions').select('*').order('created_at'),
    sb.from('planet_items').select('*').order('created_at', { ascending: false }),
    sb.from('planet_secrets').select('*').order('label'),
    sb.from('planet_settings').select('*').maybeSingle(),
  ]);
  for (const r of [apps, perms, items, secrets, settings]) if (r.error) throw r.error;
  S.apps = apps.data; S.perms = perms.data; S.items = items.data; S.secrets = secrets.data;
  if (!settings.data) {
    const ins = await sb.from('planet_settings').insert({ prefs: DEFAULT_PREFS }).select().single();
    if (ins.error) throw ins.error;
    S.settings = ins.data;
  } else S.settings = settings.data;
  S.prefs = { ...DEFAULT_PREFS, ...(S.settings.prefs || {}) };
  applyTheme();
}
async function savePrefs(patch) {
  S.prefs = { ...S.prefs, ...patch };
  applyTheme();
  const { error } = await sb.from('planet_settings').update({ prefs: S.prefs, updated_at: new Date().toISOString() }).eq('owner', S.session.user.id);
  if (error) fail(error);
}
async function mutate(table, op, payload, id) {
  let q = sb.from(table);
  if (op === 'insert') q = q.insert(payload);
  else if (op === 'update') q = q.update({ ...payload, ...(table === 'planet_apps' || table === 'planet_items' || table === 'planet_secrets' ? { updated_at: new Date().toISOString() } : {}) }).eq('id', id);
  else if (op === 'delete') q = q.delete().eq('id', id);
  const { error } = await q;
  if (error) throw error;
  await loadAll();
  render();
}

// ---------- rendering ----------
const NAV = [
  ['orbit', '🪐', 'Planet'], ['apps', '▦', 'Apps'], ['permissions', '🔑', 'Access'], ['vault', '🔒', 'Codes'], ['settings', '⚙️', 'Settings'],
];
const MARK = `<svg class="brand-mark" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="15" fill="#f2b84b"/><ellipse cx="32" cy="32" rx="29" ry="9" fill="none" stroke="#62d6c6" stroke-width="3" transform="rotate(-20 32 32)"/><circle cx="55" cy="22" r="4" fill="#ff8193"/></svg>`;

function render() {
  const root = $('#app');
  if (!S.session) { root.innerHTML = authView(); return; }
  const nav = (cls) => NAV.map(([k, ico, label]) => `<button class="nav-btn ${cls}" data-act="nav" data-page="${k}" ${S.page === k ? 'aria-current="page"' : ''}><span class="ico" aria-hidden="true">${ico}</span><span>${label}</span></button>`).join('');
  const pages = { orbit: orbitView, apps: appsView, permissions: permsView, vault: vaultView, settings: settingsView };
  root.innerHTML = `
    <div class="shell">
      <nav class="rail" aria-label="Main">
        <div class="brand">${MARK}<div><strong>Planet of the Apps</strong><div class="small muted">One app to rule them all</div></div></div>
        ${nav('')}
        <div class="spacer"></div>
        ${S.installPrompt ? `<button class="btn sm" data-act="install">Install app</button>` : ''}
        <p class="small muted" style="padding:0.5rem 0.4rem">${esc(S.session.user.email)}</p>
      </nav>
      <main class="main" id="main">${(pages[S.page] || orbitView)()}</main>
      <nav class="bottom-nav" aria-label="Main">${nav('')}</nav>
    </div>
    ${S.openId ? drawerView() : ''}`;
}

function authView() {
  return `<div class="auth"><form class="auth-card panel" data-form="auth">
    <div class="brand">${MARK}<div><h1>Planet of the Apps</h1><p class="muted">One app to rule them all</p></div></div>
    <p>Sign in to see every app you run, who can access what, and the codes that keep them going.</p>
    <label class="field"><span>Email</span><input name="email" type="email" autocomplete="email" required /></label>
    <label class="field"><span>Password</span><input name="password" type="password" autocomplete="current-password" minlength="8" /></label>
    <div class="row"><button class="btn primary" name="mode" value="signin">Sign in</button><button class="btn" name="mode" value="signup">Create account</button></div>
    <button class="btn ghost sm" name="mode" value="magic">Email me a sign-in link instead</button>
    <p class="small" id="auth-msg" role="alert">${esc(S.authMsg || '')}</p>
  </form></div>`;
}

function filtered() {
  const q = S.q.toLowerCase();
  let list = S.apps.filter((a) =>
    (!S.cat || a.category === S.cat) && (!S.status || a.status === S.status) &&
    (!q || [a.name, a.slug, a.tagline, a.description, a.category, (a.tags || []).join(' '), (a.tech || []).join(' ')].join(' ').toLowerCase().includes(q)));
  const k = S.sort;
  list.sort((a, b) => (b.pinned - a.pinned) || (k === 'updated' ? String(b.updated_at).localeCompare(a.updated_at) : String(a[k] ?? '').localeCompare(String(b[k] ?? ''))));
  return list;
}

function orbitView() {
  const cats = [...new Set(S.apps.map((a) => a.category || 'Uncategorised'))];
  const live = S.apps.filter(isLive).length;
  if (!S.apps.length) return emptyState();
  const n = cats.length;
  const rings = cats.map((c, i) => { const r = 24 + (i + 1) * (72 / (n + 0.5)); return { c, r }; });
  let bodies = '', idx = 0;
  rings.forEach(({ c, r }, ri) => {
    const apps = S.apps.filter((a) => (a.category || 'Uncategorised') === c);
    apps.forEach((a, j) => {
      const ang = (j / apps.length) * Math.PI * 2 + ri * 0.7 - Math.PI / 2;
      const x = 50 + (r / 2) * Math.cos(ang), y = 50 + (r / 2) * Math.sin(ang);
      const dim = S.focusCat && S.focusCat !== c;
      bodies += `<button class="body" style="left:${x}%;top:${y}%;--c:${esc(a.color)};--i:${idx++};${dim ? 'opacity:.25' : ''}" data-act="open" data-id="${a.id}" data-live="${isLive(a) ? 1 : 0}" aria-label="${esc(a.name)}, ${esc(a.status)}"><span class="disc" aria-hidden="true">${esc(a.icon || '🪐')}</span><span class="lbl">${esc(a.name)}</span></button>`;
    });
  });
  const ringHtml = rings.map(({ r }) => `<div class="ring" style="width:${r}%;height:${r}%"></div>`).join('');
  return `
    <div class="page-head"><div><h1>Your planet</h1>
      <div class="stat-line"><span><b>${S.apps.length}</b><span class="muted small">apps</span></span><span><b>${live}</b><span class="muted small">live</span></span><span><b>${cats.length}</b><span class="muted small">categories</span></span><span><b>${S.secrets.length}</b><span class="muted small">codes stored</span></span></div></div>
      <div class="row"><button class="btn" data-act="toggle-labels">${S.prefs.labels ? 'Hide names' : 'Show names'}</button><button class="btn primary" data-act="new-app">Add app</button></div></div>
    <div class="orbit-wrap">
      <div class="orbit ${S.prefs.labels ? 'labels' : ''} ${S._revealed ? '' : 'reveal'}" role="group" aria-label="Apps arranged by category">${ringHtml}<div class="sun" aria-hidden="true">Planet<br/>of the<br/>Apps</div>${bodies}</div>
      <div class="legend"><h3>Categories</h3><p class="small muted">Inner ring first. Tap a category to highlight it; tap an app to open it. A teal ring means it's live.</p>
        ${cats.map((c) => `<button data-act="focus-cat" data-cat="${esc(c)}" aria-pressed="${S.focusCat === c}"><span>${esc(c)}</span><span class="pill">${S.apps.filter((a) => (a.category || 'Uncategorised') === c).length}</span></button>`).join('')}
      </div>
    </div>`;
}

function emptyState() {
  return `<div class="page-head"><h1>Your planet</h1></div><div class="empty"><h2>No apps in orbit yet</h2>
    <p class="muted">Load the 14 apps already deployed, or add your first one by hand.</p>
    <div class="row"><button class="btn primary" data-act="seed">Load my 14 deployed apps</button><button class="btn" data-act="new-app">Add an app</button></div></div>`;
}

function appsView() {
  const list = filtered();
  const opt = (arr, v) => arr.map((x) => `<option ${x === v ? 'selected' : ''}>${esc(x)}</option>`).join('');
  const cats = [...new Set([...S.prefs.categories, ...S.apps.map((a) => a.category)])].filter(Boolean);
  return `
    <div class="page-head"><div><h1>All apps</h1><p class="muted">${S.apps.length} in total${list.length !== S.apps.length ? `, ${list.length} shown` : ''}</p></div>
      <div class="row"><button class="btn" data-act="export">Export</button><button class="btn primary" data-act="new-app">Add app</button></div></div>
    <div class="toolbar">
      <input type="search" placeholder="Search names, tags, tech…" value="${esc(S.q)}" data-bind="q" aria-label="Search apps" />
      <select data-bind="cat" aria-label="Category"><option value="">All categories</option>${opt(cats, S.cat)}</select>
      <select data-bind="status" aria-label="Status"><option value="">All statuses</option>${opt(S.prefs.statuses, S.status)}</select>
      <select data-bind="sort" aria-label="Sort by">${[['name', 'Name'], ['category', 'Category'], ['status', 'Status'], ['updated', 'Recently changed']].map(([v, l]) => `<option value="${v}" ${S.sort === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
    </div>
    ${S.apps.length ? '' : emptyState()}
    <div class="app-list">${list.map((a) => `
      <button class="app-row" data-act="open" data-id="${a.id}" style="--c:${esc(a.color)}">
        <span class="disc" aria-hidden="true">${esc(a.icon || '🪐')}</span>
        <span class="meta"><strong>${a.pinned ? '📌 ' : ''}${esc(a.name)}</strong><span>${esc(a.category || 'Uncategorised')}${a.tagline ? ' — ' + esc(a.tagline) : ''}</span></span>
        <span class="pill ${isLive(a) ? 'live' : ''}">${esc(a.status)}</span>
      </button>`).join('')}</div>`;
}

function permsView() {
  const rows = S.perms.map((p) => ({ ...p, app: byId(p.app_id) }));
  return `
    <div class="page-head"><div><h1>Access &amp; permissions</h1><p class="muted">Every service each app touches, and who holds the keys.</p></div>
      <button class="btn primary" data-act="new-perm">Add permission</button></div>
    ${rows.length ? `<div class="table-wrap"><table><thead><tr><th>App</th><th>Service</th><th>Scope</th><th>Level</th><th>Held by</th><th>Notes</th><th></th></tr></thead><tbody>
      ${rows.map((p) => `<tr><td>${p.app ? `<a href="#" data-act="open" data-id="${p.app.id}">${esc(p.app.name)}</a>` : '<span class="muted">All apps</span>'}</td><td>${esc(p.service)}</td><td>${esc(p.scope)}</td><td><span class="pill">${esc(p.level)}</span></td><td>${esc(p.granted_to)}</td><td>${esc(p.notes)}</td>
        <td><div class="row"><button class="btn sm" data-act="edit-perm" data-id="${p.id}">Edit</button><button class="btn sm danger" data-act="del-perm" data-id="${p.id}">Delete</button></div></td></tr>`).join('')}
    </tbody></table></div>` : `<div class="empty"><h2>No permissions recorded</h2><p class="muted">Record what each app can reach: Supabase tables, Stripe, email, GitHub, Vercel, Render.</p><button class="btn primary" data-act="new-perm">Add permission</button></div>`}`;
}

function vaultBanner() {
  if (!S.settings.vault_salt) return `<div class="panel stack"><h2>Set up your code vault</h2><p class="muted">Codes (API keys, PINs, passwords) are locked in this browser with a passphrase before they're saved. Nobody, including the database owner, can read them without it. If you forget the passphrase, stored codes can't be recovered.</p>
    <form class="row" data-form="vault-setup"><input name="pass" type="password" minlength="10" placeholder="New passphrase (10+ characters)" required style="flex:1 1 240px" autocomplete="new-password" /><input name="pass2" type="password" placeholder="Repeat passphrase" required style="flex:1 1 200px" autocomplete="new-password" /><button class="btn primary">Create vault</button></form></div>`;
  if (!S.vaultKey) return `<div class="panel stack"><h2>Vault locked</h2><p class="muted">Enter your passphrase to add, reveal or copy codes. It stays unlocked until you close or reload the app.</p>
    <form class="row" data-form="vault-unlock"><input name="pass" type="password" placeholder="Passphrase" required style="flex:1 1 240px" autocomplete="current-password" /><button class="btn primary">Unlock</button></form></div>`;
  return `<div class="row" style="justify-content:space-between"><p class="muted">Vault unlocked on this device.</p><button class="btn sm" data-act="lock">Lock vault</button></div>`;
}

function secretsTable(list) {
  if (!list.length) return `<p class="muted">No codes stored yet.</p>`;
  return `<div class="table-wrap"><table><thead><tr><th>Label</th><th>Variable name</th><th>App</th><th>Used in</th><th>Value</th><th></th></tr></thead><tbody>
    ${list.map((s) => { const a = byId(s.app_id); const shown = S.revealed[s.id]; return `<tr><td>${esc(s.label)}</td><td class="code">${esc(s.env_name)}</td><td>${a ? esc(a.name) : '<span class="muted">Shared</span>'}</td><td>${esc(s.where_used)}</td>
      <td class="secret-val">${shown != null ? esc(shown) : '••••••••'}</td>
      <td><div class="row"><button class="btn sm" data-act="reveal" data-id="${s.id}" ${S.vaultKey ? '' : 'disabled'}>${shown != null ? 'Hide' : 'Reveal'}</button><button class="btn sm" data-act="copy-secret" data-id="${s.id}" ${S.vaultKey ? '' : 'disabled'}>Copy</button><button class="btn sm danger" data-act="del-secret" data-id="${s.id}">Delete</button></div></td></tr>`; }).join('')}
  </tbody></table></div>`;
}

function vaultView() {
  return `<div class="page-head"><div><h1>Codes &amp; keys</h1><p class="muted">API keys, PINs and passwords for every app, encrypted before they leave this device.</p></div>
    <button class="btn primary" data-act="new-secret" ${S.vaultKey ? '' : 'disabled'}>Add code</button></div>
    <div class="stack">${vaultBanner()}${secretsTable(S.secrets)}</div>`;
}

function settingsView() {
  const p = S.prefs;
  return `<div class="page-head"><div><h1>Settings</h1><p class="muted">Shape the planet to fit how you work.</p></div></div>
  <div class="stack">
    <form class="panel stack" data-form="prefs">
      <h2>Look</h2>
      <label class="field"><span>Theme</span><select name="theme">${[['auto', 'Match my device'], ['dark', 'Dark'], ['light', 'Light']].map(([v, l]) => `<option value="${v}" ${p.theme === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
      <h2>Lists</h2>
      <label class="field"><span>Categories (comma separated)</span><input name="categories" value="${esc(p.categories.join(', '))}" /></label>
      <label class="field"><span>Statuses (comma separated, in order)</span><input name="statuses" value="${esc(p.statuses.join(', '))}" /></label>
      <label class="field"><span>Statuses that count as live</span><input name="liveStatuses" value="${esc((p.liveStatuses || []).join(', '))}" /></label>
      <div><button class="btn primary">Save settings</button></div>
    </form>
    <div class="panel stack">
      <h2>Custom fields</h2>
      <p class="muted">Add your own fields to every app, such as price, owner, client or renewal date.</p>
      ${p.fields.length ? `<div class="table-wrap"><table><thead><tr><th>Field</th><th>Type</th><th></th></tr></thead><tbody>${p.fields.map((f, i) => `<tr><td>${esc(f.label)}</td><td>${esc(f.type)}${f.options ? ': ' + esc(f.options.join(', ')) : ''}</td><td><button class="btn sm danger" data-act="del-field" data-i="${i}">Remove</button></td></tr>`).join('')}</tbody></table></div>` : ''}
      <form class="row" data-form="field"><input name="label" placeholder="Field name, e.g. Monthly price" required style="flex:1 1 200px" />
        <select name="type" style="width:auto">${['text', 'number', 'url', 'date', 'select', 'longtext'].map((t) => `<option>${t}</option>`).join('')}</select>
        <input name="options" placeholder="Choices for 'select', comma separated" style="flex:1 1 200px" /><button class="btn">Add field</button></form>
    </div>
    <div class="panel stack">
      <h2>Backup</h2>
      <p class="muted">Export downloads everything as one file (codes stay encrypted). Import adds apps from a file exported here.</p>
      <div class="row"><button class="btn" data-act="export">Export everything</button><label class="btn">Import file<input type="file" accept="application/json" data-act="import" class="sr" /></label>${S.apps.length ? '' : '<button class="btn" data-act="seed">Load my 14 deployed apps</button>'}</div>
    </div>
    <div class="panel stack">
      <h2>This device</h2>
      <div class="row">${S.installPrompt ? '<button class="btn" data-act="install">Install on this device</button>' : '<p class="muted small">To install: on Android, open the browser menu and choose "Add to Home screen"; on desktop, use the install icon in the address bar.</p>'}<button class="btn" data-act="signout">Sign out</button></div>
    </div>
  </div>`;
}

// ---------- drawer (single app) ----------
function drawerView() {
  const a = byId(S.openId);
  if (!a) { S.openId = null; return ''; }
  const tabs = [['overview', 'Overview'], ['access', 'Access'], ['codes', 'Codes'], ['notes', 'Notes & code'], ['fields', 'Fields']];
  const body = { overview: tabOverview, access: tabAccess, codes: tabCodes, notes: tabNotes, fields: tabFields }[S.tab](a);
  return `<div class="scrim" data-act="close-drawer"><aside class="drawer" role="dialog" aria-modal="true" aria-label="${esc(a.name)}" data-stop>
    <div class="drawer-head" style="--c:${esc(a.color)}"><span class="disc" aria-hidden="true">${esc(a.icon || '🪐')}</span>
      <div class="grow"><h2>${esc(a.name)}</h2><p class="muted small">${esc(a.category || 'Uncategorised')} <span class="pill ${isLive(a) ? 'live' : ''}">${esc(a.status)}</span></p></div>
      <button class="btn sm" data-act="close-drawer-btn" aria-label="Close">✕</button></div>
    <div class="tabs" role="tablist">${tabs.map(([k, l]) => `<button class="tab" role="tab" aria-selected="${S.tab === k}" data-act="tab" data-tab="${k}">${l}</button>`).join('')}</div>
    ${body}
  </aside></div>`;
}
const link = (u) => { const s = safeUrl(u); return s ? `<a href="${esc(s)}" target="_blank" rel="noopener">${esc(u)}</a>` : esc(u); };
function tabOverview(a) {
  const gh = a.github_repo ? `https://github.com/${a.github_repo}` : '';
  return `<div class="stack">
    ${a.tagline ? `<p><strong>${esc(a.tagline)}</strong></p>` : ''}${a.description ? `<p style="white-space:pre-wrap">${esc(a.description)}</p>` : ''}
    <dl class="kv">
      <dt>Website</dt><dd>${a.frontend_url ? link(a.frontend_url) : '<span class="muted">Not set</span>'}</dd>
      <dt>API</dt><dd>${a.backend_url ? link(a.backend_url) : '<span class="muted">Not set</span>'}</dd>
      <dt>GitHub</dt><dd>${gh ? link(gh) : '<span class="muted">Not set</span>'}</dd>
      <dt>Vercel project</dt><dd>${a.vercel_project ? link(`https://vercel.com/xaglobally-lgtm/${a.vercel_project}`) : '<span class="muted">Not set</span>'}</dd>
      <dt>Render service</dt><dd>${esc(a.render_service) || '<span class="muted">Not set</span>'}</dd>
      <dt>Database prefix</dt><dd class="code">${esc(a.supabase_prefix) || '<span class="muted">Not set</span>'}</dd>
      <dt>Tech</dt><dd><div class="tags">${(a.tech || []).map((t) => `<span class="pill">${esc(t)}</span>`).join('') || '<span class="muted">Not set</span>'}</div></dd>
      <dt>Tags</dt><dd><div class="tags">${(a.tags || []).map((t) => `<span class="pill">${esc(t)}</span>`).join('') || '<span class="muted">None</span>'}</div></dd>
    </dl>
    <div class="row">${a.frontend_url ? `<button class="btn sm" data-act="ping" data-url="${esc(a.frontend_url)}">Check website</button>` : ''}${a.backend_url ? `<button class="btn sm" data-act="ping" data-url="${esc(a.backend_url.replace(/\/$/, '') + '/health')}">Check API</button>` : ''}</div>
    <div class="row"><button class="btn primary" data-act="edit-app" data-id="${a.id}">Edit app</button><button class="btn" data-act="pin" data-id="${a.id}">${a.pinned ? 'Unpin' : 'Pin to top'}</button><button class="btn danger" data-act="del-app" data-id="${a.id}">Delete app</button></div>
  </div>`;
}
function tabAccess(a) {
  const list = S.perms.filter((p) => p.app_id === a.id);
  return `<div class="stack"><div class="row" style="justify-content:space-between"><p class="muted">Services this app can reach.</p><button class="btn sm primary" data-act="new-perm" data-app="${a.id}">Add permission</button></div>
    ${list.length ? list.map((p) => `<div class="item"><div class="row" style="justify-content:space-between"><strong>${esc(p.service)}</strong><span class="pill">${esc(p.level)}</span></div>${p.scope ? `<p>${esc(p.scope)}</p>` : ''}${p.granted_to ? `<p class="small muted">Held by ${esc(p.granted_to)}</p>` : ''}${p.notes ? `<p class="small">${esc(p.notes)}</p>` : ''}<div class="row"><button class="btn sm" data-act="edit-perm" data-id="${p.id}">Edit</button><button class="btn sm danger" data-act="del-perm" data-id="${p.id}">Delete</button></div></div>`).join('') : '<p class="muted">None recorded yet.</p>'}</div>`;
}
function tabCodes(a) {
  return `<div class="stack">${vaultBanner()}<div class="row" style="justify-content:space-between"><p class="muted">Keys and passwords for this app.</p><button class="btn sm primary" data-act="new-secret" data-app="${a.id}" ${S.vaultKey ? '' : 'disabled'}>Add code</button></div>${secretsTable(S.secrets.filter((s) => s.app_id === a.id))}</div>`;
}
function tabNotes(a) {
  const list = S.items.filter((i) => i.app_id === a.id);
  return `<div class="stack"><div class="row" style="justify-content:space-between"><p class="muted">Notes, links, code snippets, contacts and tasks.</p><button class="btn sm primary" data-act="new-item" data-app="${a.id}">Add</button></div>
    ${list.length ? list.map((i) => `<div class="item"><div class="row" style="justify-content:space-between"><strong>${esc(i.title)}</strong><span class="pill">${esc(ITEM_KINDS[i.kind] || i.kind)}${i.language ? ' · ' + esc(i.language) : ''}</span></div>
      ${i.url ? `<p>${link(i.url)}</p>` : ''}${i.body ? (i.kind === 'code' ? `<pre>${esc(i.body)}</pre>` : `<p style="white-space:pre-wrap">${esc(i.body)}</p>`) : ''}
      <div class="row">${i.kind === 'code' ? `<button class="btn sm" data-act="copy-item" data-id="${i.id}">Copy</button>` : ''}<button class="btn sm" data-act="edit-item" data-id="${i.id}">Edit</button><button class="btn sm danger" data-act="del-item" data-id="${i.id}">Delete</button></div></div>`).join('') : '<p class="muted">Nothing added yet.</p>'}</div>`;
}
function tabFields(a) {
  const c = a.custom || {};
  if (!S.prefs.fields.length) return `<p class="muted">No custom fields yet. Add them in Settings.</p>`;
  return `<form class="stack" data-form="custom" data-id="${a.id}">${S.prefs.fields.map((f) => fieldInput(f, c[f.key])).join('')}<div><button class="btn primary">Save fields</button></div></form>`;
}
function fieldInput(f, v) {
  const n = `f_${esc(f.key)}`;
  if (f.type === 'select') return `<label class="field"><span>${esc(f.label)}</span><select name="${n}"><option value=""></option>${(f.options || []).map((o) => `<option ${o === v ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select></label>`;
  if (f.type === 'longtext') return `<label class="field"><span>${esc(f.label)}</span><textarea name="${n}">${esc(v)}</textarea></label>`;
  return `<label class="field"><span>${esc(f.label)}</span><input name="${n}" type="${f.type === 'url' ? 'url' : f.type === 'number' ? 'number' : f.type === 'date' ? 'date' : 'text'}" value="${esc(v)}" step="any" /></label>`;
}

// ---------- modals ----------
function modal(html) { $('#modal-root').innerHTML = `<div class="modal" data-act="close-modal"><div class="modal-card" role="dialog" aria-modal="true" data-stop>${html}</div></div>`; $('#modal-root input, #modal-root textarea, #modal-root select')?.focus(); }
function closeModal() { $('#modal-root').innerHTML = ''; }
const appOptions = (sel) => `<option value="">Shared / all apps</option>` + S.apps.map((a) => `<option value="${a.id}" ${a.id === sel ? 'selected' : ''}>${esc(a.name)}</option>`).join('');

function appForm(a = {}) {
  const cats = [...new Set([...S.prefs.categories, a.category].filter(Boolean))];
  modal(`<form class="stack" data-form="app" data-id="${a.id || ''}"><h2>${a.id ? 'Edit app' : 'Add an app'}</h2>
    <div class="grid-2">
      <label class="field"><span>Name</span><input name="name" required value="${esc(a.name)}" /></label>
      <label class="field"><span>Short name (slug)</span><input name="slug" value="${esc(a.slug)}" placeholder="my-new-app" /></label>
      <label class="field"><span>Category</span><input name="category" list="cat-list" value="${esc(a.category || '')}" /><datalist id="cat-list">${cats.map((c) => `<option value="${esc(c)}">`).join('')}</datalist></label>
      <label class="field"><span>Status</span><select name="status">${S.prefs.statuses.map((s) => `<option ${s === (a.status || 'Idea') ? 'selected' : ''}>${esc(s)}</option>`).join('')}</select></label>
      <label class="field"><span>Icon (emoji)</span><input name="icon" value="${esc(a.icon || '🪐')}" maxlength="4" /></label>
      <label class="field"><span>Colour</span><input name="color" type="color" value="${esc(a.color || PALETTE[S.apps.length % PALETTE.length])}" style="height:2.8rem;padding:0.2rem" /></label>
    </div>
    <label class="field"><span>One-line summary</span><input name="tagline" value="${esc(a.tagline)}" /></label>
    <label class="field"><span>Description</span><textarea name="description">${esc(a.description)}</textarea></label>
    <div class="grid-2">
      <label class="field"><span>Website URL</span><input name="frontend_url" type="url" value="${esc(a.frontend_url)}" /></label>
      <label class="field"><span>API URL</span><input name="backend_url" type="url" value="${esc(a.backend_url)}" /></label>
      <label class="field"><span>GitHub repo (owner/name)</span><input name="github_repo" value="${esc(a.github_repo)}" /></label>
      <label class="field"><span>Vercel project</span><input name="vercel_project" value="${esc(a.vercel_project)}" /></label>
      <label class="field"><span>Render service</span><input name="render_service" value="${esc(a.render_service)}" /></label>
      <label class="field"><span>Database table prefix</span><input name="supabase_prefix" value="${esc(a.supabase_prefix)}" /></label>
    </div>
    <label class="field"><span>Tech (comma separated)</span><input name="tech" value="${esc((a.tech || []).join(', '))}" /></label>
    <label class="field"><span>Tags (comma separated)</span><input name="tags" value="${esc((a.tags || []).join(', '))}" /></label>
    <div class="row"><button class="btn primary">${a.id ? 'Save app' : 'Add app'}</button><button type="button" class="btn ghost" data-act="close-modal-btn">Cancel</button></div></form>`);
}
function permForm(p = {}) {
  modal(`<form class="stack" data-form="perm" data-id="${p.id || ''}"><h2>${p.id ? 'Edit permission' : 'Add permission'}</h2>
    <label class="field"><span>App</span><select name="app_id">${appOptions(p.app_id)}</select></label>
    <div class="grid-2"><label class="field"><span>Service</span><input name="service" required value="${esc(p.service)}" placeholder="Supabase, Stripe, Gmail…" list="svc" /><datalist id="svc">${['Supabase', 'Stripe', 'GitHub', 'Vercel', 'Render', 'Gmail / SMTP', 'Slack', 'Google Drive', 'OpenAI', 'Anthropic'].map((x) => `<option value="${x}">`).join('')}</datalist></label>
    <label class="field"><span>Level</span><select name="level">${LEVELS.map((l) => `<option ${l === (p.level || 'read') ? 'selected' : ''}>${l}</option>`).join('')}</select></label></div>
    <label class="field"><span>What it can reach</span><input name="scope" value="${esc(p.scope)}" placeholder="e.g. tables starting quoteflow_; send email" /></label>
    <label class="field"><span>Held by</span><input name="granted_to" value="${esc(p.granted_to)}" placeholder="e.g. backend on Render, me, a contractor" /></label>
    <label class="field"><span>Notes</span><textarea name="notes">${esc(p.notes)}</textarea></label>
    <div class="row"><button class="btn primary">Save permission</button><button type="button" class="btn ghost" data-act="close-modal-btn">Cancel</button></div></form>`);
}
function itemForm(i = {}) {
  modal(`<form class="stack" data-form="item" data-id="${i.id || ''}"><h2>${i.id ? 'Edit' : 'Add'} note or code</h2>
    <div class="grid-2"><label class="field"><span>App</span><select name="app_id">${appOptions(i.app_id)}</select></label>
    <label class="field"><span>Type</span><select name="kind">${Object.entries(ITEM_KINDS).map(([k, l]) => `<option value="${k}" ${k === (i.kind || 'note') ? 'selected' : ''}>${l}</option>`).join('')}</select></label></div>
    <label class="field"><span>Title</span><input name="title" required value="${esc(i.title)}" /></label>
    <label class="field"><span>Link (optional)</span><input name="url" type="url" value="${esc(i.url)}" /></label>
    <label class="field"><span>Language, for code (optional)</span><input name="language" value="${esc(i.language)}" placeholder="sql, js, bash…" /></label>
    <label class="field"><span>Content</span><textarea name="body" class="code" rows="8">${esc(i.body)}</textarea></label>
    <p class="small muted">Don't paste passwords or API keys here. Use Codes, which encrypts them.</p>
    <div class="row"><button class="btn primary">Save</button><button type="button" class="btn ghost" data-act="close-modal-btn">Cancel</button></div></form>`);
}
function secretForm(appId) {
  modal(`<form class="stack" data-form="secret"><h2>Add a code</h2>
    <label class="field"><span>App</span><select name="app_id">${appOptions(appId)}</select></label>
    <div class="grid-2"><label class="field"><span>Label</span><input name="label" required placeholder="e.g. Stripe secret key" /></label>
    <label class="field"><span>Variable name</span><input name="env_name" placeholder="STRIPE_SECRET_KEY" /></label></div>
    <label class="field"><span>Used in</span><input name="where_used" placeholder="e.g. Render backend env" /></label>
    <label class="field"><span>Value</span><textarea name="value" class="code" required autocomplete="off" spellcheck="false"></textarea></label>
    <p class="small muted">Encrypted on this device before saving.</p>
    <div class="row"><button class="btn primary">Encrypt and save</button><button type="button" class="btn ghost" data-act="close-modal-btn">Cancel</button></div></form>`);
}

// ---------- actions ----------
const actions = {
  nav: (d) => { S.page = d.page; localStorage.setItem('planet.page', S.page); render(); window.scrollTo(0, 0); },
  open: (d, e) => { e?.preventDefault(); S.openId = d.id; S.tab = 'overview'; S._revealed = true; render(); },
  'close-drawer': () => { S.openId = null; render(); },
  'close-drawer-btn': () => { S.openId = null; render(); },
  tab: (d) => { S.tab = d.tab; render(); },
  'focus-cat': (d) => { S.focusCat = S.focusCat === d.cat ? '' : d.cat; S._revealed = true; render(); },
  'toggle-labels': () => { S._revealed = true; savePrefs({ labels: !S.prefs.labels }).then(render); },
  'new-app': () => appForm(),
  'edit-app': (d) => appForm(byId(d.id)),
  pin: async (d) => { const a = byId(d.id); await mutate('planet_apps', 'update', { pinned: !a.pinned }, a.id).catch(fail); },
  'del-app': async (d) => { const a = byId(d.id); if (!confirm(`Delete "${a.name}" and everything saved under it?`)) return; S.openId = null; await mutate('planet_apps', 'delete', null, a.id).then(() => toast('App deleted')).catch(fail); },
  'new-perm': (d) => permForm({ app_id: d.app }),
  'edit-perm': (d) => permForm(S.perms.find((p) => p.id === d.id)),
  'del-perm': async (d) => { if (confirm('Delete this permission record?')) await mutate('planet_permissions', 'delete', null, d.id).catch(fail); },
  'new-item': (d) => itemForm({ app_id: d.app }),
  'edit-item': (d) => itemForm(S.items.find((i) => i.id === d.id)),
  'del-item': async (d) => { if (confirm('Delete this entry?')) await mutate('planet_items', 'delete', null, d.id).catch(fail); },
  'copy-item': async (d) => { await navigator.clipboard.writeText(S.items.find((i) => i.id === d.id).body || ''); toast('Copied'); },
  'new-secret': (d) => secretForm(d.app),
  reveal: async (d) => { if (S.revealed[d.id] != null) { delete S.revealed[d.id]; return render(); } const s = S.secrets.find((x) => x.id === d.id); try { S.revealed[d.id] = await decrypt(S.vaultKey, s.ciphertext, s.iv); render(); } catch { toast('Could not decrypt this code with the current passphrase'); } },
  'copy-secret': async (d) => { const s = S.secrets.find((x) => x.id === d.id); try { await navigator.clipboard.writeText(await decrypt(S.vaultKey, s.ciphertext, s.iv)); toast('Copied. Clipboard holds a secret now'); } catch { toast('Could not copy this code'); } },
  'del-secret': async (d) => { if (confirm('Delete this code permanently?')) await mutate('planet_secrets', 'delete', null, d.id).catch(fail); },
  lock: () => { S.vaultKey = null; S.revealed = {}; render(); toast('Vault locked'); },
  'del-field': (d) => { const f = [...S.prefs.fields]; f.splice(+d.i, 1); savePrefs({ fields: f }).then(render); },
  seed: async () => {
    const { data: rows, error } = await sb.from('planet_apps').insert(STARTER).select('id, slug, supabase_prefix');
    if (error) return fail(error);
    const perms = rows.flatMap((a) => [
      { app_id: a.id, service: 'Supabase', level: 'admin', scope: `Shared project "API Verifier LIVE"; app tables start ${a.supabase_prefix}. Service role key bypasses row-level security.`, granted_to: `Render backend ${a.slug}-api (SUPABASE_SERVICE_ROLE_KEY via env group xag-shared)` },
      { app_id: a.id, service: 'Render', level: 'owner', scope: `Web service ${a.slug}-api (free plan, Singapore). Env: API_ADMIN_KEY, API_ADMIN_PIN generated by Render.`, granted_to: 'xaglobally-lgtm (Blueprint in planet-of-the-apps)' },
      { app_id: a.id, service: 'Vercel', level: 'owner', scope: `Project ${a.slug}; VITE_API_URL points to the Render API.`, granted_to: 'xaglobally-lgtm' },
      { app_id: a.id, service: 'GitHub', level: 'owner', scope: `Repo xaglobally-lgtm/${a.slug}; pushes to main auto-deploy Vercel and Render.`, granted_to: 'xaglobally-lgtm' },
    ]);
    const pr = await sb.from('planet_permissions').insert(perms);
    if (pr.error) fail(pr.error);
    await loadAll(); render(); toast(`${rows.length} apps and ${perms.length} access records added`);
  },
  export: () => {
    const data = { exported_at: new Date().toISOString(), version: 1, prefs: S.prefs, apps: S.apps, permissions: S.perms, items: S.items, secrets: S.secrets, vault: { salt: S.settings.vault_salt, check: S.settings.vault_check, check_iv: S.settings.vault_check_iv } };
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: `planet-of-the-apps-${new Date().toISOString().slice(0, 10)}.json` });
    a.click(); URL.revokeObjectURL(url); toast('Backup downloaded');
  },
  ping: async (d) => { toast('Checking…'); try { await fetch(d.url, { mode: 'no-cors', cache: 'no-store' }); toast('Reachable: it responded'); } catch { toast('Not reachable right now'); } },
  install: async () => { if (!S.installPrompt) return; S.installPrompt.prompt(); await S.installPrompt.userChoice; S.installPrompt = null; render(); },
  signout: async () => { await sb.auth.signOut(); S.vaultKey = null; },
  'close-modal': () => closeModal(),
  'close-modal-btn': () => closeModal(),
};

const forms = {
  auth: async (fd, f, mode) => {
    const email = fd.get('email'), password = fd.get('password'), msg = $('#auth-msg');
    msg.textContent = 'Working…';
    let r;
    if (mode === 'magic') r = await sb.auth.signInWithOtp({ email, options: { emailRedirectTo: location.origin } });
    else if (!password || password.length < 8) { msg.textContent = 'Enter a password of at least 8 characters, or use the sign-in link.'; return; }
    else if (mode === 'signup') r = await sb.auth.signUp({ email, password, options: { emailRedirectTo: location.origin } });
    else r = await sb.auth.signInWithPassword({ email, password });
    if (r.error) msg.textContent = /invalid login/i.test(r.error.message) ? `Email or password not recognised. Check the exact email you signed up with (${email}), or use the sign-in link below.` : /not confirmed/i.test(r.error.message) ? 'Your email is not confirmed yet. Use the link in the confirmation email, or send yourself a sign-in link below.' : r.error.message;
    else if (mode === 'magic') msg.textContent = 'Check your email for the sign-in link.';
    else if (mode === 'signup' && !r.data.session) msg.textContent = 'Account created. Confirm it from the email we sent, then sign in.';
    else msg.textContent = '';
  },
  app: async (fd, f) => {
    const o = Object.fromEntries(fd); o.tech = csv(o.tech); o.tags = csv(o.tags); o.category = o.category || 'Uncategorised';
    for (const k of ['frontend_url', 'backend_url']) if (!o[k]) o[k] = null;
    const id = f.dataset.id;
    await mutate('planet_apps', id ? 'update' : 'insert', o, id);
    closeModal(); toast(id ? 'App saved' : 'App added');
  },
  perm: async (fd, f) => { const o = Object.fromEntries(fd); o.app_id = o.app_id || null; await mutate('planet_permissions', f.dataset.id ? 'update' : 'insert', o, f.dataset.id); closeModal(); toast('Permission saved'); },
  item: async (fd, f) => { const o = Object.fromEntries(fd); o.app_id = o.app_id || null; await mutate('planet_items', f.dataset.id ? 'update' : 'insert', o, f.dataset.id); closeModal(); toast('Saved'); },
  secret: async (fd) => {
    if (!S.vaultKey) return toast('Unlock the vault first');
    const o = Object.fromEntries(fd); const { ciphertext, iv } = await encrypt(S.vaultKey, o.value);
    await mutate('planet_secrets', 'insert', { app_id: o.app_id || null, label: o.label, env_name: o.env_name, where_used: o.where_used, ciphertext, iv });
    closeModal(); toast('Code encrypted and saved');
  },
  custom: async (fd, f) => {
    const a = byId(f.dataset.id); const custom = { ...(a.custom || {}) };
    for (const fld of S.prefs.fields) custom[fld.key] = fd.get('f_' + fld.key) || '';
    await mutate('planet_apps', 'update', { custom }, a.id); toast('Fields saved');
  },
  prefs: async (fd) => { await savePrefs({ theme: fd.get('theme'), categories: csv(fd.get('categories')), statuses: csv(fd.get('statuses')), liveStatuses: csv(fd.get('liveStatuses')) }); render(); toast('Settings saved'); },
  field: async (fd) => {
    const label = fd.get('label').trim(); const key = label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'field_' + Date.now();
    if (S.prefs.fields.some((f) => f.key === key)) return toast('A field with that name already exists');
    const f = { key, label, type: fd.get('type') }; if (f.type === 'select') f.options = csv(fd.get('options'));
    await savePrefs({ fields: [...S.prefs.fields, f] }); render(); toast('Field added to every app');
  },
  'vault-setup': async (fd) => {
    const p = fd.get('pass'); if (p !== fd.get('pass2')) return toast('The two passphrases don\'t match');
    const salt = b64(crypto.getRandomValues(new Uint8Array(16))); const key = await deriveKey(p, salt); const chk = await encrypt(key, VAULT_CHECK);
    const { error } = await sb.from('planet_settings').update({ vault_salt: salt, vault_check: chk.ciphertext, vault_check_iv: chk.iv }).eq('owner', S.session.user.id);
    if (error) return fail(error);
    S.vaultKey = key; await loadAll(); render(); toast('Vault created and unlocked');
  },
  'vault-unlock': async (fd) => {
    toast('Unlocking…');
    try { const key = await deriveKey(fd.get('pass'), S.settings.vault_salt); if (await decrypt(key, S.settings.vault_check, S.settings.vault_check_iv) !== VAULT_CHECK) throw 0; S.vaultKey = key; render(); toast('Vault unlocked'); }
    catch { toast('That passphrase is not correct'); }
  },
};

async function importFile(file) {
  try {
    const data = JSON.parse(await file.text());
    if (!Array.isArray(data.apps)) throw new Error('This file is not a Planet of the Apps export');
    const strip = ({ id, owner, created_at, updated_at, ...rest }) => rest;
    const map = {};
    for (const a of data.apps) { const { data: row, error } = await sb.from('planet_apps').insert(strip(a)).select('id').single(); if (error) throw error; map[a.id] = row.id; }
    const remap = (r) => ({ ...strip(r), app_id: r.app_id ? map[r.app_id] || null : null });
    if (data.permissions?.length) { const { error } = await sb.from('planet_permissions').insert(data.permissions.map(remap)); if (error) throw error; }
    if (data.items?.length) { const { error } = await sb.from('planet_items').insert(data.items.map(remap)); if (error) throw error; }
    if (data.secrets?.length) toast('Codes were skipped: they are tied to the vault they were made in');
    await loadAll(); render(); toast(`Imported ${data.apps.length} apps`);
  } catch (e) { fail(e); }
}

// ---------- events ----------
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  if ((act === 'close-drawer' || act === 'close-modal') && e.target.closest('[data-stop]')) return;
  if (act === 'import') return;
  if (actions[act]) { if (el.tagName === 'A') e.preventDefault(); Promise.resolve(actions[act](el.dataset, e)).catch(fail); }
});
document.addEventListener('change', (e) => { if (e.target.dataset.act === 'import' && e.target.files[0]) importFile(e.target.files[0]); });
document.addEventListener('input', (e) => {
  const k = e.target.dataset.bind; if (!k) return;
  S[k] = e.target.value;
  const pos = e.target.selectionStart; render();
  const again = document.querySelector(`[data-bind="${k}"]`); if (again && k === 'q') { again.focus(); again.setSelectionRange(pos, pos); }
});
document.addEventListener('submit', (e) => {
  const f = e.target.closest('form[data-form]'); if (!f) return;
  e.preventDefault();
  const btn = e.submitter; const mode = btn?.value;
  if (btn) btn.disabled = true;
  Promise.resolve(forms[f.dataset.form](new FormData(f), f, mode)).catch(fail).finally(() => { if (btn && btn.isConnected) btn.disabled = false; });
});
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { if ($('#modal-root').innerHTML) closeModal(); else if (S.openId) { S.openId = null; render(); } } });
window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); S.installPrompt = e; if (S.session) render(); });

// ---------- boot ----------
async function onSession(session) {
  S.session = session;
  if (!session) { S.vaultKey = null; render(); return; }
  try { await loadAll(); } catch (e) { fail(e); }
  render();
  setTimeout(() => { S._revealed = true; }, 1500);
}
// Surface errors Supabase returns in the address bar after an email link (e.g. expired link).
{ const h = new URLSearchParams(location.hash.slice(1) || location.search.slice(1)); const err = h.get('error_description') || h.get('error');
  if (err) { S.authMsg = `That email link didn't work: ${err.replace(/\+/g, ' ')}. Sign in with your password, or send yourself a new sign-in link.`; history.replaceState(null, '', location.pathname); } }
let booted = false;
sb.auth.onAuthStateChange((_evt, session) => {
  const changed = (session?.user?.id || null) !== (S.session?.user?.id || null);
  if (!booted || changed) { booted = true; onSession(session); }
  else S.session = session;
});
if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));

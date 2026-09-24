# Planet of the Apps
*One app to rule them all.*

A private control centre for every app in the XAG portfolio: an orbit view of all apps by category, full app records (links, repos, deploy targets, database prefixes, tech, tags), per-app access/permission records, an encrypted code vault (API keys, PINs, passwords), notes/links/code snippets, user-defined custom fields, and JSON backup/import.

- **No build step.** Static files; deploy anywhere (Vercel project root = repo root, framework "Other").
- **Installable** on Android, Windows, macOS, iOS (PWA).
- **Data:** Supabase project "API Verifier LIVE", tables `planet_apps`, `planet_permissions`, `planet_items`, `planet_secrets`, `planet_settings`. Every table has row-level security: a signed-in user only ever sees their own rows.
- **Vault:** values are encrypted in the browser (PBKDF2-SHA256, 310k iterations -> AES-256-GCM) before saving. The passphrase is never stored or sent. Lose it and stored codes are unrecoverable.

## Adding more apps
Use **Add app** in the app, or **Settings -> Import** with a JSON export. New categories, statuses and custom fields are all editable in Settings.

## Deploy (frontend)
Vercel -> Add New -> Project -> import `xaglobally-lgtm/planet-of-the-apps`.
Framework preset **Other**, Root Directory `./`, no build command, no output directory, **no environment variables**.

Then in Supabase -> Authentication -> URL Configuration, set **Site URL** to the Vercel URL
(e.g. `https://planet-of-the-apps.vercel.app`) and add it under **Redirect URLs**, so sign-up
confirmation and email sign-in links come back to the app.

## Deploy (all 14 backends) with render.yaml
Render -> New -> **Blueprint** -> connect `xaglobally-lgtm/planet-of-the-apps` -> Apply.
Enter `SUPABASE_SERVICE_ROLE_KEY` once when asked (Supabase -> Project Settings -> API keys).
Each service gets its own random `API_ADMIN_KEY` / `API_ADMIN_PIN`.
Afterwards set `VITE_API_URL` on each Vercel frontend to its `https://<app>-api.onrender.com` URL and redeploy.

## Known backlog
- Template backend accepts any `X-API-Key` (demo placeholder in server.ts). Replace with real key lookup before handling customer data.

## Phase A: operations centre (brain + monitoring + AI + money)
- **Brain:** Supabase Edge Function `planet-brain` (source in `supabase/functions/planet-brain/index.ts`, deployed separately; `.vercelignore` keeps it off Vercel).
  Secrets (Supabase → Edge Functions → Secrets): `ANTHROPIC_API_KEY`, `VERCEL_TOKEN`, `RENDER_API_KEY`, optional `GITHUB_TOKEN`, optional `PLANET_MODEL`.
- **Screens:** health rings on the orbit, daily briefing, Ask Planet, Activity, Money (Connect payments per app, expenses, profit), Plans & costs, per-app Health / Money / API keys tabs, Automation + Connections in Settings.
- **Payments:** Stripe (restricted read-only key) or Lemon Squeezy, stored encrypted server-side, synced on open or on demand.

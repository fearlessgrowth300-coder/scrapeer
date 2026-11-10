# Scrapeer

Paste websites, get the **real** contact emails: crawled from contact/about/team/policy pages, hidden emails decoded, junk removed, domains checked for a mail server, each email scored high/medium/low.

- `index.html` — the app (static page)
- `api/scrape.py` — Vercel Python function, `POST /api/scrape {"site": "example.com"}`
- `api/send.py` — `POST /api/send`: sends one email via Resend (your verified domain) or the user's own mailbox (SMTP + app password); the account is sent per request, never stored
- `api/domain.py` — `POST /api/domain`: adds a member's domain to their own Resend account and returns the DNS records + verification status (in-app setup, no Resend dashboard needed after the API key)
- `api/track.py` — `POST /api/track`: chat-style inbox — sent emails with delivery status, replies, and message bodies (quoted history stripped), read live from the user's Resend account(s)
- `api/hook.py` — `POST /api/hook?a=<account>[&t=<token>]`: live events from Resend (Svix-signed), Mailjet and Brevo (per-account secret token in the URL), normalised to delivered/opened/clicked/bounced/complained/received → pop-ups, ticks, "Reading now", "Last seen"
- `api/_scout.py` — the engine (`python api/_scout.py` runs its self-check)

Deploys on Vercel with zero config: import the repo, framework preset "Other".

The Send tab: several sending accounts per person (Brevo 300/day, Mailjet 200/day, Resend 100/day free tiers, or Gmail/Workspace/custom SMTP), rotated round-robin with a daily limit each; accounts that fail to log in are dropped for the run, recipients (from Find results or CSV), `{{field|fallback}}` personalization, opt-out line, random delay + daily cap, do-not-email list, never emails the same person twice, sent log. All kept in the browser (localStorage).

Known limits: sites that only show emails after JavaScript runs aren't covered yet; mailbox existence isn't SMTP-verified (needs port 25 or a paid verifier); sending runs in the open browser tab; no open/reply tracking yet.

## Accounts & security

- Sign up / sign in / password reset via **Supabase Auth** (passwords never touch Scrapeer's code).
- Every API route requires a signed-in user (`api/_auth.py` → `serve()`).
- Sending-account API keys/passwords are stored **AES-256-GCM encrypted** in `scrapeer_accounts.secret`; only the
  server decrypts them, the browser only ever gets public fields (label/from/reply-to/name/domain).
- Sent log, already-emailed list, do-not-email, drafts and read replies live in `scrapeer_state` per user.
- Both tables have Row Level Security ON and no policies: only the server's service key can touch them.

Setup: run `supabase/schema.sql` in the Supabase SQL editor, then set Vercel env vars
`SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_KEY`, `SCRAPEER_SECRET` (base64 of 32 random bytes —
never change it, or saved accounts can't be decrypted).

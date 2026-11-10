# Scrapeer

Paste websites, get the **real** contact emails: crawled from contact/about/team/policy pages, hidden emails decoded, junk removed, domains checked for a mail server, each email scored high/medium/low.

- `index.html` — the app (static page)
- `api/scrape.py` — Vercel Python function, `POST /api/scrape {"site": "example.com"}`
- `api/send.py` — `POST /api/send`: sends one email via Resend (your verified domain) or the user's own mailbox (SMTP + app password); the account is sent per request, never stored
- `api/domain.py` — `POST /api/domain`: adds a member's domain to their own Resend account and returns the DNS records + verification status (in-app setup, no Resend dashboard needed after the API key)
- `api/_scout.py` — the engine (`python api/_scout.py` runs its self-check)

Deploys on Vercel with zero config: import the repo, framework preset "Other".

The Send tab: account (Gmail/Outlook/Yahoo/Zoho/custom SMTP), recipients (from Find results or CSV), `{{field|fallback}}` personalization, opt-out line, random delay + daily cap, do-not-email list, never emails the same person twice, sent log. All kept in the browser (localStorage).

Known limits: sites that only show emails after JavaScript runs aren't covered yet; mailbox existence isn't SMTP-verified (needs port 25 or a paid verifier); sending runs in the open browser tab; no open/reply tracking yet.

# Scrapeer

Paste websites, get the **real** contact emails: crawled from contact/about/team/policy pages, hidden emails decoded, junk removed, domains checked for a mail server, each email scored high/medium/low.

- `index.html` — the app (static page)
- `api/scrape.py` — Vercel Python function, `POST /api/scrape {"site": "example.com"}`
- `api/_scout.py` — the engine (`python api/_scout.py` runs its self-check)

Deploys on Vercel with zero config: import the repo, framework preset "Other".

Known limits: sites that only show emails after JavaScript runs aren't covered yet; mailbox existence isn't SMTP-verified (needs port 25 or a paid verifier).

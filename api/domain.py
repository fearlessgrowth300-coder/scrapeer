"""POST /api/domain {"api_key": "re_...", "domain": "example.com", "action": "connect" | "check"}

Adds a team member's domain to THEIR OWN Resend account (or finds it if already there) and returns
the DNS records to add plus each record's status. "check" asks Resend to re-verify first.
-> {"id", "name", "status", "records": [{"record", "type", "name", "value", "priority"?, "status"}]}
"""
import json
import os
import re
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, load_account, serve  # noqa: E402
from send import resend_api  # noqa: E402

DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}")
DMARC = "v=DMARC1; p=none;"


def ok(code, data):
    if code in (401, 403):
        if data.get("name") == "restricted_api_key":
            raise Bad("This key is 'Sending access' only. In Resend create a new key with 'Full access' and paste it.")
        raise Bad("Resend refused the API key. Copy it again from Resend → API Keys.")
    if code >= 400:
        raise Bad("Resend: " + str(data.get("message") or f"error {code}")[:200])
    return data


def has_dmarc(domain):
    try:
        url = "https://dns.google/resolve?" + urlencode({"name": "_dmarc." + domain, "type": "TXT"})
        ans = json.load(urllib.request.urlopen(url, timeout=8))
        return any("v=DMARC1" in a.get("data", "") for a in ans.get("Answer", []))
    except Exception:
        return False


def other_mailbox(domain):
    """True if the domain already receives mail somewhere else (Gmail/Outlook/Zoho...): then we must not
    point its MX at Resend, or their existing inbox would stop getting mail."""
    try:
        url = "https://dns.google/resolve?" + urlencode({"name": domain, "type": "MX"})
        hosts = [a.get("data", "").lower() for a in json.load(urllib.request.urlopen(url, timeout=8)).get("Answer", [])
                 if a.get("type") == 15]
    except Exception:
        return True  # unsure: play safe
    return any(not ("rmta.net" in h or "amazonaws.com" in h) for h in hosts)


def wanted_settings(domain):
    """Open tracking (needs a links.<domain> CNAME) + receiving replies (MX) unless the domain has its own inbox."""
    receive = not other_mailbox(domain)
    return {"open_tracking": True, "tracking_subdomain": "links",
            "capabilities": {"sending": "enabled", "receiving": "enabled" if receive else "disabled"}}, receive


def domain_info(key, domain_id, receiving, dmarc=True):
    d = ok(*resend_api(key, "GET", f"/domains/{domain_id}"))
    records = d.get("records") or []
    if dmarc:  # Resend doesn't create DMARC, but inbox providers want it: suggest the safe monitoring-only policy
        records.append({"record": "DMARC (recommended)", "type": "TXT", "name": "_dmarc", "value": DMARC,
                        "status": "verified" if has_dmarc(d["name"]) else "not_started"})
    return {"id": d["id"], "name": d["name"], "status": d.get("status", "not_started"), "records": records,
            "receiving": receiving}


def handle(body, user):
    key = str(body.get("api_key", "")).strip()
    if not key and body.get("account_id"):
        key = str(load_account(user["id"], body["account_id"]).get("api_key", ""))
    domain = str(body.get("domain", "")).strip().lower()
    if not key.startswith("re_"):
        raise Bad("Paste your Resend API key (it starts with re_).")
    if not DOMAIN.fullmatch(domain):
        raise Bad("Type just the domain, like yourdomain.com")
    if body.get("action") in ("reply_setup", "reply_check"):
        return reply_domain(key, domain, body["action"] == "reply_check")
    settings, receive = wanted_settings(domain)
    found = next((d for d in ok(*resend_api(key, "GET", "/domains")).get("data", []) if d.get("name") == domain), None)
    if not found:
        code, data = resend_api(key, "POST", "/domains", {"name": domain, **settings})
        if code >= 400 and code not in (401, 403):  # tracking/receiving not allowed on this plan: plain domain
            code, data = resend_api(key, "POST", "/domains", {"name": domain})
            receive = False
        found = ok(code, data)
    else:
        cur = ok(*resend_api(key, "GET", f"/domains/{found['id']}"))
        caps = cur.get("capabilities") or {}
        if (not cur.get("open_tracking") or not cur.get("tracking_subdomain")
                or caps.get("receiving") != settings["capabilities"]["receiving"]):
            code, _ = resend_api(key, "PATCH", f"/domains/{found['id']}", settings)  # best effort: never block setup
            receive = receive and code < 400
        if body.get("action") == "check":
            ok(*resend_api(key, "POST", f"/domains/{found['id']}/verify", {}))
    return domain_info(key, found["id"], receive)


def reply_domain(key, domain, check):
    """reply.<domain>: a receive-only Resend domain (just one MX record, nothing else on the main domain changes).
    Every email from every service gets Reply-To reply@reply.<domain>, so all replies land in the Inbox chat."""
    name = "reply." + domain.removeprefix("reply.")
    found = next((d for d in ok(*resend_api(key, "GET", "/domains")).get("data", []) if d.get("name") == name), None)
    if not found:
        found = ok(*resend_api(key, "POST", "/domains", {"name": name, "capabilities": {"sending": "disabled", "receiving": "enabled"}}))
    elif check:
        ok(*resend_api(key, "POST", f"/domains/{found['id']}/verify", {}))
    info = domain_info(key, found["id"], True, dmarc=False)
    # the domain is usable for replies once its receiving MX checks out, even if Resend's overall status lags
    mx_ok = any(r.get("type") == "MX" and r.get("status") == "verified" for r in info["records"])
    return {**info, "status": "verified" if mx_ok or info["status"] == "verified" else info["status"], "reply_address": "reply@" + name}


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=4096)

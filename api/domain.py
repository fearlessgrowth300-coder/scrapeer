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
from send import Bad, resend_api  # noqa: E402

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


def domain_info(key, domain_id):
    d = ok(*resend_api(key, "GET", f"/domains/{domain_id}"))
    records = d.get("records") or []
    # Resend doesn't create DMARC, but inbox providers want it: suggest the safe monitoring-only policy
    records.append({"record": "DMARC (recommended)", "type": "TXT", "name": "_dmarc", "value": DMARC,
                    "status": "verified" if has_dmarc(d["name"]) else "not_started"})
    return {"id": d["id"], "name": d["name"], "status": d.get("status", "not_started"), "records": records}


def handle(body):
    key = str(body.get("api_key", "")).strip()
    domain = str(body.get("domain", "")).strip().lower()
    if not key.startswith("re_"):
        raise Bad("Paste your Resend API key (it starts with re_).")
    if not DOMAIN.fullmatch(domain):
        raise Bad("Type just the domain, like yourdomain.com")
    found = next((d for d in ok(*resend_api(key, "GET", "/domains")).get("data", []) if d.get("name") == domain), None)
    if not found:
        found = ok(*resend_api(key, "POST", "/domains", {"name": domain}))
    elif body.get("action") == "check" and found.get("status") != "verified":
        ok(*resend_api(key, "POST", f"/domains/{found['id']}/verify", {}))
    return domain_info(key, found["id"])


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            data = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)) or b"{}")
            self._send(200, handle(data))
        except Bad as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": f"Server error ({type(e).__name__})"})

    def _send(self, code, data):
        out = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

"""POST /api/hook?a=<account id> — Resend webhooks (opened / delivered / clicked / bounced / spam / reply received)
for one saved Resend account. Each request is verified with that webhook's own Svix signing secret (kept
encrypted with the account), then stored in scrapeer_events for the account's owner. Anything unsigned,
stale or forged is rejected.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, db, decrypt  # noqa: E402

KEEP = {"email.delivered", "email.opened", "email.clicked", "email.bounced", "email.complained", "email.received"}
UUID = re.compile(r"[0-9a-f-]{36}")


def svix_ok(secret, headers, body, now=None):
    """Svix scheme: base64(HMAC-SHA256(key, f"{id}.{timestamp}.{body}")), key = base64 part of whsec_..."""
    msg_id, ts, sigs = headers.get("svix-id", ""), headers.get("svix-timestamp", ""), headers.get("svix-signature", "")
    if not (msg_id and ts.isdigit() and sigs and secret.startswith("whsec_")):
        return False
    if abs((now or time.time()) - int(ts)) > 300:  # replayed or very late
        return False
    key = base64.b64decode(secret.split("_", 1)[1])
    want = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    return any(hmac.compare_digest(want, s.split(",", 1)[1]) for s in sigs.split() if s.startswith("v1,"))


def addr(s):
    m = re.search(r"[^\s<>\"]+@[^\s<>\"]+", str(s or ""))
    return m.group(0).lower() if m else ""


def handle(account_id, headers, raw):
    if not UUID.fullmatch(account_id or ""):
        raise Bad("unknown account", 404)
    rows = db("GET", "scrapeer_accounts", {"id": f"eq.{account_id}", "select": "id,user_id,secret"})
    if not rows:
        raise Bad("unknown account", 404)
    acct = decrypt(rows[0]["secret"])
    if not svix_ok(acct.get("hook_secret", ""), headers, raw):
        raise Bad("bad signature", 401)
    ev = json.loads(raw)
    if ev.get("type") not in KEEP:
        return
    d = ev.get("data") or {}
    contact = addr(d.get("from")) if ev["type"] == "email.received" else addr((d.get("to") or [""])[0])
    db("POST", "scrapeer_events?on_conflict=event_id", prefer="return=minimal,resolution=ignore-duplicates", body={
        "event_id": headers.get("svix-id"), "user_id": rows[0]["user_id"], "account_id": account_id, "type": ev["type"],
        "email_id": d.get("email_id"), "contact": contact, "subject": str(d.get("subject") or "")[:300],
        "at": ev.get("created_at") or d.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            raw = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 262144))
            handle((parse_qs(urlparse(self.path).query).get("a") or [""])[0], self.headers, raw)
            code = 200
        except Bad as e:
            code = e.status
        except Exception:
            code = 500  # Resend retries later
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _selfcheck():
    secret = "whsec_" + base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
    body, ts = b'{"type":"email.opened"}', str(int(time.time()))
    sig = base64.b64encode(hmac.new(base64.b64decode(secret[6:]), f"msg_1.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    good = {"svix-id": "msg_1", "svix-timestamp": ts, "svix-signature": "v1,bad v1," + sig}
    assert svix_ok(secret, good, body)
    assert not svix_ok(secret, good, body + b" ")                                    # tampered body
    assert not svix_ok(secret, {**good, "svix-timestamp": str(int(ts) - 900)}, body)  # replay
    assert not svix_ok("whsec_" + base64.b64encode(b"x" * 32).decode(), good, body)   # wrong secret
    assert not svix_ok("", good, body)                                                # no secret saved
    assert addr("Bob <BOB@x.com>") == "bob@x.com"
    print("hook selfcheck ok")


if __name__ == "__main__":
    _selfcheck()

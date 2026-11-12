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
from _auth import Bad, db, decrypt, hook_token  # noqa: E402
from _push import notify  # noqa: E402

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


MAILJET = {"sent": "email.delivered", "open": "email.opened", "click": "email.clicked", "bounce": "email.bounced",
           "blocked": "email.bounced", "spam": "email.complained"}
BREVO = {"delivered": "email.delivered", "opened": "email.opened", "uniqueOpened": "email.opened", "click": "email.clicked",
         "hardBounce": "email.bounced", "blocked": "email.bounced", "invalid": "email.bounced", "spam": "email.complained"}


def iso(ts):
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts)))
    except (TypeError, ValueError):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def other_events(provider, raw):
    """Mailjet/Brevo payload (one event or a list) -> rows like the Resend ones."""
    data = json.loads(raw or b"null")
    out = []
    for ev in data if isinstance(data, list) else [data]:
        if not isinstance(ev, dict):
            continue
        if provider == "mailjet":
            kind, ts = MAILJET.get(ev.get("event")), ev.get("time")
            eid = f"mj-{ev.get('MessageID')}-{ev.get('event')}-{ts}"
        else:
            kind, ts = BREVO.get(ev.get("event")), ev.get("ts_event") or ev.get("ts_epoch") or ev.get("ts")
            ts = int(ts) // 1000 if ts and int(ts) > 10**11 else ts  # ts_epoch is in milliseconds
            eid = f"br-{ev.get('message-id') or ev.get('id')}-{ev.get('event')}-{ts}"
        if kind and ev.get("email"):
            out.append({"event_id": eid[:200], "type": kind, "contact": addr(ev["email"]), "subject": str(ev.get("subject") or "")[:300], "at": iso(ts)})
    return out


def handle(account_id, headers, raw, token=""):
    if not UUID.fullmatch(account_id or ""):
        raise Bad("unknown account", 404)
    rows = db("GET", "scrapeer_accounts", {"id": f"eq.{account_id}", "select": "id,user_id,provider,secret"})
    if not rows:
        raise Bad("unknown account", 404)
    if rows[0]["provider"] in ("mailjet", "brevo"):
        if not hmac.compare_digest(token or "", hook_token(account_id)):
            raise Bad("bad token", 401)
        for e in other_events(rows[0]["provider"], raw):
            db("POST", "scrapeer_events?on_conflict=event_id", prefer="return=minimal,resolution=ignore-duplicates",
               body={**e, "user_id": rows[0]["user_id"], "account_id": account_id})
        return
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
    if ev["type"] == "email.received":  # every service's replies land here (shared reply address), so one place to notify
        try:
            notify(rows[0]["user_id"], f"💬 New reply from {contact}", str(d.get("subject") or ""))
        except Exception:
            pass  # the reply is saved; a missed notification must not make Resend retry


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            raw = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 262144))
            q = parse_qs(urlparse(self.path).query)
            handle((q.get("a") or [""])[0], self.headers, raw, (q.get("t") or [""])[0])
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
    mj = other_events("mailjet", b'[{"event":"open","time":1794340000,"MessageID":7,"email":"Bob@X.com"},{"event":"unsub","email":"a@b.c"}]')
    assert mj == [{"event_id": "mj-7-open-1794340000", "type": "email.opened", "contact": "bob@x.com", "subject": "", "at": "2026-11-10T19:46:40Z"}], mj
    br = other_events("brevo", b'{"event":"hardBounce","email":"x@y.com","message-id":"<m1>","ts_event":1794340000,"subject":"Hi"}')
    assert br[0]["type"] == "email.bounced" and br[0]["subject"] == "Hi" and br[0]["at"] == "2026-11-10T19:46:40Z"
    assert other_events("brevo", b'{"event":"opened","email":"x@y.com","ts_epoch":1794340000123}')[0]["at"] == "2026-11-10T19:46:40Z"
    print("hook selfcheck ok")


if __name__ == "__main__":
    _selfcheck()

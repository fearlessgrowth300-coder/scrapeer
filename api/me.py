"""POST /api/me — the signed-in user's saved data.

{"action": "load"}                          -> {"email", "accounts": [public fields only], "state": {...}}
{"action": "add_account", "account": {...}} -> tests the login, then stores it ENCRYPTED; returns public fields
{"action": "remove_account", "id": "..."}
{"action": "save_state", "state": {...}}    -> sent log, already-emailed list, do-not-email, drafts, read replies
{"action": "ensure_hooks"}                  -> registers a signed Resend webhook per saved Resend account (once)
{"action": "events", "since": iso}          -> opened/delivered/clicked/bounced/spam/reply events after `since`
"""
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, db, decrypt, encrypt, serve  # noqa: E402

NAMES = {"brevo": "Brevo", "mailjet": "Mailjet", "resend": "Resend", "smtp": "Email"}
FIELDS = ("provider", "api_key", "from", "reply_to", "user", "pass", "from_name", "host", "port", "cap", "domain")
PUBLIC = ("from", "reply_to", "from_name", "domain")  # safe to send back to the browser
STATE_KEYS = ("log", "sent", "dne", "draft", "read", "reply")
APP_URL = os.environ.get("APP_URL", "https://scrapeer-brown.vercel.app").rstrip("/")
HOOK_EVENTS = ["email.bounced", "email.clicked", "email.complained", "email.delivered", "email.opened", "email.received"]


def ensure_hooks(user):
    """One webhook per saved Resend account → /api/hook?a=<id>; its signing secret is kept inside the encrypted blob."""
    from send import resend_api  # noqa: E402
    out = []
    for r in db("GET", "scrapeer_accounts", {"user_id": f"eq.{user['id']}", "provider": "eq.resend", "select": "id,label,secret"}) or []:
        acct = decrypt(r["secret"])
        if acct.get("hook_secret"):
            out.append({"label": r["label"], "ok": True})
            continue
        key, endpoint = acct.get("api_key", ""), f"{APP_URL}/api/hook?a={r['id']}"
        code, data = resend_api(key, "GET", "/webhooks")
        hook = next((w for w in (data or {}).get("data", []) if w.get("endpoint") == endpoint), None) if code == 200 else None
        if hook:  # already registered earlier (e.g. secret lost): fetch its secret
            code, full = resend_api(key, "GET", f"/webhooks/{hook['id']}")
            hook = {**hook, **(full or {})} if code == 200 else hook
        else:
            code, hook = resend_api(key, "POST", "/webhooks", {"endpoint": endpoint, "events": HOOK_EVENTS})
            if code >= 400:
                out.append({"label": r["label"], "ok": False, "error": str((hook or {}).get("message") or code)})
                continue
        if not (hook or {}).get("signing_secret"):
            out.append({"label": r["label"], "ok": False, "error": "Resend didn't return a signing secret"})
            continue
        acct.update(hook_id=hook.get("id"), hook_secret=hook["signing_secret"])
        db("PATCH", "scrapeer_accounts", {"id": f"eq.{r['id']}", "user_id": f"eq.{user['id']}"},
           body={"secret": encrypt(acct)}, prefer="return=minimal")
        out.append({"label": r["label"], "ok": True, "new": True})
    return out


def public_row(r):
    return {"id": r["id"], "label": r["label"], "provider": r["provider"], "cap": r["cap"], **(r.get("public") or {})}


def handle(body, user):
    action = body.get("action")
    if action == "load":
        rows = db("GET", "scrapeer_accounts", {"user_id": f"eq.{user['id']}", "order": "created_at.asc",
                                               "select": "id,label,provider,cap,public"}) or []
        st = db("GET", "scrapeer_state", {"user_id": f"eq.{user['id']}", "select": "data"}) or []
        return {"email": user["email"], "accounts": [public_row(r) for r in rows], "state": st[0]["data"] if st else {}}

    if action == "add_account":
        from send import send  # noqa: E402  (verify the login before saving it)
        acct = {k: v for k, v in (body.get("account") or {}).items() if k in FIELDS}
        if acct.get("provider") not in NAMES:
            raise Bad("Pick a service.")
        send({"account": acct, "action": "verify"})
        cap = max(1, min(int(acct.get("cap") or 100), 100000))
        label = f"{NAMES[acct['provider']]} · {(acct.get('from') or acct.get('user') or '').strip().lower()}"
        row = {"user_id": user["id"], "label": label, "provider": acct["provider"], "cap": cap,
               "public": {k: str(acct.get(k) or "") for k in PUBLIC}, "secret": encrypt(acct)}
        saved = db("POST", "scrapeer_accounts?on_conflict=user_id,label", body=row,
                   prefer="return=representation,resolution=merge-duplicates")
        return {"account": public_row(saved[0])}

    if action == "remove_account":
        db("DELETE", "scrapeer_accounts", {"id": f"eq.{body.get('id')}", "user_id": f"eq.{user['id']}"}, prefer="return=minimal")
        return {"ok": True}

    if action == "ensure_hooks":
        return {"hooks": ensure_hooks(user)}

    if action == "events":
        since = str(body.get("since") or "1970-01-01T00:00:00Z")[:40]
        rows = db("GET", "scrapeer_events", {"user_id": f"eq.{user['id']}", "created_at": f"gt.{since}", "order": "created_at.asc",
                                             "limit": "500", "select": "id,type,contact,subject,email_id,at,created_at"})
        return {"events": rows or []}

    if action == "save_state":
        state = {k: v for k, v in (body.get("state") or {}).items() if k in STATE_KEYS}
        if len(json.dumps(state)) > 3_500_000:
            raise Bad("Your saved data is too large — clear the sent log.")
        db("POST", "scrapeer_state?on_conflict=user_id", body={"user_id": user["id"], "data": state, "updated_at": datetime.now(timezone.utc).isoformat()},
           prefer="return=minimal,resolution=merge-duplicates")
        return {"ok": True}

    raise Bad("Unknown action.")


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=4_000_000)

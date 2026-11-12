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
import base64  # noqa: E402
from _auth import Bad, _http, db, decrypt, encrypt, hook_token, serve  # noqa: E402
from _push import push_host_ok  # noqa: E402

NAMES = {"brevo": "Brevo", "mailjet": "Mailjet", "resend": "Resend", "smtp": "Email"}
FIELDS = ("provider", "api_key", "from", "reply_to", "user", "pass", "from_name", "host", "port", "cap", "domain")
PUBLIC = ("from", "reply_to", "from_name", "domain")  # safe to send back to the browser
STATE_KEYS = ("log", "sent", "dne", "draft", "read", "reply", "order", "refs", "sig", "scrapes", "templates", "counts")
APP_URL = os.environ.get("APP_URL", "https://scrapeer-brown.vercel.app").rstrip("/")
HOOK_EVENTS = ["email.bounced", "email.clicked", "email.complained", "email.delivered", "email.opened", "email.received"]


MJ_EVENTS = ["sent", "open", "click", "bounce", "spam", "blocked"]
BREVO_EVENTS = ["delivered", "opened", "uniqueOpened", "click", "hardBounce", "spam", "blocked", "invalid"]


def mailjet_hook(acct, url):
    """Mailjet: one callback URL per event type, set with the same API key + secret used for SMTP."""
    auth = {"Authorization": "Basic " + base64.b64encode(f"{acct.get('user', '')}:{acct.get('pass', '')}".encode()).decode()}
    code, data = _http("GET", "https://api.mailjet.com/v3/REST/eventcallbackurl?Limit=100", auth)
    if code != 200:
        return f"Mailjet refused the API key/secret ({code} {str((data or {}).get('ErrorMessage') or '')[:120]})"
    have = {d.get("EventType"): d for d in (data or {}).get("Data", [])}
    busy = []
    for et in MJ_EVENTS:
        cur = have.get(et)
        if cur and cur.get("Url") == url:
            continue
        if cur and APP_URL not in str(cur.get("Url")):
            busy.append(et)  # already used by another app: leave it alone
            continue
        if cur:
            code, _ = _http("PUT", f"https://api.mailjet.com/v3/REST/eventcallbackurl/{cur['ID']}", {**auth, "Content-Type": "application/json"}, {"Url": url, "Status": "alive"})
        else:
            code, _ = _http("POST", "https://api.mailjet.com/v3/REST/eventcallbackurl", {**auth, "Content-Type": "application/json"},
                            {"EventType": et, "Url": url, "Status": "alive"})
        if code >= 400:
            return f"Mailjet didn't accept the '{et}' webhook ({code})"
    return f"Mailjet already sends {', '.join(busy)} events to another app" if busy else ""


def brevo_reason(code, data):
    """Brevo's own words, plus the fix for the two usual causes."""
    msg = str((data or {}).get("message") or (data or {}).get("code") or "")[:160] if isinstance(data, dict) else ""
    low = msg.lower()
    if "ip" in low.split() or "ip address" in low or "unrecognised" in low or "unrecognized" in low:
        return f"Brevo is blocking unknown IPs for API keys — Brevo → Settings → Security → Authorized IPs → 'Deactivate for API keys'. (Brevo said: {msg})"
    if code in (401, 403) or "key" in low:
        return f"Brevo didn't accept the API key — use the xkeysib- key from Settings → SMTP & API → API Keys. (Brevo said: {code} {msg})"
    return f"Brevo error {code}: {msg}"


def brevo_hook(acct, url):
    """Brevo: needs a Brevo *API* key (the SMTP key can't manage webhooks)."""
    key = str(acct.get("api_key") or "")
    if not key:
        return "needs_key"
    h = {"api-key": key, "accept": "application/json", "content-type": "application/json"}
    code, data = _http("GET", "https://api.brevo.com/v3/webhooks?type=transactional", h)
    if code == 400 and "does not exist" in str((data or {}).get("message", "")).lower():
        code, data = 200, {"webhooks": []}  # Brevo answers 400 "Webhook record does not exist" for an empty list
    if code != 200:
        return brevo_reason(code, data)
    if any(w.get("url") == url for w in (data or {}).get("webhooks", [])):
        return ""
    code, data = _http("POST", "https://api.brevo.com/v3/webhooks", h,
                       {"url": url, "description": "Scrapeer ticks & pop-ups", "events": BREVO_EVENTS, "type": "transactional"})
    return "" if code < 400 else brevo_reason(code, data)


def ensure_hooks(user):
    """Live events for every saved account → /api/hook?a=<id>. Resend: signed (secret kept in the encrypted blob);
    Mailjet/Brevo: unsigned, so their URL carries a per-account secret token."""
    from send import resend_api  # noqa: E402
    out = []
    for r in db("GET", "scrapeer_accounts", {"user_id": f"eq.{user['id']}", "provider": "in.(resend,mailjet,brevo)",
                                             "select": "id,label,provider,secret"}) or []:
        acct = decrypt(r["secret"])
        if acct.get("hook_secret") or acct.get("hook_ok"):
            out.append({"label": r["label"], "ok": True})
            continue
        if r["provider"] in ("mailjet", "brevo"):
            url = f"{APP_URL}/api/hook?a={r['id']}&t={hook_token(r['id'])}"
            err = (mailjet_hook if r["provider"] == "mailjet" else brevo_hook)(acct, url)
            if err and not err.endswith("to another app"):
                out.append({"label": r["label"], "ok": False, "error": err})
                continue
            acct["hook_ok"] = True
            db("PATCH", "scrapeer_accounts", {"id": f"eq.{r['id']}", "user_id": f"eq.{user['id']}"},
               body={"secret": encrypt(acct)}, prefer="return=minimal")
            out.append({"label": r["label"], "ok": True, "new": True, **({"warning": err} if err else {})})
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


def log_key(entry):
    """Identity of one log line (old lines have no ts: fall back to the 'when' text)."""
    return f"{entry.get('ts') or entry.get('when')}|{entry.get('email')}|{entry.get('status')}|{entry.get('via')}"


def merge_state(cur, new):
    """Union of history from every tab/device: nothing already saved can be dropped by a stale copy.
    Settings-like keys (dne, draft, sig, reply, order) are last-write-wins so edits still work."""
    out = {**cur, **new}
    seen, log = set(), []
    for e in sorted((new.get("log") or []) + (cur.get("log") or []), key=lambda e: -(e.get("ts") or 0)):
        if isinstance(e, dict) and log_key(e) not in seen:
            seen.add(log_key(e)); log.append(e)
    out["log"] = log[:3000]
    out["sent"] = {**(cur.get("sent") or {}), **(new.get("sent") or {})}
    out["refs"] = dict(list({**(cur.get("refs") or {}), **(new.get("refs") or {})}.items())[-500:])
    cc, nc = cur.get("counts") or {}, new.get("counts") or {}  # ponytail: max per day+sender, two tabs sending at once can undercount
    out["counts"] = {k: max(cc.get(k, 0), nc.get(k, 0)) for k in {**cc, **nc}}
    out["read"] = list(dict.fromkeys((cur.get("read") or []) + (new.get("read") or [])))[-5000:]
    return out


def public_row(r):
    return {"id": r["id"], "label": r["label"], "provider": r["provider"], "cap": r["cap"], **(r.get("public") or {})}


def handle(body, user):
    action = body.get("action")
    if action == "load":
        rows = db("GET", "scrapeer_accounts", {"user_id": f"eq.{user['id']}", "order": "created_at.asc",
                                               "select": "id,label,provider,cap,public"}) or []
        st = db("GET", "scrapeer_state", {"user_id": f"eq.{user['id']}", "select": "data"}) or []
        state = st[0]["data"] if st else {}
        from _scout import is_junk  # noqa: E402  (re-check saved searches with the current junk rules)
        for sc in state.get("scrapes") or []:
            for e in sc.get("results") or []:
                e["email"] = e.get("email", "").removeprefix("u003e")
            sc["results"] = [e for e in sc.get("results") or [] if not is_junk(e["email"])]
        return {"email": user["email"], "accounts": [public_row(r) for r in rows], "state": state}

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

    if action == "push_subscribe":  # this phone/browser wants a notification when a reply arrives
        sub = body.get("sub") or {}
        ep, keys = str(sub.get("endpoint") or ""), sub.get("keys") or {}
        if len(ep) > 1000 or not push_host_ok(ep) or not keys.get("p256dh") or not keys.get("auth"):
            raise Bad("This browser's notification setup isn't supported.")
        db("POST", "scrapeer_push?on_conflict=endpoint", prefer="return=minimal,resolution=merge-duplicates",
           body={"endpoint": ep, "user_id": user["id"], "keys": {"p256dh": str(keys["p256dh"])[:200], "auth": str(keys["auth"])[:100]}})
        return {"ok": True}

    if action == "ensure_hooks":
        return {"hooks": ensure_hooks(user)}

    if action == "events":
        since = str(body.get("since") or "1970-01-01T00:00:00Z")[:40]
        rows = db("GET", "scrapeer_events", {"user_id": f"eq.{user['id']}", "created_at": f"gt.{since}", "order": "created_at.asc",
                                             "limit": "500", "select": "id,account_id,type,contact,subject,email_id,at,created_at"})
        return {"events": rows or []}

    if action in ("save_state", "clear_log"):
        incoming = {k: v for k, v in (body.get("state") or {}).items() if k in STATE_KEYS}
        cur = (db("GET", "scrapeer_state", {"user_id": f"eq.{user['id']}", "select": "data"}) or [{}])[0].get("data") or {}
        if action == "clear_log":  # the only way history gets removed
            state = {**cur, "log": [], "sent": {}}
        else:
            state = merge_state(cur, incoming)
        if len(json.dumps(state)) > 3_500_000:
            raise Bad("Your saved data is too large — clear the sent log.")
        db("POST", "scrapeer_state?on_conflict=user_id", body={"user_id": user["id"], "data": state, "updated_at": datetime.now(timezone.utc).isoformat()},
           prefer="return=minimal,resolution=merge-duplicates")
        return {"ok": True, "log": state.get("log", []), "sent": state.get("sent", {}), "read": state.get("read", []), "refs": state.get("refs", {})}

    raise Bad("Unknown action.")


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=4_000_000)

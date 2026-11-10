"""POST /api/track — status of sent emails and the replies received, read live from the signed-in
user's saved Resend account(s). Nothing is stored on this server.

{"action": "sent"}                         -> {"emails": [{id, to, subject, last_event, created_at}]}
{"action": "inbox"}                        -> {"replies": [{id, key, from, subject, created_at, message_id}]}
{"action": "read", "key": 0, "id": "..."}  -> {from, to, subject, text, created_at, message_id}
"""
import html as htmllib
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, serve, user_accounts  # noqa: E402
from send import resend_api  # noqa: E402

UUID = re.compile(r"[0-9a-f-]{36}")


def call(key, path):
    code, data = resend_api(key, "GET", path)
    if code in (401, 403):
        raise Bad("Resend refused one of your API keys — remove and re-add that account.")
    if code >= 400:
        raise Bad("Resend: " + str(data.get("message") or code)[:200])
    return data


def all_pages(key, path, pages):
    out, after = [], None
    for _ in range(pages):
        d = call(key, f"{path}?limit=100" + (f"&after={after}" if after else ""))
        rows = d.get("data") or []
        out += rows
        if not d.get("has_more") or not rows:
            break
        after = rows[-1]["id"]
    return out


def to_text(html):
    """Replies come as HTML; send back plain text only (no remote images/scripts in the app)."""
    html = re.sub(r"(?is)<(script|style|head)[^>]*>.*?</\1>", " ", html or "")
    html = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</tr>", "\n", html)
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", html))
    text = "\n".join(re.sub(r"[ \t\xa0]+", " ", line).strip() for line in text.splitlines())
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def handle(body, user):
    accts = [a for a in user_accounts(user["id"], "resend") if str(a.get("api_key", "")).startswith("re_")]
    accts = [a for i, a in enumerate(accts) if a["api_key"] not in {b["api_key"] for b in accts[:i]}][:10]  # one per key
    keys = [a["api_key"] for a in accts]
    if not keys:
        raise Bad("Add a Resend account in the Send tab to see delivery status and replies.")
    action = body.get("action")
    if action == "sent":
        return {"emails": [{"id": e.get("id"), "to": (e.get("to") or [""])[0], "subject": e.get("subject"),
                            "last_event": e.get("last_event"), "created_at": e.get("created_at")}
                           for k in keys for e in all_pages(k, "/emails", 10)]}
    if action == "inbox":
        return {"replies": [{"id": e.get("id"), "key": i, "account_id": accts[i]["id"], "from": e.get("from"), "to": e.get("to"),
                             "subject": e.get("subject"), "created_at": e.get("created_at"),
                             "message_id": e.get("message_id")}
                            for i, k in enumerate(keys) for e in all_pages(k, "/emails/receiving", 3)]}
    if action == "read":
        rid, i = str(body.get("id", "")), int(body.get("key") or 0)
        if not UUID.fullmatch(rid) or not 0 <= i < len(keys):
            raise Bad("Unknown message.")
        e = call(keys[i], f"/emails/receiving/{rid}")
        return {"from": e.get("from"), "to": e.get("to"), "subject": e.get("subject"), "created_at": e.get("created_at"),
                "message_id": e.get("message_id"), "text": (e.get("text") or "").strip() or to_text(e.get("html"))}
    raise Bad("Unknown action.")


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=8192)

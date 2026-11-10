"""POST /api/track — chat-style inbox data, read live from the signed-in user's saved Resend account(s).
Nothing is stored on this server.

{"action": "sent"}    -> {"emails":  [{id, key, account_id, to, subject, last_event, created_at}]}
{"action": "inbox"}   -> {"replies": [{id, key, account_id, from, subject, created_at, message_id}]}
{"action": "bodies", "items": [{"id", "key", "dir": "out"|"in"}]}   (max 40)
                      -> {"bodies": {id: text}}   replies have quoted history ("On … wrote:") cut off
"""
import html as htmllib
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, serve, user_accounts  # noqa: E402
from send import resend_api  # noqa: E402

UUID = re.compile(r"[0-9a-f-]{36}")


def call(key, path):
    for attempt in range(4):
        code, data = resend_api(key, "GET", path)
        if code != 429:  # Resend allows ~2 requests/second: wait and retry
            break
        time.sleep(1.1)
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
    html = re.sub(r"(?is)<blockquote.*?</blockquote>", "\n", html)  # quoted history in HTML replies
    html = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</tr>", "\n", html)
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", html))
    text = "\n".join(re.sub(r"[ \t\xa0]+", " ", line).strip() for line in text.splitlines())
    return re.sub(r"\n{3,}", "\n\n", text).strip()


QUOTE_STARTS = [
    re.compile(r"^On .{0,300}?wrote:\s*$", re.M | re.S),          # Gmail/Apple: "On Mon, … Harper <…> wrote:"
    re.compile(r"^-{2,}\s*Original Message\s*-{2,}", re.M | re.I),  # Outlook
    re.compile(r"^_{8,}\s*$", re.M),                                # Outlook web divider
    re.compile(r"^From: .+\n(?:Sent|Date): ", re.M),                # Outlook header block
    re.compile(r"^Le .{0,200}a écrit\s*:\s*$", re.M | re.S),        # French Gmail
]


def reply_refs(headers):
    """Message-IDs a reply points back to, newest first (In-Reply-To, then References)."""
    if isinstance(headers, list):  # [{"name": .., "value": ..}] form
        headers = {h.get("name", ""): h.get("value", "") for h in headers if isinstance(h, dict)}
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    ids = re.findall(r"<[^<>\s]+>", h.get("in-reply-to", "")) + re.findall(r"<[^<>\s]+>", h.get("references", ""))[::-1]
    return list(dict.fromkeys(i.lower() for i in ids))[:20]


def strip_quoted(text):
    """Keep only what the person actually wrote, like a chat message."""
    cut = min([m.start() for p in QUOTE_STARTS for m in [p.search(text)] if m] or [len(text)])
    lines = [line for line in text[:cut].splitlines() if not line.startswith(">")]
    return "\n".join(lines).strip() or text.strip()


def handle(body, user):
    accts = [a for a in user_accounts(user["id"], "resend") if str(a.get("api_key", "")).startswith("re_")]
    accts = [a for i, a in enumerate(accts) if a["api_key"] not in {b["api_key"] for b in accts[:i]}][:10]  # one per key
    keys = [a["api_key"] for a in accts]
    if not keys:
        raise Bad("Add a Resend account in the Send tab to see your conversations here.")
    action = body.get("action")
    if action == "sent":
        return {"emails": [{"id": e.get("id"), "key": i, "account_id": accts[i]["id"], "to": (e.get("to") or [""])[0],
                            "subject": e.get("subject"), "last_event": e.get("last_event"), "created_at": e.get("created_at"),
                            "message_id": e.get("message_id")}
                           for i, k in enumerate(keys) for e in all_pages(k, "/emails", 10)]}
    if action == "inbox":
        return {"replies": [{"id": e.get("id"), "key": i, "account_id": accts[i]["id"], "from": e.get("from"),
                             "subject": e.get("subject"), "created_at": e.get("created_at"), "message_id": e.get("message_id")}
                            for i, k in enumerate(keys) for e in all_pages(k, "/emails/receiving", 3)]}
    if action == "refs":  # which of our emails each reply answers (In-Reply-To / References headers)
        out = {}
        for it in (body.get("items") or [])[:40]:
            rid, i = str(it.get("id", "")), int(it.get("key") or 0)
            if UUID.fullmatch(rid) and 0 <= i < len(keys):
                out[rid] = reply_refs(call(keys[i], f"/emails/receiving/{rid}").get("headers"))
        return {"refs": out}
    if action == "bodies":
        out = {}
        for it in (body.get("items") or [])[:40]:
            rid, i, direction = str(it.get("id", "")), int(it.get("key") or 0), it.get("dir")
            if not UUID.fullmatch(rid) or not 0 <= i < len(keys) or direction not in ("in", "out"):
                continue
            e = call(keys[i], f"/emails/{rid}" if direction == "out" else f"/emails/receiving/{rid}")
            text = (e.get("text") or "").strip() or to_text(e.get("html"))
            out[rid] = strip_quoted(text) if direction == "in" else text
        return {"bodies": out}
    raise Bad("Unknown action.")


def _selfcheck():
    reply = "Sounds good, call me Friday.\n\nThanks,\nBob\n\nOn Mon, Nov 10, 2026 at 3:00 PM Harper Hodson <harper@legacyfalcon.tech>\nwrote:\n> Hi Bob,\n> quick question"
    assert strip_quoted(reply) == "Sounds good, call me Friday.\n\nThanks,\nBob", repr(strip_quoted(reply))
    assert strip_quoted("Yes!\n-----Original Message-----\nFrom: me") == "Yes!"
    assert strip_quoted("> only quotes") == "> only quotes"  # never return an empty bubble
    assert to_text("<p>Hi</p><blockquote>old stuff</blockquote>") == "Hi"
    assert reply_refs({"In-Reply-To": "<b@x>", "References": "<a@x> <B@x>"}) == ["<b@x>", "<a@x>"]
    assert reply_refs([{"name": "in-reply-to", "value": "<c@y>"}]) == ["<c@y>"] and reply_refs(None) == []
    print("track selfcheck ok")


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=16384)


if __name__ == "__main__":
    _selfcheck()

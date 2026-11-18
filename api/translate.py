"""POST /api/translate {"texts": ["subject", "body"], "to": "de"} -> {"texts": [...], "from": "en"}
Google Translate's free web endpoint: keeps {{fields}}, {a|b} and line breaks as they are."""
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, serve  # noqa: E402

URL = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&dt=t&tl="


def translate(text, to):
    if not text.strip():
        return text, ""
    req = urllib.request.Request(URL + to, data=urllib.parse.urlencode({"q": text}).encode(),
                                 headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.load(r)
    return "".join(seg[0] for seg in d[0] if seg and seg[0]), d[2] if len(d) > 2 else ""


def handle(body, user):
    to, texts = str(body.get("to", "")).lower(), body.get("texts")
    if not re.fullmatch(r"[a-z]{2,3}(-[a-z]{2,4})?", to) or not isinstance(texts, list) or not 1 <= len(texts) <= 3:
        raise Bad("bad translate request")
    out, src = [], ""
    for t in texts:
        if not isinstance(t, str) or len(t) > 8000:
            raise Bad("text too long to translate")
        try:
            tr, s = translate(t, to)
        except (OSError, ValueError, IndexError, TypeError):
            raise Bad("Translation service didn't answer. Try again.", 502)
        out.append(tr); src = src or s
    return {"texts": out, "from": src}


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=40000)

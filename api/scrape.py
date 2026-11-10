"""POST /api/scrape {"site": "example.com"} -> {"site", "pages", "emails": [...]}  (one site per call)."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, serve  # noqa: E402
from _scout import scout  # noqa: E402


def handle(body, user):
    site = str(body.get("site", "")).strip()
    if not site or len(site) > 300 or any(c.isspace() for c in site):
        raise Bad("give one website")
    return scout(site)


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=4096)

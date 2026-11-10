"""POST /api/scrape {"site": "example.com"} -> {"site", "pages", "emails": [...]}  (one site per call)."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _scout import scout  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)) or b"{}")
            site = str(body.get("site", "")).strip()
            if not site or len(site) > 300 or any(c.isspace() for c in site):
                return self._send(400, {"error": "give one website"})
            self._send(200, scout(site))
        except Exception as e:
            self._send(500, {"error": type(e).__name__})

    def _send(self, code, data):
        out = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

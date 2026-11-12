"""GET /api/config — the PUBLIC Supabase settings the sign-in screen needs (URL + anon key; never the service key)."""
import json
import os
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        out = json.dumps({"url": os.environ.get("SUPABASE_URL", ""), "anon": os.environ.get("SUPABASE_ANON_KEY", ""),
                          "vapid": os.environ.get("VAPID_PUBLIC", "")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

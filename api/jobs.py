"""POST /api/jobs — background searches and sending on the server (see _jobs.py). VPS only."""
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import serve  # noqa: E402
from _jobs import handle  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=8_000_000)

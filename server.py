"""Run Scrapeer on your own server (VPS): the same api/*.py handlers Vercel runs, plus the app's files.
python3 server.py [port]   — put Caddy/nginx in front for HTTPS."""
import importlib
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "api"))
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".png": "image/png",
         ".webmanifest": "application/manifest+json", ".json": "application/json"}
STATIC = {"/" + f for f in os.listdir(ROOT) if os.path.splitext(f)[1] in TYPES and f != "server.py"}


class App(BaseHTTPRequestHandler):
    def _api(self, method):
        name = self.path.split("?")[0][5:].strip("/")
        if not re.fullmatch(r"[a-z]+", name) or not os.path.exists(os.path.join(ROOT, "api", name + ".py")):
            return self._send(404, b"not found", "text/plain")
        fn = getattr(importlib.import_module(name).handler, "do_" + method, None)  # Vercel's handler class, run as-is
        return fn(self) if fn else self._send(405, b"method not allowed", "text/plain")

    def _send(self, code, body, ctype, cache="no-cache"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0].split("#")[0]
        if path.startswith("/api/"):
            return self._api("GET")
        path = "/index.html" if path == "/" else path
        if path not in STATIC:
            return self._send(404, b"not found", "text/plain")
        with open(os.path.join(ROOT, path[1:]), "rb") as f:
            self._send(200, f.read(), TYPES[os.path.splitext(path)[1]], "public, max-age=3600" if path.endswith(".png") else "no-cache")

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self._api("POST")
        self._send(404, b"not found", "text/plain")

    def log_message(self, fmt, *args):  # one short line per request in the service log
        sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    try:  # carry on with searches/sending that were running before a restart
        import _jobs
        _jobs.resume()
    except Exception as e:
        sys.stderr.write(f"resume failed: {e}
")
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8790), App).serve_forever()

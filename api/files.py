"""POST /api/files {"action": "upload", "name", "size", "type", "kind": "file" | "logo"}
-> a one-time signed upload token; the browser uploads straight to Supabase Storage (big videos never pass
through this server). Files go in the PRIVATE bucket under the user's own folder; signature logos go in the
public bucket (they must be publicly loadable inside emails).
"""
import os
import re
import secrets
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(__file__))
from _auth import SUPABASE_URL, Bad, serve, storage  # noqa: E402

FILES, PUBLIC = "scrapeer-files", "scrapeer-public"
LOGO_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
MAX_FILE, MAX_LOGO = 50 * 1024 * 1024, 2 * 1024 * 1024


def safe_name(name):
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", os.path.basename(str(name or "file"))).strip("-.") or "file"
    return name[-80:]


def handle(body, user):
    if body.get("action") != "upload":
        raise Bad("Unknown action.")
    logo = body.get("kind") == "logo"
    size, ctype = int(body.get("size") or 0), str(body.get("type") or "")
    if size <= 0:
        raise Bad("That file is empty.")
    if logo and (ctype not in LOGO_TYPES or size > MAX_LOGO):
        raise Bad("Logo must be a PNG, JPG, GIF or WebP image under 2 MB.")
    if not logo and size > MAX_FILE:
        raise Bad("Files can be up to 50 MB each.")
    bucket = PUBLIC if logo else FILES
    path = f"{user['id']}/{secrets.token_hex(8)}/{safe_name(body.get('name'))}"
    code, data = storage("POST", f"/object/upload/sign/{bucket}/{path}", {})
    if code >= 400 or not (data or {}).get("url"):
        raise Bad("Couldn't prepare the upload. Try again.", 502)
    token = (parse_qs(urlparse(data["url"]).query).get("token") or [""])[0]
    out = {"bucket": bucket, "path": path, "token": token}
    if logo:
        out["public_url"] = f"{SUPABASE_URL}/storage/v1/object/public/{PUBLIC}/{path}"
    return out


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=4096)

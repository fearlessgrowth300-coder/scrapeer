"""Shared server plumbing: who is signed in (Supabase Auth), private storage (Supabase Postgres via the
service key — tables have RLS on and no policies, so browsers can never read them) and AES-256-GCM
encryption for API keys/passwords at rest.

Env (Vercel): SUPABASE_URL, SUPABASE_ANON_KEY (anon or sb_publishable_), SUPABASE_SERVICE_KEY (service_role or sb_secret_), SCRAPEER_SECRET (base64, 32 bytes).
"""
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")


class Bad(Exception):
    """A problem the user can fix; message is shown in the app. status 401 = sign in again."""

    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def _http(method, url, headers, body=None, timeout=20):
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except OSError:
        raise Bad("Couldn't reach the database. Try again.", 503)


def require_user(headers):
    """The signed-in user ({id, email}) from the 'Authorization: Bearer <supabase access token>' header."""
    if not SUPABASE_URL or not SERVICE_KEY:
        raise Bad("The app's database isn't configured yet.", 503)
    token = (headers.get("Authorization") or "").removeprefix("Bearer ").strip()
    if not token:
        raise Bad("Please sign in.", 401)
    code, user = _http("GET", SUPABASE_URL + "/auth/v1/user", {"apikey": SERVICE_KEY, "Authorization": "Bearer " + token})
    if code != 200 or not (user or {}).get("id"):
        raise Bad("Your session expired — please sign in again.", 401)
    return {"id": user["id"], "email": user.get("email", "")}


def db(method, table, query=None, body=None, prefer="return=representation"):
    """PostgREST call with the service key. query: dict of PostgREST filters, e.g. {"user_id": "eq.<id>"}."""
    url = f"{SUPABASE_URL}/rest/v1/{table}" + ("?" + urllib.parse.urlencode(query) if query else "")
    headers = {"apikey": SERVICE_KEY, "Content-Type": "application/json", "Prefer": prefer}
    if not SERVICE_KEY.startswith("sb_"):  # legacy service_role JWT; new sb_secret_ keys must not be sent as Bearer
        headers["Authorization"] = "Bearer " + SERVICE_KEY
    code, data = _http(method, url, headers, body)
    if code >= 400:
        msg = (data or {}).get("message", "") if isinstance(data, dict) else ""
        raise Bad("Database error" + (f": {msg}" if msg else f" ({code})") +
                  (" — run supabase/schema.sql in the Supabase SQL editor." if "does not exist" in msg or code == 404 else ""), 500)
    return data


def _key():
    raw = base64.b64decode(os.environ.get("SCRAPEER_SECRET", "") or b"")
    if len(raw) != 32:
        raise Bad("The app's encryption key isn't configured yet.", 503)
    return raw


def encrypt(obj):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return base64.b64encode(nonce + AESGCM(_key()).encrypt(nonce, json.dumps(obj).encode(), None)).decode()


def decrypt(token):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(token)
    return json.loads(AESGCM(_key()).decrypt(raw[:12], raw[12:], None))


def user_accounts(user_id, provider=None):
    """The user's saved sending accounts, oldest first, secrets decrypted (server-side only)."""
    query = {"user_id": f"eq.{user_id}", "order": "created_at.asc", "select": "id,label,provider,cap,public,secret"}
    if provider:
        query["provider"] = f"eq.{provider}"
    rows = db("GET", "scrapeer_accounts", query) or []
    return [{**decrypt(r["secret"]), "id": r["id"], "label": r["label"], "cap": r["cap"]} for r in rows]


def load_account(user_id, account_id):
    if not isinstance(account_id, str) or len(account_id) != 36:
        raise Bad("Unknown sending account — re-add it in the Send tab.")
    rows = db("GET", "scrapeer_accounts", {"id": f"eq.{account_id}", "user_id": f"eq.{user_id}", "select": "id,label,cap,secret"})
    if not rows:
        raise Bad("That sending account was removed — re-add it in the Send tab.")
    return {**decrypt(rows[0]["secret"]), "id": rows[0]["id"], "label": rows[0]["label"], "cap": rows[0]["cap"]}


def serve(handler, fn, limit=65536):
    """Run fn(body, user) for a signed-in user and write JSON. Every API route goes through here."""
    try:
        user = require_user(handler.headers)
        n = min(int(handler.headers.get("Content-Length") or 0), limit)
        out, code = fn(json.loads(handler.rfile.read(n) or b"{}"), user), 200
    except Bad as e:
        out, code = {"error": str(e)}, e.status
    except Exception as e:
        out, code = {"error": f"Server error ({type(e).__name__})"}, 500
    raw = json.dumps(out).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _selfcheck():
    os.environ["SCRAPEER_SECRET"] = base64.b64encode(b"k" * 32).decode()
    blob = encrypt({"api_key": "re_secret"})
    assert "re_secret" not in blob and decrypt(blob) == {"api_key": "re_secret"}
    try:
        decrypt(blob[:-4] + ("AAAA" if not blob.endswith("AAAA") else "BBBB"))
        raise AssertionError("tampered ciphertext must not decrypt")
    except AssertionError:
        raise
    except Exception:
        pass
    print("auth selfcheck ok")


if __name__ == "__main__":
    _selfcheck()

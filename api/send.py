"""POST /api/send — send ONE email via Resend (own domain, account.provider="resend") or the user's own mailbox (SMTP + app password).

{"account_id": "<saved account>"}  or  {"account": {...unsaved form...}}   (signed-in users only)
 "action": "verify"}                                   -> just log in, to test the account
 "to": "x@site.com", "subject": "...", "body": "..."   -> send it

The account is sent with each request and never stored on the server.
"""
import base64
import html as htmllib
import json
import os
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import SUPABASE_URL, Bad, load_account, serve, storage  # noqa: E402,F401  (Bad re-exported for track/domain)
from _scout import EMAIL, is_public  # noqa: E402

HOSTS = {"gmail.com": "smtp.gmail.com", "googlemail.com": "smtp.gmail.com", "outlook.com": "smtp-mail.outlook.com",
         "hotmail.com": "smtp-mail.outlook.com", "live.com": "smtp-mail.outlook.com", "yahoo.com": "smtp.mail.yahoo.com",
         "icloud.com": "smtp.mail.me.com", "me.com": "smtp.mail.me.com", "zoho.com": "smtp.zoho.com", "aol.com": "smtp.aol.com"}
PORTS = (465, 587, 2525)


def one_line(s, limit):
    return " ".join(str(s or "").split())[:limit]


PROVIDER_HOSTS = {"brevo": "smtp-relay.brevo.com", "mailjet": "in-v3.mailjet.com"}


def sender_of(acct):
    """The From address: explicit 'from' (Brevo/Mailjet logins aren't your address), else the login itself."""
    sender = str(acct.get("from") or acct.get("user") or "").strip().lower()
    if not EMAIL.fullmatch(sender):
        raise Bad("Enter the From address (an address on your domain).")
    return sender


KEY_HINTS = {  # provider-specific mix-ups we can spot before even connecting
    "brevo": lambda u, p: "That's your Brevo API key (xkeysib-…). The SMTP key box needs the SMTP key, which starts with xsmtpsib- "
                          "(Brevo → Settings → SMTP & API → SMTP tab → Generate a new SMTP key)." if p.startswith("xkeysib-") else
                          "The SMTP login should look like 12345a001@smtp-brevo.com (Brevo → Settings → SMTP & API → SMTP tab)." if "@" not in u else "",
}


def login_error(acct, e):
    """Human explanation + the server's own words, so the user can tell a wrong key from an unapproved account."""
    code = getattr(e, "smtp_code", None)
    raw = getattr(e, "smtp_error", b"") or b""
    said = (raw.decode("utf-8", "ignore") if isinstance(raw, bytes) else str(raw)).strip().replace("\n", " ")[:220]
    provider = acct.get("provider")
    if provider == "brevo":
        tip = ("Brevo refused the login. Check: (1) the SMTP key starts with xsmtpsib- (not the xkeysib- API key), "
               "(2) the SMTP login is the one shown on Brevo's SMTP tab, (3) your Brevo account is approved for sending "
               "(new accounts must be activated — look for a banner in Brevo or contact their support).")
    elif provider == "mailjet":
        tip = "Mailjet refused the login. Use your Mailjet API key as the login and the Secret key as the password."
    else:
        tip = "Login refused. Check the login and password/key (Gmail needs an App Password with 2-step verification on)."
    return tip + (f" Server said: {code} {said}" if said else "")


def connect(acct):
    user = str(acct.get("user", "")).strip()
    if not user or not acct.get("pass"):
        raise Bad("Enter the SMTP login and password / key.")
    hint = KEY_HINTS.get(acct.get("provider"), lambda u, p: "")(user, str(acct.get("pass")).strip())
    if hint:
        raise Bad(hint)
    sender = sender_of(acct)
    domain = (user if "@" in user else sender).split("@")[1].lower()
    host = str(acct.get("host") or PROVIDER_HOSTS.get(acct.get("provider")) or HOSTS.get(domain) or "smtp." + domain).strip()
    port = int(acct.get("port") or 587)
    if port not in PORTS:
        raise Bad("Port must be 587, 465 or 2525.")
    if not is_public(f"https://{host}:{port}/"):
        raise Bad(f"Can't reach mail server {host}. Set the SMTP server under Advanced.")
    ctx = ssl.create_default_context()
    try:
        server = smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) if port == 465 else smtplib.SMTP(host, port, timeout=20)
        if port != 465:
            server.starttls(context=ctx)
    except (OSError, smtplib.SMTPException) as e:
        raise Bad(f"Couldn't connect to {host}:{port} ({type(e).__name__}).")
    try:
        server.login(user, str(acct["pass"]).replace(" ", "") if domain in ("gmail.com", "googlemail.com") else str(acct["pass"]))
    except (smtplib.SMTPAuthenticationError, smtplib.SMTPServerDisconnected) as e:
        # Gmail hangs up after the first wrong password, so smtplib's retry shows up as "disconnected"
        raise Bad(login_error(acct, e))
    except (OSError, smtplib.SMTPException) as e:
        raise Bad(f"Mail server error during login ({type(e).__name__}).")
    return server, sender


def resend_api(key, method, path, payload=None):
    req = urllib.request.Request("https://api.resend.com" + path, method=method,
                                 data=json.dumps(payload).encode() if payload is not None else None,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json",
                                          "User-Agent": "scrapeer/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}
    except OSError:
        raise Bad("Couldn't reach Resend. Try again.")


def send_resend(body):
    acct = body.get("account") or {}
    key, sender = str(acct.get("api_key", "")).strip(), str(acct.get("from", "")).strip().lower()
    reply_to = str(acct.get("reply_to", "")).strip().lower()
    if not key.startswith("re_") or not EMAIL.fullmatch(sender):
        raise Bad("Enter your Resend API key (starts with re_) and a From address on your domain.")
    if reply_to and not EMAIL.fullmatch(reply_to):
        raise Bad("The 'Replies go to' address isn't valid.")
    domain = sender.split("@")[1]
    if body.get("action") == "verify":
        code, data = resend_api(key, "GET", "/domains")
        if code in (401, 403) and data.get("name") == "restricted_api_key":
            return {"ok": True, "message": "Key works (sending-only key, so the domain can't be checked — send a test)."}
        if code != 200:
            raise Bad("Resend refused the API key." if code in (401, 403) else f"Resend error: {data.get('message', code)}")
        status = {d.get("name"): d.get("status") for d in data.get("data", [])}
        if status.get(domain) != "verified":
            raise Bad(f"{domain} is not verified in Resend" + (f" (status: {status[domain]})." if domain in status else " — add it under Domains."))
        return {"ok": True, "message": f"Resend connected — {domain} is verified."}
    to = str(body.get("to", "")).strip().lower()
    if not EMAIL.fullmatch(to):
        raise Bad("Bad recipient address.")
    subject, text = one_line(body.get("subject"), 300), str(body.get("body", ""))[:20000]
    if not subject or not text.strip():
        raise Bad("Subject and message can't be empty.")
    unsub = reply_to or sender
    text, html = with_extras(body, text)
    payload = {"from": formataddr((one_line(acct.get("from_name"), 80), sender)), "to": [to], "subject": subject,
               "text": text, "headers": {}}
    if not body.get("plain"):
        payload.update(html=html, headers={"List-Unsubscribe": f"<mailto:{unsub}?subject=unsubscribe>"})
    if body.get("_attach"):
        payload["attachments"] = [{"filename": n, "content": base64.b64encode(b).decode()} for n, _, b in body["_attach"]]
    in_reply_to = one_line(body.get("in_reply_to"), 300)
    if in_reply_to.startswith("<") and in_reply_to.endswith(">"):  # answering a reply: keep it in the same thread
        payload["headers"].update({"In-Reply-To": in_reply_to, "References": in_reply_to})
    if reply_to:
        payload["reply_to"] = reply_to
    code, data = resend_api(key, "POST", "/emails", payload)
    if code != 200:
        msg = data.get("message") or f"HTTP {code}"
        raise Bad(("Resend refused the API key: " if code in (401, 403) else "Resend: ") + str(msg)[:200])
    return {"ok": True, "id": data.get("id")}


def html_twin(text):
    """Plain-looking HTML copy of the text: every service needs HTML to add its open-tracking pixel."""
    return ("<div style=\"font-family:Arial,sans-serif;font-size:14px;line-height:1.5\">"
            + htmllib.escape(text).replace("\n", "<br>") + "</div>")


ATTACH_LIMIT = 7 * 1024 * 1024  # bigger than this goes as a download link (big attachments get blocked / spam-foldered)


def human_size(n):
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{max(1, n // 1024)} KB"


def gather_files(files, user_id):
    """Uploaded files → small ones attached, the rest as 30-day private download links. Only the user's own files."""
    attach, links, total = [], [], 0
    for f in (files or [])[:10]:
        path, name = str(f.get("path", "")), str(f.get("name") or "file")[:120]
        if not path.startswith(user_id + "/") or ".." in path:
            raise Bad("Unknown attachment.")
        size, ctype = int(f.get("size") or 0), str(f.get("type") or "application/octet-stream")[:100]
        if size and total + size <= ATTACH_LIMIT:
            code, data = storage("GET", f"/object/scrapeer-files/{path}", raw=True)
            if code == 200 and data:
                attach.append((name, ctype, data)); total += len(data)
                continue
        code, data = storage("POST", f"/object/sign/scrapeer-files/{path}", {"expiresIn": 30 * 86400})
        if code >= 400 or not (data or {}).get("signedURL"):
            raise Bad(f"Couldn't prepare {name}. Try again.")
        links.append((name, size, f"{SUPABASE_URL}/storage/v1{data['signedURL']}"))
    return attach, links


def with_extras(body, text):
    """Message + download links + signature (text and logo — GIFs animate inside the email)."""
    links = body.get("_links") or []
    if links:
        text += "\n\n" + "\n".join(f"📎 {n} ({human_size(s)}): {u}" for n, s, u in links)
    sig = body.get("signature") or {}
    sig_text = str(sig.get("text") or "").strip()[:500]
    logo = str(sig.get("logo") or "")
    logo_ok = logo.startswith(f"{SUPABASE_URL}/storage/v1/object/public/scrapeer-public/") and '"' not in logo
    html = html_twin(text)
    if sig_text:
        text += "\n\n" + sig_text
    if sig_text or logo_ok:
        html += ("<div style=\"margin-top:18px;font-family:Arial,sans-serif;font-size:13px;line-height:1.45;color:#444\">"
                 + htmllib.escape(sig_text).replace("\n", "<br>")
                 + (f'<br><img src="{logo}" alt="logo" style="max-width:160px;max-height:80px;margin-top:8px;border:0">' if logo_ok else "")
                 + "</div>")
    if links:  # make the links clickable in the HTML version
        for n, s, u in links:
            html = html.replace(htmllib.escape(u), f'<a href="{htmllib.escape(u)}">{htmllib.escape(u)}</a>')
    return text, html


def send(body):
    acct = body.get("account") or {}
    override = str(body.get("reply_to") or "").strip().lower()
    if EMAIL.fullmatch(override):  # the user's shared reply inbox wins over each account's own reply-to
        acct = {**acct, "reply_to": override}
        body = {**body, "account": acct}
    if acct.get("provider") == "resend":
        return send_resend(body)
    server, user = connect(acct)
    try:
        if body.get("action") == "verify":
            return {"ok": True, "message": f"Connected as {user}"}
        to = str(body.get("to", "")).strip().lower()
        if not EMAIL.fullmatch(to):
            raise Bad("Bad recipient address.")
        subject, text = one_line(body.get("subject"), 300), str(body.get("body", ""))[:20000]
        if not subject or not text.strip():
            raise Bad("Subject and message can't be empty.")
        msg = EmailMessage()
        msg["From"] = formataddr((one_line(acct.get("from_name"), 80), user))
        msg["To"] = to
        msg["Subject"] = subject
        msg["Message-ID"] = make_msgid(domain=user.split("@")[1])
        reply_to = str(acct.get("reply_to", "")).strip().lower()
        if EMAIL.fullmatch(reply_to):
            msg["Reply-To"] = reply_to
        plain = bool(body.get("plain"))
        if not plain:
            msg["List-Unsubscribe"] = f"<mailto:{reply_to if EMAIL.fullmatch(reply_to) else user}?subject=unsubscribe>"
        if acct.get("provider") == "mailjet" and not plain:
            msg["X-Mailjet-TrackOpen"] = "1"  # Brevo tracks opens on HTML mail by default
        text, html = with_extras(body, text)
        msg.set_content(text)
        if not plain:
            msg.add_alternative(html, subtype="html")
        for name, ctype, data in body.get("_attach") or []:
            main, _, sub = (ctype if "/" in ctype else "application/octet-stream").partition("/")
            msg.add_attachment(data, maintype=main, subtype=sub, filename=name)
        try:
            server.send_message(msg)
        except smtplib.SMTPRecipientsRefused:
            raise Bad("The mail server refused this recipient.")
        except smtplib.SMTPException as e:
            raise Bad(f"Mail server said no: {str(e)[:160]}")
        return {"ok": True, "message_id": msg["Message-ID"]}
    finally:
        try:
            server.quit()
        except Exception:
            pass


def handle(body, user):
    if body.get("account_id"):  # a saved account: its secrets never leave the server
        body = {**body, "account": load_account(user["id"], body["account_id"])}
    body = {k: v for k, v in body.items() if not k.startswith("_")}  # internal fields can't come from the browser
    if body.get("files"):
        attach, links = gather_files(body["files"], user["id"])
        body = {**body, "_attach": attach, "_links": links}
    if body.get("signature") and not str((body["signature"] or {}).get("logo") or "").startswith(
            f"{SUPABASE_URL}/storage/v1/object/public/scrapeer-public/{user['id']}/"):
        body = {**body, "signature": {"text": (body["signature"] or {}).get("text", "")}}  # only your own logo
    return send(body)


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle)

"""POST /api/send — send ONE email via Resend (own domain, account.provider="resend") or the user's own mailbox (SMTP + app password).

{"account_id": "<saved account>"}  or  {"account": {...unsaved form...}}   (signed-in users only)
 "action": "verify"}                                   -> just log in, to test the account
 "to": "x@site.com", "subject": "...", "body": "..."   -> send it

The account is sent with each request and never stored on the server.
"""
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
from _auth import Bad, load_account, serve  # noqa: E402,F401  (Bad re-exported for track/domain)
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


def connect(acct):
    user = str(acct.get("user", "")).strip()
    if not user or not acct.get("pass"):
        raise Bad("Enter the SMTP login and password / key.")
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
    except (smtplib.SMTPAuthenticationError, smtplib.SMTPServerDisconnected):
        # Gmail hangs up after the first wrong password, so smtplib's retry shows up as "disconnected"
        raise Bad("Login refused. Check the login and password/key (Gmail needs an App Password with 2-step verification on).")
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
    html = html_twin(text)
    payload = {"from": formataddr((one_line(acct.get("from_name"), 80), sender)), "to": [to], "subject": subject,
               "text": text, "html": html, "headers": {"List-Unsubscribe": f"<mailto:{unsub}?subject=unsubscribe>"}}
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
        msg["List-Unsubscribe"] = f"<mailto:{reply_to if EMAIL.fullmatch(reply_to) else user}?subject=unsubscribe>"
        if acct.get("provider") == "mailjet":
            msg["X-Mailjet-TrackOpen"] = "1"  # Brevo tracks opens on HTML mail by default
        msg.set_content(text)
        msg.add_alternative(html_twin(text), subtype="html")
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
    return send(body)


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle)

"""POST /api/send — send ONE email through the user's own mailbox (SMTP + app password).

{"account": {"user": "me@gmail.com", "pass": "app password", "from_name": "Me", "host": "", "port": 587},
 "action": "verify"}                                   -> just log in, to test the account
 "to": "x@site.com", "subject": "...", "body": "..."   -> send it

The account is sent with each request and never stored on the server.
"""
import json
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _scout import EMAIL, is_public  # noqa: E402

HOSTS = {"gmail.com": "smtp.gmail.com", "googlemail.com": "smtp.gmail.com", "outlook.com": "smtp-mail.outlook.com",
         "hotmail.com": "smtp-mail.outlook.com", "live.com": "smtp-mail.outlook.com", "yahoo.com": "smtp.mail.yahoo.com",
         "icloud.com": "smtp.mail.me.com", "me.com": "smtp.mail.me.com", "zoho.com": "smtp.zoho.com", "aol.com": "smtp.aol.com"}
PORTS = (465, 587, 2525)


class Bad(Exception):
    """A problem the user can fix; message is shown in the app."""


def one_line(s, limit):
    return " ".join(str(s or "").split())[:limit]


def connect(acct):
    user = str(acct.get("user", "")).strip().lower()
    if not EMAIL.fullmatch(user) or not acct.get("pass"):
        raise Bad("Enter your email address and app password.")
    domain = user.split("@")[1]
    host = str(acct.get("host") or HOSTS.get(domain) or "smtp." + domain).strip()
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
        server.login(user, str(acct["pass"]).replace(" ", "") if domain in ("gmail.com", "googlemail.com") else str(acct["pass"]))
    except smtplib.SMTPAuthenticationError:
        raise Bad("Login refused. Use an App Password (not your normal password), and check 2-step verification is on.")
    except (OSError, smtplib.SMTPException) as e:
        raise Bad(f"Couldn't connect to {host}:{port} ({type(e).__name__}).")
    return server, user


def send(body):
    acct = body.get("account") or {}
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
        msg["List-Unsubscribe"] = f"<mailto:{user}?subject=unsubscribe>"
        msg.set_content(text)
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


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            data = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 65536)) or b"{}")
            self._send(200, send(data))
        except Bad as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": f"Server error ({type(e).__name__})"})

    def _send(self, code, data):
        out = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

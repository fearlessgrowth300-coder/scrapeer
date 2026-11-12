"""Phone/desktop notifications that arrive even when the app is closed (Web Push).
RFC 8291 (aes128gcm payload encryption) + RFC 8292 (VAPID), done with the cryptography lib the app already uses.
Keys: VAPID_PRIVATE = base64 of a P-256 private key PEM, VAPID_PUBLIC = its raw public point, base64url."""
import base64
import json
import os
import struct
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# only real browser push services: the server POSTs to this URL, so never to anything a user typed in
PUSH_HOSTS = ("fcm.googleapis.com", "push.services.mozilla.com", "push.apple.com", "notify.windows.com")


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64(s):
    return base64.urlsafe_b64decode(str(s) + "=" * (-len(str(s)) % 4))


def raw_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def push_host_ok(endpoint):
    u = urlparse(str(endpoint))
    host = (u.hostname or "").lower()
    return u.scheme == "https" and any(host == h or host.endswith("." + h) for h in PUSH_HOSTS)


def _hkdf(salt, ikm, info, n):
    return HKDF(hashes.SHA256(), n, salt, info).derive(ikm)


def _keys(salt, auth, shared, ua_pub, as_pub):
    ikm = _hkdf(auth, shared, b"WebPush: info\x00" + ua_pub + as_pub, 32)
    return _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16), _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)


def encrypt(p256dh, auth, payload):
    ua_pub, auth = unb64(p256dh), unb64(auth)
    eph = ec.generate_private_key(ec.SECP256R1())
    as_pub, salt = raw_pub(eph), os.urandom(16)
    shared = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_pub))
    cek, nonce = _keys(salt, auth, shared, ua_pub, as_pub)
    return salt + struct.pack(">IB", 4096, len(as_pub)) + as_pub + AESGCM(cek).encrypt(nonce, payload + b"\x02", None)


def vapid_auth(endpoint, key, pub_b64):
    u = urlparse(endpoint)
    seg = lambda d: b64(json.dumps(d, separators=(",", ":")).encode())
    msg = seg({"typ": "JWT", "alg": "ES256"}) + "." + seg(
        {"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 12 * 3600, "sub": "https://scrapeer-brown.vercel.app"})
    r, s = decode_dss_signature(key.sign(msg.encode(), ec.ECDSA(hashes.SHA256())))
    return f"vapid t={msg}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}, k={pub_b64}"


def notify(user_id, title, body, url="/#inbox"):
    """Best effort: a failed notification must never break the webhook that triggered it."""
    from _auth import db  # noqa: E402  (lazy: keeps the self-check below free of the database)
    pem, pub = os.environ.get("VAPID_PRIVATE", ""), os.environ.get("VAPID_PUBLIC", "")
    if not pem or not pub:
        return
    key = serialization.load_pem_private_key(base64.b64decode(pem), None)
    payload = json.dumps({"title": title[:120], "body": body[:200], "url": url}).encode()
    for row in db("GET", "scrapeer_push", {"user_id": f"eq.{user_id}", "select": "endpoint,keys"}) or []:
        ep = row["endpoint"]
        if not push_host_ok(ep):
            continue
        req = urllib.request.Request(ep, method="POST", data=encrypt(row["keys"]["p256dh"], row["keys"]["auth"], payload), headers={
            "Authorization": vapid_auth(ep, key, pub), "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream", "TTL": "86400", "Urgency": "high"})
        try:
            urllib.request.urlopen(req, timeout=5).close()
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):  # the phone unsubscribed or the app was removed
                db("DELETE", "scrapeer_push", {"endpoint": f"eq.{ep}"}, prefer="return=minimal")
        except OSError:
            pass


if __name__ == "__main__":  # round trip: decrypt as the browser would, and check the VAPID signature
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    ua, auth = ec.generate_private_key(ec.SECP256R1()), os.urandom(16)
    blob = encrypt(b64(raw_pub(ua)), b64(auth), b'{"title":"hi"}')
    salt, rs, n = blob[:16], struct.unpack(">I", blob[16:20])[0], blob[20]
    as_pub = blob[21:21 + n]
    shared = ua.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_pub))
    cek, nonce = _keys(salt, auth, shared, raw_pub(ua), as_pub)
    assert rs == 4096 and AESGCM(cek).decrypt(nonce, blob[21 + n:], None) == b'{"title":"hi"}\x02'
    k = ec.generate_private_key(ec.SECP256R1())
    h = vapid_auth("https://fcm.googleapis.com/fcm/send/abc", k, b64(raw_pub(k)))
    jwt = h.split("t=")[1].split(",")[0]
    m, sig = jwt.rsplit(".", 1)
    sig = unb64(sig)
    k.public_key().verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), m.encode(), ec.ECDSA(hashes.SHA256()))
    assert json.loads(unb64(m.split(".")[1]))["aud"] == "https://fcm.googleapis.com"
    assert push_host_ok("https://fcm.googleapis.com/fcm/send/x") and push_host_ok("https://web.push.apple.com/abc")
    assert not push_host_ok("http://fcm.googleapis.com/x") and not push_host_ok("https://evil.com/fcm.googleapis.com")
    assert not push_host_ok("https://fcm.googleapis.com.evil.com/x")
    print("push selfcheck ok")

"""Scrapeer engine: find the REAL contact emails on a website, not random junk.

- crawls the pages that hold contacts (contact/about/team/impressum/policies links, one hop deeper)
- decodes hidden emails: Cloudflare protection, mailto links, JSON-LD, "name [at] site [dot] com"
- drops junk (image@2x.png, tracker hashes, example.com, theme/vendor addresses)
- keeps only domains that can receive mail (MX record) and scores each email high/medium/low
"""
import concurrent.futures as cf
import html as htmllib
import ipaddress
import json
import re
import socket
import urllib.request
from urllib.parse import unquote, urlencode, urljoin, urlparse

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/130.0 Safari/537.36", "Accept-Language": "en-US,en;q=0.9"}
EMAIL = re.compile(r"[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9-]+\.)+[a-z]{2,24}", re.I)
OBFUSCATED = re.compile(r"([a-z0-9._%+-]+)\s*[\[\(\{]\s*(?:at|@)\s*[\]\)\}]\s*"
                        r"([a-z0-9-]+(?:\s*[\[\(\{]\s*(?:dot|\.)\s*[\]\)\}]\s*[a-z0-9-]+)+)", re.I)
MAILTO = re.compile(r"mailto:([^\"'?>\s]+)", re.I)
CFEMAIL = re.compile(r"(?:data-cfemail=\"|/cdn-cgi/l/email-protection#)([0-9a-f]{6,})", re.I)
HREF = re.compile(r"<a\b[^>]*href=[\"']([^\"'#]+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
CONTACT_WORDS = re.compile(r"contact|about|team|staff|people|impressum|imprint|kontakt|get.in.touch|reach.us|"
                           r"support|legal|privacy|policies|leadership|who-we-are", re.I)
FALLBACK_PATHS = ("contact", "contact-us", "about", "about-us", "pages/contact", "pages/about",
                  "policies/privacy-policy", "policies/contact-information", "privacy-policy", "impressum")
MAX_PAGES = 12
TIMEOUT = 8

FREE_MAIL = {"gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com",
             "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "zoho.com", "yandex.com", "mail.com"}
ROLE = {"info", "sales", "admin", "contact", "contactus", "hello", "hi", "office", "support", "help", "team",
        "enquiries", "inquiries", "booking", "bookings", "orders", "service", "mail", "billing", "careers", "jobs",
        "press", "media", "marketing", "general", "reception", "privacy", "legal", "accounts"}
# addresses a site's code/theme carries that belong to someone else
VENDOR_DOMAINS = ("wixpress.com", "sentry.io", "squarespace.com", "shopify.com", "godaddy.com", "wordpress.com",
                  "wordpress.org", "w3.org", "schema.org", "jquery.com", "cloudflare.com", "example.com",
                  "example.org", "domain.com", "yourdomain.com", "email.com", "test.com", "mysite.com",
                  "website.com", "company.com", "placeholder.com")
PLACEHOLDER_LOCALS = {"name", "email", "you", "your", "yourname", "youremail", "user", "username", "john.doe",
                      "johndoe", "jane.doe", "janedoe", "firstname", "first.last", "firstname.lastname", "someone",
                      "test", "noreply", "no-reply", "donotreply", "do-not-reply", "example"}
NOT_TLD = ("png", "jpg", "jpeg", "gif", "svg", "webp", "js", "css", "ico", "woff", "woff2", "mp4", "pdf")


def is_public(url):
    """Only fetch real internet sites: blocks localhost, private networks and cloud metadata (SSRF)."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(p.hostname, p.port or 443)}
    except OSError:
        return False
    return all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, newurl) if is_public(newurl) else None


_opener = urllib.request.build_opener(_SafeRedirect)


def fetch(url):
    if not is_public(url):
        return "", url
    try:
        with _opener.open(urllib.request.Request(url, headers=UA), timeout=TIMEOUT) as r:
            return r.read(3_000_000).decode("utf-8", "ignore"), r.geturl()
    except Exception:
        return "", url


def decode_cf(hexstr):
    """Cloudflare 'email protection': first byte is an XOR key for the rest."""
    key = int(hexstr[:2], 16)
    return bytes(int(hexstr[i:i + 2], 16) ^ key for i in range(2, len(hexstr) - 1, 2)).decode("utf-8", "ignore")


def is_junk(email):
    local, _, domain = email.partition("@")
    return (domain.rsplit(".", 1)[-1] in NOT_TLD or "@2x" in email or "@3x" in email
            or local in PLACEHOLDER_LOCALS or re.fullmatch(r"[0-9a-f]{16,}", local) is not None
            or any(domain == v or domain.endswith("." + v) for v in VENDOR_DOMAINS))


def emails_in(page):
    """{email: source} — source ranks how deliberately the site published it."""
    found = {}

    def add(e, src):
        e = unquote(e).strip().strip(".").lower()
        if EMAIL.fullmatch(e) and not is_junk(e):
            found.setdefault(e, src)  # first (strongest) source wins

    for h in CFEMAIL.findall(page):
        add(decode_cf(h), "hidden")
    for m in MAILTO.findall(page):
        add(htmllib.unescape(m), "mailto")
    for blob in re.findall(r"<script[^>]+ld\+json[^>]*>(.*?)</script>", page, re.S | re.I):
        for e in re.findall(r"\"email\"\s*:\s*\"(?:mailto:)?([^\"]+)\"", blob):
            add(e, "schema")
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", page))
    for local, dom in OBFUSCATED.findall(text):
        add(local + "@" + re.sub(r"\s*[\[\(\{]\s*(?:dot|\.)\s*[\]\)\}]\s*", ".", dom), "hidden")
    for e in EMAIL.findall(text):
        add(e, "text")
    return found


def root(host):
    host = host.lower().removeprefix("www.")
    parts = host.split(".")
    # ponytail: naive registrable domain (co.uk/com.au via the 2-letter rule); use publicsuffix if it misfires
    return ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) == 2 else ".".join(parts[-2:])


def contact_links(page, base):
    host = urlparse(base).netloc
    links = []
    for href, label in HREF.findall(page):
        url = urljoin(base, href.strip())
        if urlparse(url).netloc == host and (CONTACT_WORDS.search(url) or CONTACT_WORDS.search(label)):
            links.append(url.split("#")[0])
    return list(dict.fromkeys(links))


_mx = {}


def has_mx(domain):
    if domain not in _mx:
        try:
            url = "https://dns.google/resolve?" + urlencode({"name": domain, "type": "MX"})
            ans = json.load(urllib.request.urlopen(url, timeout=TIMEOUT))
            _mx[domain] = ans.get("Status") == 0 and any(a.get("type") == 15 for a in ans.get("Answer", []))
        except Exception:
            _mx[domain] = True  # lookup failed: don't throw away a possibly good email
    return _mx[domain]


SOURCE_SCORE = {"mailto": 3, "schema": 3, "hidden": 3, "text": 1}


def score(email, src, pages, site_root, on_contact_page):
    domain = email.split("@")[1]
    s = SOURCE_SCORE[src] + min(pages, 3) + (1 if on_contact_page else 0)
    if root(domain) == site_root:
        s += 4
    elif domain in FREE_MAIL:
        s += 1          # small businesses often use gmail
    else:
        s -= 3          # another company's domain: often the web designer or a partner
    return s


def scout(site):
    site = site.strip()
    if not site.startswith("http"):
        site = "https://" + site
    home, final = fetch(site)
    if not home and site.startswith("https://"):
        home, final = fetch("http://" + site[8:])
    if not home:
        return {"site": site, "error": "site did not load", "emails": []}
    site_root = root(urlparse(final).netloc)
    origin = "{0.scheme}://{0.netloc}/".format(urlparse(final))
    pages, seen = [(home, final)], {site, final}
    todo = contact_links(home, final) + [origin + p for p in FALLBACK_PATHS]
    with cf.ThreadPoolExecutor(8) as pool:
        for _ in range(2):  # round 1: contact pages, round 2: one hop deeper (Policies -> Privacy, About -> Team)
            batch = [u for u in dict.fromkeys(todo) if u not in seen][:MAX_PAGES - len(pages)]
            seen.update(batch)
            todo = []
            for html, url in pool.map(fetch, batch):
                if html and url not in {p[1] for p in pages}:
                    pages.append((html, url))
                    todo += contact_links(html, url)

    hits = {}  # email -> [source, page count, seen on a contact page, first page url]
    for html, url in pages:
        for e, src in emails_in(html).items():
            h = hits.setdefault(e, [src, 0, False, url])
            if SOURCE_SCORE[src] > SOURCE_SCORE[h[0]]:
                h[0] = src
            h[1] += 1
            h[2] = h[2] or bool(CONTACT_WORDS.search(url))

    results = []
    for e, (src, n, contact_pg, url) in hits.items():
        if not has_mx(e.split("@")[1]):
            continue
        s = score(e, src, n, site_root, contact_pg)
        results.append({
            "email": e, "site": site_root, "score": s,
            "confidence": "high" if s >= 7 else "medium" if s >= 4 else "low",
            "type": "role" if re.sub(r"[._-]?\d+$", "", e.split("@")[0]) in ROLE else "personal",
            "source": src, "found_on": url,
        })
    return {"site": site_root, "pages": len(pages), "emails": sorted(results, key=lambda r: -r["score"])}


def _selfcheck():
    page = ('<a href="mailto:Jane.Smith@Acme.co.uk?subject=hi">mail</a> logo@2x.png bob@example.com '
            '<span data-cfemail="42' + "".join(f"{b ^ 0x42:02x}" for b in b"sales@acme.co.uk") + '">x</span>'
            ' write to mike [at] acme [dot] co [dot] uk or 0123456789abcdef0123@sentry.io')
    got = emails_in(page)
    assert got == {"jane.smith@acme.co.uk": "mailto", "sales@acme.co.uk": "hidden", "mike@acme.co.uk": "hidden"}, got
    assert root("www.shop.acme.co.uk") == "acme.co.uk" and root("blog.acme.com") == "acme.com"
    assert score("a@acme.com", "mailto", 2, "acme.com", True) > score("a@webdesignco.com", "mailto", 2, "acme.com", True)
    assert contact_links('<a href="/contact-us">x</a><a href="/shop">Get in touch</a><a href="https://x.com/about">y</a>',
                         "https://acme.com/") == ["https://acme.com/contact-us", "https://acme.com/shop"]
    assert not is_public("http://127.0.0.1/") and not is_public("http://169.254.169.254/") and not is_public("file:///etc/passwd")
    print("selfcheck ok")


if __name__ == "__main__":
    _selfcheck()

"""POST /api/store {"site": "shop.com"} -> facts to personalise an email: store name, a product they sell, niche.
Shopify stores publish /products.json; other sites just give their name."""
import collections
import html as htmllib
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, serve  # noqa: E402
from _scout import fetch  # noqa: E402


def short(title, words=6):
    title = re.split(r"\s[-|–—:]\s|,|\(", htmllib.unescape(title))[0].strip()
    return " ".join(title.split()[:words])


def store_name(page, site):
    m = (re.search(r'property=["\']og:site_name["\'][^>]*content=["\']([^"\']+)', page, re.I)
         or re.search(r"<title[^>]*>([^<]+)", page, re.I))
    name = short(m.group(1), 4) if m else ""
    return name or site.split(".")[0].capitalize()


def facts(site):
    site = re.sub(r"^https?://", "", site.strip().lower()).removeprefix("www.").split("/")[0]
    page, _ = fetch("https://" + site)
    out = {"store": store_name(page, site)}
    raw, _ = fetch(f"https://{site}/products.json?limit=250")
    try:
        products = json.loads(raw).get("products") or []
    except ValueError:
        products = []
    if products:
        newest = max(products, key=lambda p: p.get("published_at") or p.get("created_at") or "")
        types = collections.Counter((p.get("product_type") or "").strip() for p in products if (p.get("product_type") or "").strip())
        out.update(product=short(newest.get("title", "")),
                   niche=types.most_common(1)[0][0].lower() if types else "",
                   product_count=f"{len(products)}+" if len(products) == 250 else str(len(products)))
    return out


def handle(body, user):
    site = str(body.get("site", "")).strip()
    if not site or len(site) > 300 or any(c.isspace() for c in site):
        raise Bad("give one website")
    return facts(site)


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=4096)


if __name__ == "__main__":
    assert short("Glow Serum - 30ml | Free Shipping") == "Glow Serum"
    assert store_name('<meta property="og:site_name" content="Water Glow">', "waterglow.shop") == "Water Glow"
    assert store_name("", "waterglow.shop") == "Waterglow"
    for s in sys.argv[1:]:
        print(s, facts(s))
    print("selfcheck ok")

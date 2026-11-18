"""POST /api/store {"site": "shop.com"} -> facts to personalise an email: store name, a product they sell, niche.
Shopify stores publish /products.json; other sites just give their name."""
import collections
import html as htmllib
import json
import os
import re
import sys
import unicodedata
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _auth import Bad, serve  # noqa: E402
from _scout import fetch  # noqa: E402


# words a cut-off name must not end on (English, German, Spanish, French, Dutch, Italian)
DANGLING = {"", "for", "with", "and", "of", "the", "a", "an", "in", "to", "by", "on", "from", "&", "+",
            "für", "fur", "mit", "und", "aus", "der", "die", "das", "von", "zum", "zur", "de", "del", "la", "el",
            "y", "con", "para", "pour", "et", "le", "les", "du", "des", "en", "voor", "met", "van", "het", "per", "e", "di", "il"}


def short(title, words=6):
    title = re.split(r"\s[-|–—:]\s|,|\(", htmllib.unescape(title))[0].strip()
    title = re.sub(r"^(copy of|kopie von|copia de|copie de)\s+", "", title, flags=re.I)  # Shopify's duplicated products
    cut = title.split()[:words]
    while len(cut) > 1 and re.fullmatch(r"[\d.,/]+", cut[-1]):  # "Riesling trocken 0" (from "0,75 l") -> "Riesling trocken"
        cut.pop()
    while len(cut) > 1 and cut[-1].lower().strip(".&+") in DANGLING:  # "... aus Granit für" -> "... aus Granit"
        cut.pop()
    return " ".join(cut)


# names a page carries that aren't the store's (platform names, generic page titles): use the website name instead
NOT_A_NAME = re.compile(r"^(my ?shopify|shopify|wix|squarespace|bigcommerce|woocommerce|wordpress|home( ?page)?|welcome|"
                        r"online ?store|store|shop|index|untitled|coming soon|password|opening soon|default store|"
                        r"404|page not found|just a moment\.*|access denied|attention required.*)$", re.I)


def store_name(page, site):
    m = (re.search(r'property=["\']og:site_name["\'][^>]*content=["\']([^"\']+)', page, re.I)
         or re.search(r"<title[^>]*>([^<]+)", page, re.I))
    name = ""
    if m:  # a site_name is already just the name ("Love, Logan"), only a page title needs cutting down
        raw = htmllib.unescape(m.group(1))
        name = " ".join(raw.split()[:5]) if "site_name" in m.group(0) else short(raw, 4)
        name = "".join(c for c in name if unicodedata.category(c) not in ("So", "Sk", "Cf", "Cs")).strip()  # flags, emoji
    return name if name and not NOT_A_NAME.match(name) else site.split(".")[0].capitalize()


# a country ending → the language people there read; a language → its main country
CC_LANG = {"de": "de", "at": "de", "ch": "de", "fr": "fr", "be": "fr", "es": "es", "mx": "es", "ar": "es", "it": "it", "nl": "nl",
           "pt": "pt", "br": "pt", "pl": "pl", "se": "sv", "dk": "da", "no": "no", "fi": "fi", "gr": "el", "cz": "cs", "jp": "ja"}
LANG_CC = {"de": "DE", "fr": "FR", "es": "ES", "it": "IT", "nl": "NL", "pt": "PT", "pl": "PL", "sv": "SE", "da": "DK", "nb": "NO",
           "no": "NO", "fi": "FI", "el": "GR", "cs": "CZ", "ja": "JP"}
NOT_COUNTRY = {"co", "io", "me", "tv", "ai", "eu", "fm", "ly", "gg", "to", "cc", "ws", "la", "is"}  # used as words: shop.co, app.io


def locale(page, site):
    """(country code, language) from the domain ending, <html lang="de-DE">, og:locale, then Shopify's own country."""
    tld = site.rsplit(".", 1)[-1]
    tag = re.search(r"<html[^>]*?\slang=[\"']?([a-zA-Z]{2,3})(?:[-_]([a-zA-Z]{2}))?", page)
    og = re.search(r"og:locale[\"'][^>]*content=[\"']([a-z]{2})_([A-Za-z]{2})", page)
    shop = re.search(r'Shopify\.country\s*=\s*"([A-Z]{2})"', page)
    lang = (tag and tag.group(1).lower()) or (og and og.group(1)) or CC_LANG.get(tld) or "en"
    region = ((tag and tag.group(2)) or (og and og.group(2)) or "").upper()
    if len(tld) == 2 and tld not in NOT_COUNTRY:
        country = "GB" if tld == "uk" else tld.upper()
    elif region and not (lang == "en" and region == "US"):  # en-US is just the default on most English sites
        country = region
    else:
        country = (shop and shop.group(1)) or LANG_CC.get(lang) or "US"
    return country, lang


def facts(site, only_locale=False):
    site = re.sub(r"^https?://", "", site.strip().lower()).removeprefix("www.").split("/")[0]
    page, _ = fetch("https://" + site)
    out = {"store": store_name(page, site)}
    out["country"], out["lang"] = locale(page, site)
    if only_locale:
        return out
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
    return facts(site, bool(body.get("only_locale")))


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        serve(self, handle, limit=4096)


if __name__ == "__main__":
    assert short("Glow Serum - 30ml | Free Shipping") == "Glow Serum"
    assert short("Personalisierter ovaler Tiergrabstein aus Granit für Hunde") == "Personalisierter ovaler Tiergrabstein aus Granit"
    assert short("Cozy Blanket for the Sofa and Bed") == "Cozy Blanket for the Sofa"
    assert store_name('<meta property="og:site_name" content="Water Glow">', "waterglow.shop") == "Water Glow"
    assert store_name("", "waterglow.shop") == "Waterglow"
    assert store_name('<meta property="og:site_name" content="Love, Logan">', "x.shop") == "Love, Logan"
    assert store_name('<meta property="og:site_name" content="Ecuador 🇪🇨">', "x.shop") == "Ecuador"
    assert store_name("<title>Glow - Home</title>", "x.shop") == "Glow"
    assert store_name('<meta property="og:site_name" content="Myshopify">', "harlemwines.com") == "Harlemwines"
    assert store_name("<title>Just a moment...</title>", "acme.com") == "Acme"
    assert locale('<html lang="de">', "yepoda.de") == ("DE", "de")
    assert locale('<html class="x" lang="de-AT">', "shop.com") == ("AT", "de")
    assert locale('<html lang="en">', "shop.co.uk") == ("GB", "en")
    assert locale('<html lang="en-US">', "shop.com") == ("US", "en")
    assert locale('<html lang="fr">', "shop.com") == ("FR", "fr")
    assert locale('<html lang="en"> Shopify.country = "AU";', "shop.com") == ("AU", "en")
    assert locale("", "shop.de") == ("DE", "de") and locale("", "shop.io") == ("US", "en")
    for s in sys.argv[1:]:
        print(s, facts(s))
    print("selfcheck ok")

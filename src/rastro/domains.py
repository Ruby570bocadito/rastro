"""Domain name helpers shared by every source."""

from __future__ import annotations

import ipaddress

# Public suffixes with two labels that show up in this kind of data; enough for a first pass.
TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "com.es", "org.es", "gob.es", "com.mx", "gob.mx", "com.ar", "gob.ar", "com.br",
    "gov.br", "com.co", "gov.co", "com.pe", "gob.pe", "go.cr", "com.ve", "gob.ve", "com.ec", "gob.ec",
    "com.uy", "com.py", "com.bo", "com.gt", "com.do", "com.pa", "com.sv", "com.hn", "com.ni", "co.cr",
    "com.au", "co.nz", "co.jp", "co.in", "com.cn", "com.tr", "co.za",
}
# Second-level labels that country registries keep for the public (co.id, com.my, ac.th...). Without
# them, every name under such a suffix would look like one domain.
GENERIC_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "gob", "mil", "nom", "or", "ne", "go",
                        "sch", "ltd", "plc"}
# Hosting platforms that hand out free subdomains, as the Public Suffix List's private section has them, and who
# runs each. Every subdomain belongs to whoever made it, so it is the registrable name: correos-es.pages.dev is
# not pages.dev. Nobody registers it at a registry either, so its abuse report goes to the platform.
PLATFORMS = {
    "pages.dev": "Cloudflare Pages", "workers.dev": "Cloudflare Workers", "r2.dev": "Cloudflare R2",
    "web.app": "Google Firebase", "firebaseapp.com": "Google Firebase", "appspot.com": "Google App Engine",
    "blogspot.com": "Google Blogger", "github.io": "GitHub Pages", "vercel.app": "Vercel",
    "netlify.app": "Netlify", "herokuapp.com": "Heroku", "glitch.me": "Glitch", "onrender.com": "Render",
    "azurewebsites.net": "Microsoft Azure", "weebly.com": "Weebly", "wixsite.com": "Wix", "webflow.io": "Webflow",
    "myshopify.com": "Shopify", "surge.sh": "Surge", "repl.co": "Replit", "ngrok-free.app": "ngrok",
    "duckdns.org": "Duck DNS",
}
# Link shorteners: the host says nothing about the campaign, the page it leads to does.
SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "cutt.ly", "rebrand.ly", "ow.ly",
    "buff.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "bit.do", "lnkd.in", "shorte.st", "qrco.de",
}


def platform(name: str) -> str | None:
    """The hosting platform's suffix when `name` is one of its subdomains (pages.dev), else None."""
    parts = name.strip(".").lower().split(".")
    suffix = ".".join(parts[-2:])
    return suffix if len(parts) >= 3 and suffix in PLATFORMS else None


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def registrable(name: str) -> str:
    """Registrable domain of a host name (approximate public-suffix handling)."""
    parts = name.strip(".").lower().split(".")
    if len(parts) >= 3 and (".".join(parts[-2:]) in TWO_LABEL_SUFFIXES or ".".join(parts[-2:]) in PLATFORMS
                            or (len(parts[-1]) == 2 and parts[-2] in GENERIC_SECOND_LEVEL)):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

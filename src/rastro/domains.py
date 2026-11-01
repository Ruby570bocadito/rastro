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
# Where each platform takes abuse reports: its own form, each checked by hand on 2026-11-01. Platforms whose form
# could not be confirmed have none, rather than a guess.
ABUSE_FORMS = {
    "pages.dev": "https://abuse.cloudflare.com/", "workers.dev": "https://abuse.cloudflare.com/",
    "r2.dev": "https://abuse.cloudflare.com/",
    "appspot.com": "https://support.google.com/code/contact/cloud_platform_report",
    "blogspot.com": "https://support.google.com/blogger/answer/76315",
    "github.io": "https://github.com/contact/report-abuse", "vercel.app": "https://vercel.com/abuse",
    "azurewebsites.net": "https://msrc.microsoft.com/report/abuse",
    "myshopify.com": "https://www.shopify.com/legal/tools/report-an-issue", "ngrok-free.app": "https://ngrok.com/abuse",
    "wixsite.com": "https://www.wix.com/abuse", "weebly.com": "https://www.weebly.com/abuse",
}
# Platforms that answer DNS for any name, even one nobody made (checked on 2026-11-01 with random names through the
# public resolver). On them an address says nothing: a site taken down still resolves, and every site shares the
# platform's addresses. Only the others (pages.dev, workers.dev, azurewebsites.net, duckdns.org, repl.co) answer
# NXDOMAIN once a site is gone.
WILDCARD_DNS = {
    "appspot.com", "blogspot.com", "firebaseapp.com", "github.io", "glitch.me", "herokuapp.com", "myshopify.com",
    "netlify.app", "ngrok-free.app", "onrender.com", "r2.dev", "surge.sh", "vercel.app", "web.app", "webflow.io",
    "weebly.com", "wixsite.com",
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


def host_label(name: str) -> str | None:
    """Who to warn about a platform subdomain, as Rastro names it (Cloudflare Pages (pages.dev)), else None."""
    suffix = platform(name)
    return f"{PLATFORMS[suffix]} ({suffix})" if suffix else None


def dns_hides_takedown(name: str) -> bool:
    """Whether `name` sits on a platform that answers DNS for any name, so DNS cannot tell if it is still up."""
    return platform(name) in WILDCARD_DNS


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

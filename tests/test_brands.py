from rastro import brands
from rastro.domains import is_ip, platform, registrable


def test_brands_spelled_out_still_match_as_before():
    assert brands.brand_of("correos-envio-4821.top") == "correos"
    assert brands.brand_of("my-dhl-parcel.top") == "dhl"
    assert brands.brand_of("dhlexpress.top") is None                  # short brands need a whole token
    assert brands.brand_of("modern-internet.com") is None


def test_lookalike_spellings_name_the_brand_they_imitate():
    assert brands.brand_of("paypa1-secure.top") == "paypal"            # a one for an l
    assert brands.brand_of("1cloud-find.top") == "icloud"              # a one for an i
    assert brands.brand_of("5team-gift.top") == "steam"
    assert brands.brand_of("arnazon-verify.xyz") == "amazon"           # rn for m
    assert brands.brand_of("vvhatsapp-group.top") == "whatsapp"        # vv for w
    assert brands.brand_of("xn--pypal-4ve.com") == "paypal"            # Cyrillic а, as punycode
    assert brands.brand_of("xn--cinbase-9ig.com") == "coinbase"        # Cyrillic о


def test_numbers_are_not_read_as_letters():
    assert brands.brand_of("shop-app1369.com") is None
    assert brands.brand_of("blog-app13.top") is None
    assert brands.brand_of("2024-report.top") is None


def test_hosting_platforms_are_public_suffixes():
    assert registrable("www.correos-es.pages.dev") == "correos-es.pages.dev"
    assert registrable("santander.web.app") == "santander.web.app"
    assert registrable("pages.dev") == "pages.dev"
    assert platform("correos-es.pages.dev") == "pages.dev"
    assert platform("pages.dev") is None and platform("correos-es.top") is None
    assert brands.brand_of("correos-es.pages.dev") == "correos"
    assert brands.suspicious("my-blog.github.io")


def test_addresses_are_told_from_names():
    assert is_ip("192.0.2.4") and is_ip("[2001:db8::1]")
    assert not is_ip("192.0.2.4.example.com")

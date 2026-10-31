from rastro import pattern

CAMPAIGN = [
    "paqexpres-entrega-4821.top", "paqexpres-envio-3318.top", "paqexpres-aduana-1180.icu",
    "paqexpres-pago-7710.xyz", "paqexpres-seguimiento-2093.top", "paqexpres-entrega-5541.icu",
    "paqexpres-envio-8802.xyz", "paqexpres-aduana-6627.top", "paqexpres-pago-3019.icu",
    "paqexpres-seguimiento-4410.xyz",
]


def test_shape_describes_the_token_layout():
    assert pattern.shape("paqexpres-aduana-7093.icu") == "a-a-9.a"
    assert pattern.shape("apple1d-login.com") == "a9a-a.a"


def test_learns_a_readable_template():
    (p,) = pattern.learn(CAMPAIGN)
    assert p.regex == r"paqexpres-(aduana|entrega|envio|pago|seguimiento)-\d{4}\.(icu|top|xyz)"
    assert p.support == 10


def test_catches_the_next_domain_and_rejects_lookalikes():
    patterns = pattern.learn(CAMPAIGN)
    assert pattern.first_match(patterns, "paqexpres-aduana-7093.icu")
    for decoy in [
        "paqexpress-entrega-4821.top",     # two s
        "paqexpres-entrega.top",           # no digits
        "paqexpres-aduana-7093.com",       # TLD they never use
        "paqexpres-envio-12345.top",       # five digits
        "mi-paqexpres-pago-2201.xyz",      # prefix
        "paqexpres-recogida-5512.icu",     # word outside their vocabulary
    ]:
        assert pattern.first_match(patterns, decoy) is None, decoy


def test_random_looking_words_become_a_class():
    names = ["secure-qwhzk.top", "secure-plmzaq.top", "secure-vbtrex.top", "secure-yuiop.top"]
    (p,) = pattern.learn(names)
    assert p.regex == r"secure-[a-z]{5,6}\.top"
    assert p.matches("secure-abcde.top")


def test_a_shared_core_stays_literal():
    names = ["accountappleid.com", "secureappleverify.com", "myapplecenter.com", "loginapple.com"]
    (p,) = pattern.learn(names)
    assert p.regex == r"[a-z]{2,7}apple[a-z]{0,6}\.com"
    assert p.matches("helpappleid.com")
    assert not p.matches("accountgoogleid.com")


def test_a_core_that_moves_between_slots_is_required_anywhere():
    names = ["apple-login.com", "my-apple.com", "appleid-help.com", "secure-applecare.com"]
    (p,) = pattern.learn(names)
    assert p.regex.startswith(r"(?=.*apple)")
    assert p.matches("verify-apple.com")
    assert not p.matches("google-login.com")


def test_breadth_counts_the_names_a_pattern_can_match():
    (p,) = pattern.learn(CAMPAIGN)
    # 5 words x 10^4 numbers x 3 TLDs = 150,000 names
    assert abs(p.breadth_log10 - 5.176) < 0.01


def test_layouts_seen_once_are_not_generalised():
    assert pattern.learn(["one-off-name.top"]) == []

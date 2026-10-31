import random
from datetime import UTC, datetime

import pytest

from rastro import husmo, investigate, scorer, watch
from rastro.__main__ import main
from rastro.domains import registrable
from rastro.sources.ctlog import Entry


def toy_model() -> scorer.Model:
    rng = random.Random(1)
    lookalikes = [f"{rng.choice(['paypal', 'amazon', 'correos'])}-{rng.choice(['verify', 'login', 'envio'])}-"
                  f"{rng.randint(100, 9999)}.{rng.choice(['top', 'xyz'])}" for _ in range(600)]
    ordinary = [f"{rng.choice(['bakery', 'garden', 'studio', 'lake'])}{rng.choice(['', 'shop', 'home'])}"
                f".{rng.choice(['com', 'de', 'org'])}" for _ in range(600)]
    return scorer.train(lookalikes, ordinary, epochs=3)


def test_registrable_knows_country_second_levels():
    assert registrable("shop.example.co.id") == "example.co.id"
    assert registrable("a.b.com.my") == "b.com.my"
    assert registrable("mail.web.de") == "web.de"            # a real domain, not a public suffix
    assert registrable("login.paypal.com") == "paypal.com"


def test_features_read_the_brand_the_words_and_the_shape():
    f = scorer.features("paypal-verify-4821.top")
    assert {"tld:top", "brand:paypal", "brand+more", "w:verify", "digits:3-4", "hyphens:1-2",
            "digits+hyphens"} <= set(f)
    assert "g:^pay" in f and "punycode" in scorer.features("xn--pypal-4ve.com")


def test_the_model_separates_and_explains():
    m = toy_model()
    assert m.score("paypal-secure-7741.top") > 0.9 > 0.1 > m.score("lakehome.com")
    kinds = {k for k, _, _ in m.reasons("paypal-secure-7741.top")}
    assert kinds and kinds <= {"g", "w", "tld", "brand", "brand+more", "digits", "hyphens", "digits+hyphens", "length"}
    assert husmo.reason("brand", "paypal") == "the brand PayPal"
    assert husmo.reason("tld", "top", "es") == "la terminación .top"


def test_a_saved_model_scores_the_same(tmp_path):
    m = toy_model()
    path = tmp_path / "scorer.bin"
    scorer.save(m, path)
    back = scorer.loads(path.read_bytes())
    for d in ("paypal-secure-7741.top", "lakehome.com", "amazon-envio-12.xyz"):
        assert back.score(d) == pytest.approx(m.score(d), abs=0.02)
    with pytest.raises(ValueError):
        scorer.loads(b'{"format": "something-else"}\n')


def test_the_watcher_keeps_and_alerts_on_high_scores():
    w = watch.Watcher("test", model=toy_model(), keep_score=0.9, alert_score=0.95)
    t = datetime(2026, 10, 31, 9, 0, tzinfo=UTC)
    entries = [Entry(1, t, False, ("lakehome.com",), "CA"), Entry(2, t, False, ("correos-envio-5521.top",), "CA"),
               Entry(3, t, False, ("paypal.com",), "CA")]
    (alert,) = w.handle(entries)
    assert alert.domain == "correos-envio-5521.top" and alert.score > 0.95 and "scores" in alert.line()
    assert [e.index for e in w.keep(entries)] == [2]


def test_the_investigation_carries_the_seed_score_into_the_narration():
    inv = investigate.investigate("paypal-secure-7741.top", investigate.Sources(), sims=0, model=toy_model())
    assert inv.name_score > 0.9 and inv.name_reasons
    lines = [text for _, text in husmo.narrate(inv, "es")]
    assert any(text.startswith("Solo por su nombre, mi modelo le da un 0.99 sobre 1") for text in lines)


def test_no_name_model_is_shipped_and_the_command_says_why(capsys):
    assert scorer.default() is None
    assert main(["score", "lakehome.com"]) == 1
    assert "experiment 07" in capsys.readouterr().out


def test_score_command_ranks_names_with_a_trained_model(tmp_path, capsys):
    path = tmp_path / "model.bin"
    scorer.save(toy_model(), path)
    assert main(["score", "lakehome.com", "hxxps://paypal-secure-7741[.]top/x", "not a domain",
                 "--name-model", str(path)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].endswith(")") and "paypal-secure-7741.top" in out[0]
    assert "lakehome.com" in out[1] and out[-1] == "1 lines were not domain names"

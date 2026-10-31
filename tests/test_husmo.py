import re

from rastro import husmo, investigate, report


def test_learned_patterns_are_said_in_words():
    assert husmo.spoken_pattern(r"paqexpres-(aduana|entrega|envio|pago)-\d{4}\.test", "es") == (
        "paqexpres guion aduana, entrega, envio o pago guion 4 cifras punto test")
    assert husmo.spoken_pattern(r"\d{4,8}-coinbase\.com", "en") == "4 to 8 digits dash coinbase dot com"
    assert husmo.spoken_pattern(r"(?=.*microsofterrorfound)[a-z0-9.-]+\.ph", "en") == (
        "any name with microsofterrorfound in it dot ph")
    assert husmo.spoken_pattern(r"secure-[a-z]{5,6}\.top", "es") == "secure guion de 5 a 6 letras punto top"


def test_lines_are_rewritten_for_a_voice():
    said = husmo.spoken(r"Su nombre sigue una plantilla: \d{4,8}-coinbase\.com. Lo más probable, UTC−7; "
                        "test de ritmo p = 0.0002, unos 10^4.6 nombres.", "es")
    assert said == ("Su nombre sigue una plantilla: de 4 a 8 cifras guion coinbase punto com. Lo más probable, "
                    "UTC menos 7; test de ritmo p igual a 0,0002, unos 10 elevado a 4,6 nombres.")
    assert husmo.spoken("Seen at 203.0.113.7, UTC+3, p < 0.0001.", "en") == (
        "Seen at 203.0.113.7, UTC plus 3, p below 0.0001.")


def test_the_case_file_speaks_with_offline_voices_only():
    inv = investigate.investigate("paqexpres-entrega-4821.top", investigate.Sources(), sims=0)
    data = report.case_data(inv, "es")
    line = next(n for n in data["narration"] if "\\d{4}" in n["text"])
    assert "4 cifras" in line["speech"] and "\\d" not in line["speech"]
    page = report.render(inv, "es")
    assert 'id="listen"' in page and all(f'id="m-{k}"' in page for k in ("rest", "M", "S", "E", "A", "O"))
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    assert "v.localService" in script          # a cloud voice would send the case's text to an outside service

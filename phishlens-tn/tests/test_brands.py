"""Brand detection and typosquatting."""
from __future__ import annotations

import pytest

from analyzer.brands import BrandDataError, analyze_brands, is_transposition, label_contains_token, levenshtein, load_brands, visual_skeleton


def analyze(host, **kwargs):
    return analyze_brands(hosts=[host], final_host=host, **kwargs)


def test_brand_list_covers_required_brands_and_official_domains():
    brands = {b.name: b for b in load_brands()}
    required = ["BIAT", "STB", "BNA", "Attijari Bank", "Amen Bank", "ATB", "UIB", "Banque Zitouna", "La Poste Tunisienne",
                "Tunisie Telecom", "Ooredoo Tunisie", "Orange Tunisie", "D17", "Clictopay", "Paymee"]
    assert all(name in brands for name in required)
    assert "biat.com.tn" in brands["BIAT"].official_domains and "uib.com.tn" in brands["UIB"].official_domains


def test_bad_brand_file(tmp_path):
    bad = tmp_path / "brands.json"
    bad.write_text('{"brands": [{"id": "x"}]}')
    with pytest.raises(BrandDataError):
        load_brands(bad)


@pytest.mark.parametrize("host", ["biat.com.tn", "www.biat.com.tn", "webbanking.biat.com.tn", "attijaribank.com.tn", "ooredoo.tn"])
def test_official_domains_are_never_flagged(host):
    result = analyze(host, title="BIAT Connexion", text="BIAT BIAT BIAT")
    assert result.official_brand and not result.hits and not result.typosquats and not result.embedded_official


@pytest.mark.parametrize("host,brand,technique", [
    ("biatt.com.tn", "BIAT", "repeated-letter"),
    ("b1at.com.tn", "BIAT", "character-swap"),
    ("amenbnak.com", "Amen Bank", "transposition"),
    ("amenbanc.com", "Amen Bank", "edit-distance"),
    ("arnenbank.com", "Amen Bank", "character-swap"),
    ("attijar1bank.com", "Attijari Bank", "character-swap"),
    ("ooredo0.tn", "Ooredoo Tunisie", "character-swap"),
    ("tunisietelecom.com", "Tunisie Telecom", "tld-swap"),
    ("clictopay.net", "Clictopay", "tld-swap"),
    ("paymeee.tn", "Paymee", "repeated-letter"),
])
def test_typosquats_are_detected(host, brand, technique):
    result = analyze(host)
    assert any(t.brand == brand and t.technique == technique for t in result.typosquats), result.typosquats
    assert brand in result.targeted_brands


@pytest.mark.parametrize("host", ["example.com", "boat.com", "orange.com", "atb.com", "stb.com", "postes.tn", "unrelated-bank.com"])
def test_unrelated_domains_are_not_flagged(host):
    result = analyze(host)
    assert not result.typosquats and not result.hits and not result.embedded_official


def test_official_domain_embedded_in_longer_host():
    result = analyze("biat.com.tn.secure-check.example.net")
    assert result.embedded_official and result.embedded_official[0].official_domain == "biat.com.tn"


def test_brand_in_subdomain_and_domain():
    sub = analyze("biat.secure-login.example.com")
    assert [h.location for h in sub.hits] == ["subdomain"]
    dom = analyze("secure-biat-login.com")
    assert [h.location for h in dom.hits] == ["domain"]
    assert analyze("biat24.example.org").hits  # glued to digits


def test_homoglyph_host_is_folded_before_matching():
    spoof = "b\u0456at.com.tn".encode("idna").decode("ascii")  # Cyrillic i inside biat.com.tn
    result = analyze(spoof)
    assert spoof.startswith("xn--") and not result.official_brand
    assert [(t.brand, t.technique) for t in result.typosquats] == [("BIAT", "homoglyph")]
    assert analyze("xn--invalid-").typosquats == []  # malformed punycode must not crash


def test_typosquat_in_subdomain_of_a_shared_domain():
    result = analyze("biatt-login.example.com")
    assert result.typosquats and result.typosquats[0].fragment == "biatt" and result.typosquats[0].candidate == "biatt-login.example.com"


def test_title_text_and_assets_on_unofficial_site():
    result = analyze_brands(
        hosts=["evil.example.com"], final_host="evil.example.com", title="BIAT - Connexion",
        text="Bienvenue BIAT. La BIAT vous protege. Attijari aussi.",
        external_domains={"images": {"biat.com.tn": 3}}, favicon_domain="attijaribank.com.tn", paths=["/biat/login"],
    )
    locations = {(h.brand, h.location) for h in result.hits}
    assert ("BIAT", "title") in locations and ("BIAT", "text") in locations and ("BIAT", "asset") in locations
    assert ("Attijari Bank", "asset") in locations and ("BIAT", "path") in locations
    assert next(h for h in result.hits if h.brand == "BIAT" and h.location == "text").count == 2


def test_accents_and_acronym_case():
    result = analyze_brands(hosts=["x.example.com"], final_host="x.example.com", title="Tunisie Télécom - Recharge", text="la biat est un mot minuscule")
    assert any(h.brand == "Tunisie Telecom" and h.location == "title" for h in result.hits)
    assert not any(h.brand == "BIAT" for h in result.hits)  # lowercase 'biat' is not the acronym


def test_text_is_ignored_on_official_sites():
    result = analyze_brands(hosts=["www.stb.com.tn"], final_host="www.stb.com.tn", title="BIAT", text="BIAT BIAT")
    assert result.official_brand == "STB" and not result.hits


def test_helpers():
    assert levenshtein("kitten", "sitting") == 3 and levenshtein("", "abc") == 3 and levenshtein("a", "a") == 0
    assert is_transposition("amenbnak", "amenbank") and not is_transposition("abc", "abc")
    assert visual_skeleton("b1at") == visual_skeleton("biat") and visual_skeleton("arnen") == visual_skeleton("amen")
    assert label_contains_token("secure-stb-login", "stb") and not label_contains_token("substance", "stb")
    assert label_contains_token("attijaribanklogin", "attijari")

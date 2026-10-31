"""Scoring engine, rules and the offline end-to-end pipeline."""
from __future__ import annotations

import json

import pytest

from analyzer.scoring import Evidence, Hit, Rule, get_rules, level_for, score, severity_for
from analyzer.tls import TLSInfo

from conftest import fixture_text, good_tls

PHISH_URL = "https://biatt-login.example.com/connexion"


def ids(result):
    return {s["id"] for s in result["signals"]}


@pytest.mark.parametrize("value,level", [(0, "Low"), (24, "Low"), (25, "Medium"), (49, "Medium"), (50, "High"), (74, "High"), (75, "Critical"), (100, "Critical")])
def test_level_boundaries(value, level):
    assert level_for(value) == level


def test_severity_buckets():
    assert [severity_for(w) for w in (-5, 4, 12, 25, 38)] == ["positive", "low", "medium", "high", "critical"]


def test_rule_ids_are_unique_and_documented():
    rules = get_rules()
    assert len({r.id for r in rules}) == len(rules) >= 40
    assert all(r.description and r.title and r.icon for r in rules)


def test_phishing_fixture_is_critical_with_explanations(run_offline):
    result = run_offline(PHISH_URL, fixture_text("phishing_bank_login.html"))
    assert result["level"] == "Critical" and result["score"] >= 75
    assert {"typosquatting", "form_posts_external", "brand_in_title", "card_data_requested", "exfil_service",
            "brand_credential_combo", "brand_assets_hotlinked", "obfuscated_javascript", "suspicious_iframe"} <= ids(result)
    assert all(s["explanation"] and isinstance(s["weight"], int) for s in result["signals"])
    weights = [s["weight"] for s in result["signals"]]
    assert weights == sorted(weights, reverse=True)
    assert "BIAT" in result["verdict"] and result["brands"]["targeted_brands"][0] == "BIAT"
    json.dumps(result)  # fully serialisable


def test_benign_page_scores_zero(run_offline):
    result = run_offline("https://www.example.com/", fixture_text("benign_page.html"))
    assert result["score"] == 0 and result["level"] == "Low" and result["signals"] == []
    assert result["verdict"].startswith("Low risk")


def test_official_login_page_stays_low(run_offline):
    html = fixture_text("legit_login.html").replace("Espace client", "BIAT Espace client")
    result = run_offline("https://www.biat.com.tn/login", html)
    assert result["level"] == "Low" and "official_domain" in ids(result)
    assert "brand_in_title" not in ids(result) and "typosquatting" not in ids(result)


def test_generic_login_on_own_domain_is_only_mildly_suspicious(run_offline):
    result = run_offline("https://shop.example.com/login", fixture_text("legit_login.html"))
    assert ids(result) == {"login_form_present", "suspicious_path_keywords"} and result["level"] == "Low"


def test_embedded_official_domain_is_flagged(run_offline):
    result = run_offline("https://biat.com.tn.verify-account.example.net/", fixture_text("benign_page.html"))
    assert "official_domain_embedded" in ids(result) and result["score"] >= 40


def test_redirect_chain_across_domains(run_offline):
    chain = ["http://short.example.net/a", "https://hop.example.org/b", "https://landing.example.com/c"]
    result = run_offline(chain[0], fixture_text("benign_page.html"), chain=chain)
    assert "cross_domain_redirects" in ids(result) and result["fetch"]["redirect_count"] == 2


def test_certificate_rules(run_offline):
    bad = good_tls("www.example.com", trusted=False, verification_error="self-signed certificate", self_signed=True)
    assert "cert_not_trusted" in ids(run_offline("https://www.example.com/", fixture_text("benign_page.html"), tls=bad))
    mismatch = good_tls("www.example.com", trusted=False, matches_domain=False, san=["other.example.net"])
    result = run_offline("https://www.example.com/", fixture_text("benign_page.html"), tls=mismatch)
    assert "cert_hostname_mismatch" in ids(result) and "cert_not_trusted" not in ids(result)
    fresh = good_tls("www.example.com", age_days=2)
    assert "cert_recent" in ids(run_offline("https://www.example.com/", fixture_text("benign_page.html"), tls=fresh))


def test_http_page_with_password_form(run_offline):
    result = run_offline("http://shop.example.com/login", fixture_text("legit_login.html"))
    assert {"no_https", "credentials_over_http"} <= ids(result)


def build_evidence(monkeypatch, fake_dns):
    from analyzer import pipeline
    from analyzer.brands import analyze_brands
    from analyzer.domain import analyze_domain, analyze_url_features
    from analyzer.netsafe import parse_target
    from analyzer.parser import parse_html

    from conftest import make_fetch

    url = "https://shop.example.com/login"
    target = parse_target(url)
    html = fixture_text("legit_login.html")
    page = parse_html(html, url)
    domain = analyze_domain(target.host, use_rdap=False)
    features = analyze_url_features(target)
    brands = analyze_brands(hosts=[target.host], final_host=target.host, title=page.title, text=page.visible_text)
    return Evidence(target, target, make_fetch(url, html), page, good_tls(target.host), domain, domain, features, features, brands)


def test_engine_sums_weights_clamps_and_supports_custom_rules(monkeypatch, fake_dns):
    evidence = build_evidence(monkeypatch, fake_dns)
    big = Rule("big", "Big", 80, "url", "alert", "d", lambda ev: Hit("one"))
    huge = Rule("huge", "Huge", 80, "url", "alert", "d", lambda ev: Hit("two"))
    result = score(evidence, [big, huge])
    assert result.raw_score == 160 and result.score == 100 and result.level == "Critical"
    mitigation = Rule("good", "Good", -30, "trust", "check", "d", lambda ev: Hit("fine"))
    low = score(evidence, [Rule("a", "A", 10, "url", "alert", "d", lambda ev: Hit("x")), mitigation])
    assert low.raw_score == -20 and low.score == 0  # never below zero
    assert [s.severity for s in low.signals] == ["medium", "positive"]


def test_weight_override_and_rule_isolation(monkeypatch, fake_dns):
    evidence = build_evidence(monkeypatch, fake_dns)

    def broken(ev):
        raise RuntimeError("boom")

    rules = [
        Rule("broken", "Broken", 50, "url", "alert", "d", broken),
        Rule("silent", "Silent", 50, "url", "alert", "d", lambda ev: None),
        Rule("var", "Variable", 5, "url", "alert", "d", lambda ev: Hit("v", weight=22)),
    ]
    result = score(evidence, rules)
    assert [s.id for s in result.signals] == ["var"] and result.signals[0].weight == 22
    assert result.rule_errors == ["broken: RuntimeError"]


def test_new_domain_weights(monkeypatch, fake_dns):
    from analyzer.domain import RdapInfo
    from analyzer.rules import new_domain

    evidence = build_evidence(monkeypatch, fake_dns)
    for age, expected in ((5, 25), (45, 15), (120, 6)):
        evidence.domain.rdap = RdapInfo(available=True, age_days=age)
        assert new_domain(evidence).weight == expected
    evidence.domain.rdap = RdapInfo(available=True, age_days=400)
    assert new_domain(evidence) is None
    evidence.domain.rdap = RdapInfo(error="unavailable")
    assert new_domain(evidence) is None  # fails gracefully, no penalty

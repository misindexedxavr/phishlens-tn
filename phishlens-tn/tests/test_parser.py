"""Form extraction and page parsing, using static HTML fixtures."""
from __future__ import annotations

from analyzer.parser import classify_field, parse_html

from conftest import fixture_text

PAGE_URL = "https://biat-secure-login.example.com/index.html"


def phishing_page():
    return parse_html(fixture_text("phishing_bank_login.html"), PAGE_URL)


def test_extracts_all_forms_with_actions_and_methods():
    page = phishing_page()
    assert len(page.forms) == 2
    login, search = page.forms
    assert login.method == "post" and login.resolved_action == "https://collect.example.org/post.php"
    assert login.action_domain == "example.org" and login.external_action
    assert search.method == "get" and search.resolved_action == "https://biat-secure-login.example.com/search"
    assert not search.external_action


def test_login_form_inputs_and_sensitive_fields():
    login = phishing_page().forms[0]
    assert login.has_password and login.hidden_count == 1
    assert login.input_types == {"text": 3, "password": 1, "hidden": 1}
    assert {"password", "card", "otp", "username"} <= set(login.sensitive_fields)
    assert login.has_credentials and login.submit_labels == ["Se connecter"]
    named = {i.name: i for i in login.inputs}
    assert named["mot_de_passe"].type == "password" and "password" in named["mot_de_passe"].sensitive
    assert named["cvv"].sensitive == ["card"]


def test_empty_action_posts_to_the_page_itself():
    page = parse_html('<form method="post"><input type="password" name="p"></form>', PAGE_URL)
    assert page.forms[0].resolved_action == PAGE_URL and not page.forms[0].external_action


def test_relative_action_and_base_tag():
    html = '<base href="https://cdn.example.net/app/"><form action="submit.php"><input name="x"></form><a href="y.html">y</a>'
    page = parse_html(html, PAGE_URL)
    assert page.base_href == "https://cdn.example.net/app/"
    assert page.forms[0].resolved_action == "https://cdn.example.net/app/submit.php"


def test_mailto_and_javascript_actions_are_flagged_not_followed():
    page = parse_html('<form action="mailto:x@example.org"><input name="a"></form><form action="javascript:go()"></form>', PAGE_URL)
    assert [f.action_scheme for f in page.forms] == ["mailto", "javascript"]
    assert all(not f.external_action for f in page.forms)


def test_title_favicon_and_external_domains():
    page = phishing_page()
    assert page.title == "BIAT - Espace client | Connexion"
    assert page.favicon_domain == "biat.com.tn" and page.favicon_external and page.favicon_source == "link"
    assert page.external_domains["images"] == {"biat.com.tn": 1}
    assert page.external_domains["forms"] == {"example.org": 1}
    domains = {e["domain"]: e for e in page.external_summary}
    assert {"biat.com.tn", "example.org"} <= set(domains)
    assert "favicon" in domains["biat.com.tn"]["categories"]


def test_iframes_and_meta_refresh():
    page = phishing_page()
    assert len(page.iframes) == 1 and page.iframes[0].hidden and page.iframes[0].external
    assert page.meta_refresh and page.meta_refresh.external and page.meta_refresh.delay == 300
    assert page.meta_refresh.domain == "example.org"


def test_script_indicators_are_read_statically():
    page = phishing_page()
    assert {"eval", "atob"} <= set(page.script_indicators)
    assert page.exfil_endpoints == ["Telegram bot API"]
    assert page.right_click_disabled and page.js_redirect == "https://elsewhere.example.net/landing"
    assert page.noindex


def test_default_favicon_when_none_declared():
    page = parse_html(fixture_text("legit_login.html"), "https://shop.example.com/login")
    assert page.favicon_url == "https://shop.example.com/favicon.ico" and not page.favicon_external


def test_legit_login_form_is_internal_and_not_exfiltrating():
    page = parse_html(fixture_text("legit_login.html"), "https://shop.example.com/login")
    form = page.forms[0]
    assert form.has_password and not form.external_action and form.hidden_count == 1
    assert page.exfil_endpoints == [] and page.script_indicators == []


def test_password_field_outside_a_form_is_counted():
    page = parse_html('<input type="password" name="p"><form><input name="q"></form>', PAGE_URL)
    assert page.password_field_count == 1 and page.orphan_password_inputs == 1 and page.has_login_form


def test_non_html_and_empty_bodies_do_not_crash():
    assert parse_html(b"", PAGE_URL).notes
    page = parse_html(b"\x00\x01\x02 plain bytes", PAGE_URL)
    assert not page.is_html and page.forms == []


def test_visible_text_excludes_scripts_and_is_not_exported():
    page = phishing_page()
    assert "eval(" not in page.visible_text and "Bienvenue" in page.visible_text
    assert "visible_text" not in page.to_dict()


def test_classify_field():
    assert classify_field("password", "x") == ["password"]
    assert "card" in classify_field("text", "card_number")
    assert "otp" in classify_field("text", "code_sms")
    assert "pin" in classify_field("text", "user_pin")
    assert "identity" in classify_field("text", "rib")
    assert classify_field("hidden", "csrf_token") == []

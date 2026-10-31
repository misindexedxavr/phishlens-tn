"""Certificate parsing (static PEM fixture) and host-name matching."""
from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

import pytest

from analyzer.tls import DerError, TLSInfo, describe_certificate, hostname_matches, inspect_tls, parse_certificate

from conftest import FIXTURES


@pytest.fixture(scope="module")
def der() -> bytes:
    return ssl.PEM_cert_to_DER_cert((FIXTURES / "test_cert.pem").read_text())


def test_parses_issuer_subject_and_san(der):
    cert = parse_certificate(der)
    assert cert["subject"]["CN"] == ["test.example.org"] and cert["subject"]["O"] == ["PhishLens Test"]
    assert cert["issuer"] == cert["subject"]
    assert cert["dns_names"] == ["test.example.org", "*.example.net"] and cert["ip_names"] == ["203.0.113.7"]


def test_describe_certificate_dates_and_flags(der):
    cert = parse_certificate(der)
    now = cert["not_before"] + timedelta(days=10)
    info = describe_certificate(der, "test.example.org", now)
    assert info.available and info.age_days == 10 and info.self_signed and info.matches_domain
    assert info.validity_days >= 3600 and not info.expired and info.days_until_expiry == info.validity_days - 10
    assert info.issuer == "O=PhishLens Test, CN=test.example.org" and len(info.sha256) == 64
    assert "IP:203.0.113.7" in info.san
    expired = describe_certificate(der, "test.example.org", cert["not_after"] + timedelta(days=1))
    assert expired.expired and expired.days_until_expiry < 0
    early = describe_certificate(der, "test.example.org", cert["not_before"] - timedelta(days=1))
    assert early.not_yet_valid


def test_hostname_matching_rules(der):
    cert = parse_certificate(der)
    dns, ips = cert["dns_names"], cert["ip_names"]
    assert hostname_matches("test.example.org", dns, ips, None)
    assert hostname_matches("a.example.net", dns, ips, None)  # single-label wildcard
    assert not hostname_matches("example.net", dns, ips, None)  # wildcard does not cover the apex
    assert not hostname_matches("a.b.example.net", dns, ips, None)  # nor two labels
    assert not hostname_matches("evil.example.org", dns, ips, None)
    assert hostname_matches("203.0.113.7", dns, ips, None) and not hostname_matches("203.0.113.8", dns, ips, None)
    assert hostname_matches("only-cn.example.com", [], [], "only-cn.example.com")  # CN only when there is no SAN
    assert not hostname_matches("x.com", ["*.com"], [], None)  # no wildcards on a bare TLD


def test_mismatch_is_reported(der):
    info = describe_certificate(der, "login.biat.example.com", datetime.now(timezone.utc))
    assert info.matches_domain is False


def test_garbage_is_rejected_cleanly():
    with pytest.raises(DerError):
        parse_certificate(b"not a certificate")


def test_inspect_tls_never_raises_on_blocked_host(monkeypatch):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    info = inspect_tls("rebind.example", 443)
    assert isinstance(info, TLSInfo) and not info.available and "private or internal" in info.error


def test_not_applicable():
    info = TLSInfo.not_applicable("a.example", 80, "not https")
    assert not info.applicable and not info.available

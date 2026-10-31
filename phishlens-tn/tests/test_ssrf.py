"""SSRF protection: URL validation, IP policy, DNS answers, redirects and the connection guard."""
from __future__ import annotations

import socket

import pytest
import requests

from analyzer import netsafe
from analyzer.errors import BlockedAddressError, HostResolutionError, InvalidURLError, TooManyRedirectsError
from analyzer.fetcher import fetch
from analyzer.netsafe import check_url, is_blocked_ip, parse_target, resolve_host

from conftest import PUBLIC_IP


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.1.2.3", "10.0.0.1", "172.16.5.4", "192.168.1.10", "169.254.169.254", "0.0.0.0",
    "100.64.0.1", "224.0.0.1", "240.0.0.1", "::1", "fe80::1", "fc00::1", "::", "::ffff:127.0.0.1",
    "2002:7f00:1::", "64:ff9b::7f00:1", "::7f00:1",
])
def test_blocks_non_public_addresses(ip):
    assert is_blocked_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_allows_public_addresses(ip):
    assert not is_blocked_ip(ip)


@pytest.mark.parametrize("bad", [
    "", "   ", "javascript:alert(1)", "file:///etc/passwd", "ftp://example.com", "gopher://example.com",
    "data:text/html,hi", "mailto:a@b.com", "http://", "http://exa mple.com", "http://example.com:99999",
    "http://example.com:abc", "http://a\\@b.com", "http://[::1", "http://..", "x" * 3000,
])
def test_rejects_invalid_urls(bad):
    with pytest.raises(InvalidURLError):
        parse_target(bad)


@pytest.mark.parametrize("name", ["http://localhost/", "http://LOCALHOST:8080", "http://foo.localhost", "http://db.internal/", "http://printer.local/", "http://x.home.arpa"])
def test_rejects_local_names(name):
    with pytest.raises(BlockedAddressError):
        parse_target(name)


def test_normalises_scheme_credentials_and_fragment():
    target = parse_target("example.com/login#frag")
    assert target.url == "http://example.com/login" and target.scheme == "http"
    spoof = parse_target("https://biat.com.tn@evil.example.org/x")
    assert spoof.host == "evil.example.org" and spoof.has_userinfo and "@" not in spoof.url


def test_ip_literals_are_resolved_and_blocked():
    for url in ("http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/", "http://2130706433/"):
        with pytest.raises(BlockedAddressError):
            check_url(url)


def test_dns_answer_with_private_record_is_blocked(monkeypatch):
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 80)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(BlockedAddressError):
        resolve_host("rebind.example", 80)


def test_unresolvable_host(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(HostResolutionError):
        resolve_host("does-not-exist.example", 80)


def test_connection_guard_refuses_private_address_before_connecting(monkeypatch):
    """DNS rebinding defence: even if pre-flight passed, connect-time resolution is validated again."""
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))])

    def no_sockets(*a, **k):
        raise AssertionError("a socket must not be created for a blocked address")

    monkeypatch.setattr(netsafe.socket, "socket", no_sockets)
    with pytest.raises(BlockedAddressError):
        netsafe.guarded_create_connection(("rebind.example", 80), 1.0)


def test_guard_is_installed_in_urllib3():
    from urllib3.util import connection

    netsafe.install_connection_guard()
    assert connection.create_connection is netsafe.guarded_create_connection


def test_session_ignores_environment_proxies(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:3128")
    assert netsafe.make_session().trust_env is False


# --- redirects (fake session, no sockets) -------------------------------------------------
class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"<html></html>"):
        self.status_code = status
        self.headers = requests.structures.CaseInsensitiveDict(headers or {"Content-Type": "text/html"})
        self.reason = "OK"
        self._body = body

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        pass


class FakeSession:
    def __init__(self, routes):
        self.routes, self.requested = routes, []

    def get(self, url, **kwargs):
        self.requested.append((url, kwargs))
        result = self.routes[url]
        if isinstance(result, Exception):
            raise result
        return result

    def close(self):
        pass


def redirect(to, status=302):
    return FakeResponse(status, {"Location": to})


def test_redirect_chain_is_recorded(fake_dns):
    session = FakeSession({
        "http://a.example/": redirect("https://b.example/x"),
        "https://b.example/x": redirect("/final"),
        "https://b.example/final": FakeResponse(body=b"<html>ok</html>"),
    })
    result = fetch("http://a.example/", session=session)
    assert [h.url for h in result.chain] == ["http://a.example/", "https://b.example/x", "https://b.example/final"]
    assert result.final_url == "https://b.example/final" and result.redirect_count == 2
    assert all(kw["allow_redirects"] is False for _, kw in session.requested)


def test_redirect_to_private_ip_is_blocked_after_first_hop(fake_dns):
    fake_dns["internal.example"] = "10.1.2.3"
    session = FakeSession({"http://a.example/": redirect("http://internal.example/admin")})
    with pytest.raises(BlockedAddressError) as exc:
        fetch("http://a.example/", session=session)
    assert "Redirect #1" in exc.value.message
    assert [u for u, _ in session.requested] == ["http://a.example/"]  # the private target was never requested


@pytest.mark.parametrize("target", ["http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/"])
def test_redirect_to_literal_private_ip_is_blocked(fake_dns, target):
    session = FakeSession({"http://a.example/": redirect(target)})
    with pytest.raises(BlockedAddressError):
        fetch("http://a.example/", session=session)


@pytest.mark.parametrize("target", ["file:///etc/passwd", "gopher://a.example/", "javascript:alert(1)", "ftp://a.example/"])
def test_redirect_to_other_schemes_is_rejected(fake_dns, target):
    session = FakeSession({"http://a.example/": redirect(target)})
    with pytest.raises(InvalidURLError):
        fetch("http://a.example/", session=session)


def test_redirect_limit(fake_dns):
    routes = {f"http://a.example/{i}": redirect(f"http://a.example/{i + 1}") for i in range(10)}
    routes["http://a.example/10"] = FakeResponse()
    with pytest.raises(TooManyRedirectsError):
        fetch("http://a.example/0", session=FakeSession(routes))


def test_body_is_truncated_at_limit(fake_dns):
    session = FakeSession({"http://a.example/": FakeResponse(body=b"x" * 5000)})
    result = fetch("http://a.example/", session=session, max_bytes=1000)
    assert result.truncated and len(result.body) == 1000


def test_bad_certificate_is_retried_unverified_and_reported(fake_dns):
    class SSLSession(FakeSession):
        def get(self, url, **kwargs):
            if kwargs.get("verify", True):
                raise requests.exceptions.SSLError("... certificate verify failed: self-signed certificate (_ssl.c:1006)")
            return FakeResponse()

    result = fetch("https://a.example/", session=SSLSession({}))
    assert result.tls_verify_error == "self-signed certificate" and result.status_code == 200


def test_timeout_is_mapped(fake_dns):
    from analyzer.errors import FetchTimeoutError

    session = FakeSession({"http://a.example/": requests.exceptions.ConnectTimeout("slow")})
    with pytest.raises(FetchTimeoutError):
        fetch("http://a.example/", session=session)

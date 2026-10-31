"""Shared fixtures. No test performs real network I/O."""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

import pytest

from analyzer import pipeline
from analyzer.fetcher import FetchResult, Hop
from analyzer.tls import TLSInfo

FIXTURES = Path(__file__).parent / "fixtures"
PUBLIC_IP = "93.184.216.34"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def make_fetch(url: str, html: str, *, chain: list[str] | None = None, status: int = 200) -> FetchResult:
    urls = chain or [url]
    hops = [Hop(u, 301 if i < len(urls) - 1 else status, urls[i + 1] if i < len(urls) - 1 else None, PUBLIC_IP) for i, u in enumerate(urls)]
    return FetchResult(urls[0], urls[-1], status, "OK", "text/html", {}, html.encode("utf-8"), False, hops, 50, None)


def good_tls(host: str, **overrides) -> TLSInfo:
    data = dict(available=True, host=host, issuer="O=Test CA, CN=Test", age_days=200, days_until_expiry=160, validity_days=360,
                trusted=True, matches_domain=True, san=[host], subject_cn=host)
    data.update(overrides)
    return TLSInfo(**data)


@pytest.fixture
def fake_dns(monkeypatch):
    """Resolve every host to a public address (or a mapping you supply)."""
    mapping: dict[str, str] = {}

    def fake_getaddrinfo(host, port, *args, **kwargs):
        try:  # IP literals resolve to themselves, exactly like the real resolver
            ipaddress.ip_address(host.strip("[]"))
            ip = host.strip("[]")
        except ValueError:
            ip = mapping.get(host, PUBLIC_IP)
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return mapping


@pytest.fixture
def run_offline(monkeypatch, fake_dns):
    """Run the whole pipeline against an HTML fixture without any network access."""

    def runner(url: str, html: str, *, tls: TLSInfo | None = None, chain: list[str] | None = None, final_url: str | None = None):
        final = final_url or (chain[-1] if chain else url)
        fetch = make_fetch(url, html, chain=chain or [final])
        host = final.split("//", 1)[1].split("/", 1)[0].split(":")[0]
        monkeypatch.setattr(pipeline, "fetch_url", lambda _u: fetch)
        monkeypatch.setattr(pipeline, "inspect_tls", lambda *a, **k: tls or good_tls(host))
        return pipeline.analyze_url(url, use_rdap=False)

    return runner

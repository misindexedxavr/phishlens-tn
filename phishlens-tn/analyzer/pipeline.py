"""Analysis pipeline: fetch -> parse -> TLS -> domain & brands -> score.

:func:`iter_analysis` yields progress events (used by the streaming API so the UI
can show real step-by-step progress). :func:`analyze_url` runs the same steps and
simply returns the final result, raising typed errors on failure.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Generator, Iterator
from urllib.parse import urlsplit

from . import __version__
from .brands import analyze_brands
from .domain import analyze_domain, analyze_url_features
from .errors import PhishLensError
from .fetcher import FetchResult
from .fetcher import fetch as fetch_url
from .netsafe import parse_target
from .parser import ParsedPage, parse_html
from .scoring import Evidence, score
from .tls import TLSInfo, inspect_tls

log = logging.getLogger(__name__)

SCHEMA = "phishlens-tn/analysis@1"
STEPS = (
    ("fetch", "Fetching"),
    ("parse", "Parsing"),
    ("tls", "TLS"),
    ("domain", "Domain"),
    ("score", "Scoring"),
)


def _step(step: str, status: str, detail: str = "") -> dict[str, Any]:
    return {"event": "step", "step": step, "status": status, "detail": detail}


def _steps(raw_url: str, use_rdap: bool, now: datetime | None) -> Generator[dict[str, Any], None, dict[str, Any]]:
    started = time.monotonic()
    now = now or datetime.now(timezone.utc)
    current = "fetch"
    try:
        entry = parse_target(raw_url)

        yield _step("fetch", "running", f"Requesting {entry.host} (no JavaScript is executed)")
        fetch = fetch_url(entry.url)
        final = parse_target(fetch.final_url)
        yield _step("fetch", "done", f"HTTP {fetch.status_code}, {fetch.redirect_count} redirect(s), {len(fetch.body) // 1024} KB")

        current = "parse"
        yield _step("parse", "running", "Reading the HTML as text")
        page = _parse(fetch)
        yield _step("parse", "done", f"{len(page.forms)} form(s), {len(page.external_summary)} external domain(s)")

        current = "tls"
        if final.scheme == "https":
            yield _step("tls", "running", f"Reading the certificate of {final.host}")
            tls = inspect_tls(final.host, final.port, now=now)
            yield _step("tls", "done" if tls.available else "failed", (tls.issuer or tls.error or "") if tls.available else (tls.error or "No certificate"))
        else:
            tls = TLSInfo.not_applicable(final.host, final.port, "The final page is not served over HTTPS.")
            yield _step("tls", "skipped", "Final page is not HTTPS")

        current = "domain"
        yield _step("domain", "running", "Checking the domain, its age and brand look-alikes")
        domain = analyze_domain(final.host, use_rdap=use_rdap, now=now)
        entry_domain = domain if entry.host == final.host else analyze_domain(entry.host, use_rdap=False, now=now)
        features = analyze_url_features(final)
        entry_features = features if entry.url == final.url and not entry.has_userinfo else analyze_url_features(entry)
        brands = analyze_brands(
            hosts=[final.host, entry.host],
            final_host=final.host,
            paths=list(dict.fromkeys([urlsplit(final.url).path, urlsplit(entry.url).path])),
            title=page.title,
            text=page.visible_text,
            external_domains=page.external_domains,
            favicon_domain=page.favicon_domain if page.favicon_external else None,
        )
        age = f"{domain.rdap.age_days} days old" if domain.rdap.available else "age unknown"
        yield _step("domain", "done", f"{domain.registered_domain}, {age}")

        current = "score"
        yield _step("score", "running", "Applying the weighted rules")
        evidence = Evidence(entry, final, fetch, page, tls, domain, entry_domain, entry_features, features, brands)
        result = score(evidence)
        yield _step("score", "done", f"{result.score}/100, {result.level}")

        return {
            "schema": SCHEMA,
            "tool_version": __version__,
            "analyzed_at": now.isoformat(),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "input_url": entry.original,
            "url": entry.url,
            "final_url": final.url,
            "score": result.score,
            "raw_score": result.raw_score,
            "level": result.level,
            "verdict": result.verdict,
            "signals": [s.to_dict() for s in result.signals],
            "rule_errors": result.rule_errors,
            "brands": brands.to_dict(),
            "fetch": fetch.to_dict(),
            "page": page.to_dict(),
            "tls": tls.to_dict(),
            "domain": domain.to_dict(),
            "entry_domain": entry_domain.to_dict() if entry_domain is not domain else None,
            "url_features": features.to_dict(),
        }
    except Exception as exc:  # annotate which step failed, then re-raise
        if getattr(exc, "step", None) is None:
            try:
                exc.step = current  # type: ignore[attr-defined]
            except AttributeError:
                pass
        raise


def _parse(fetch: FetchResult) -> ParsedPage:
    if not fetch.body:
        page = ParsedPage()
        page.notes.append(
            f"No HTML was downloaded (content type: {fetch.content_type or 'unknown'}). Only URL, domain and certificate checks apply."
        )
        return page
    page = parse_html(fetch.body, fetch.final_url)
    if fetch.truncated:
        page.notes.append("The response was larger than 2 MB and was truncated before analysis.")
    if fetch.status_code >= 400:
        page.notes.append(f"The server answered HTTP {fetch.status_code}; the content may be an error page or a decoy shown to scanners.")
    return page


def iter_analysis(raw_url: str, *, use_rdap: bool = True, now: datetime | None = None) -> Iterator[dict[str, Any]]:
    """Yield progress events, ending with a ``result`` or an ``error`` event."""
    try:
        result = yield from _steps(raw_url, use_rdap, now)
        yield {"event": "result", "result": result}
    except PhishLensError as exc:
        yield {"event": "error", "step": exc.step, "error": exc.to_dict()}
    except Exception:  # never leak internals to the client
        log.exception("Unexpected failure while analyzing a URL")
        yield {
            "event": "error",
            "step": None,
            "error": {
                "code": "internal_error",
                "message": "Something went wrong while analyzing this link.",
                "hint": "Please try again. If it keeps happening, try a different URL.",
            },
        }


def analyze_url(raw_url: str, *, use_rdap: bool = True, now: datetime | None = None) -> dict[str, Any]:
    """Analyze ``raw_url`` and return the full result dictionary.

    Raises a :class:`~analyzer.errors.PhishLensError` subclass on expected failures
    (invalid URL, blocked address, timeout ...).
    """
    generator = _steps(raw_url, use_rdap, now)
    try:
        while True:
            next(generator)
    except StopIteration as stop:
        return stop.value

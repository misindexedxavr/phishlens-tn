"""Safe page fetching.

Pages are downloaded as raw bytes and **never executed**: no JavaScript, no
rendering, no form submission and no following of form actions. Limits: 10 s
per network operation (30 s overall), 2 MB of body, 5 redirects. Redirects are
followed manually so each hop is validated against the SSRF policy.
"""
from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin

import requests
import urllib3

from .errors import (
    BlockedAddressError,
    FetchConnectionError,
    FetchError,
    FetchTimeoutError,
    InvalidURLError,
    PhishLensError,
    TooManyRedirectsError,
)
from .netsafe import ParsedTarget, check_url, make_session

MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 10.0
TOTAL_DEADLINE = 30.0
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_KEPT_HEADERS = ("server", "x-powered-by", "content-type", "content-length", "content-language")

# Phishing sites frequently have broken certificates. We still want to read the
# page (sending nothing sensitive), so an unverified retry is made and reported.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class Hop:
    """One response in the redirect chain."""

    url: str
    status: int
    location: str | None
    ip: str | None


@dataclass
class FetchResult:
    """Everything learned from the HTTP exchange."""

    requested_url: str
    final_url: str
    status_code: int
    reason: str
    content_type: str
    headers: dict[str, str]
    body: bytes
    truncated: bool
    chain: list[Hop] = field(default_factory=list)
    elapsed_ms: int = 0
    tls_verify_error: str | None = None

    @property
    def redirect_count(self) -> int:
        return max(0, len(self.chain) - 1)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe summary (the raw body is not exported)."""
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "reason": self.reason,
            "content_type": self.content_type,
            "headers": self.headers,
            "body_bytes": len(self.body),
            "truncated": self.truncated,
            "elapsed_ms": self.elapsed_ms,
            "redirect_count": self.redirect_count,
            "redirect_chain": [asdict(h) for h in self.chain],
            "tls_verify_error": self.tls_verify_error,
        }


def is_textual(content_type: str) -> bool:
    """True when the body is worth downloading and parsing as markup."""
    ctype = content_type.lower()
    return not ctype or ctype.startswith("text/") or "html" in ctype or "xml" in ctype


def fetch(
    url: str,
    *,
    session: requests.Session | None = None,
    max_bytes: int = MAX_BYTES,
    max_redirects: int = MAX_REDIRECTS,
    timeout: float = REQUEST_TIMEOUT,
    deadline: float = TOTAL_DEADLINE,
) -> FetchResult:
    """Fetch ``url`` safely and return the final response plus the redirect chain."""
    entry, ips = check_url(url)
    owns_session = session is None
    http = session or make_session()
    started = time.monotonic()
    chain: list[Hop] = []
    current, current_ips = entry, ips
    try:
        while True:
            _check_deadline(started, deadline)
            response, verify_error = _open(http, current.url, timeout)
            status = response.status_code
            location = response.headers.get("Location")
            if status in REDIRECT_STATUSES and location:
                response.close()
                if len(chain) >= max_redirects:
                    chain.append(Hop(current.url, status, location, current_ips[0]))
                    raise TooManyRedirectsError(
                        f"The link redirected more than {max_redirects} times, so analysis stopped.",
                        details={"chain": [h.url for h in chain]},
                    )
                next_url = _resolve_redirect(current.url, location, len(chain) + 1)
                nxt, nxt_ips = _check_redirect(next_url, len(chain) + 1)
                chain.append(Hop(current.url, status, nxt.url, current_ips[0]))
                current, current_ips = nxt, nxt_ips
                continue

            content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            body, truncated = b"", False
            if is_textual(content_type):
                body, truncated = _read_body(response, max_bytes, started, deadline)
            else:
                response.close()
            chain.append(Hop(current.url, status, None, current_ips[0]))
            headers = {k: v for k, v in response.headers.items() if k.lower() in _KEPT_HEADERS}
            return FetchResult(
                requested_url=entry.url,
                final_url=current.url,
                status_code=status,
                reason=str(response.reason or ""),
                content_type=content_type,
                headers=headers,
                body=body,
                truncated=truncated,
                chain=chain,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                tls_verify_error=verify_error,
            )
    except PhishLensError:
        raise
    except requests.exceptions.RequestException as exc:
        raise _map_error(exc, timeout) from exc
    finally:
        if owns_session:
            http.close()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _open(session: requests.Session, url: str, timeout: float) -> tuple[requests.Response, str | None]:
    """GET without following redirects; retry unverified if the certificate is bad."""
    try:
        return session.get(url, allow_redirects=False, stream=True, timeout=timeout, verify=True), None
    except requests.exceptions.SSLError as exc:
        reason = _ssl_reason(exc)
        response = session.get(url, allow_redirects=False, stream=True, timeout=timeout, verify=False)
        return response, reason


def _ssl_reason(exc: Exception) -> str:
    text = str(exc)
    match = re.search(r"certificate verify failed: ([^(]+)", text)
    if match:
        return match.group(1).strip().rstrip(".")
    return "TLS certificate could not be verified"


def _check_deadline(started: float, deadline: float) -> None:
    if time.monotonic() - started > deadline:
        raise FetchTimeoutError(f"The analysis exceeded its {deadline:g}-second time limit.")


def _read_body(response: requests.Response, max_bytes: int, started: float, deadline: float) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                chunks.append(chunk[: len(chunk) - (total - max_bytes)])
                truncated = True
                break
            chunks.append(chunk)
            _check_deadline(started, deadline)
    finally:
        response.close()
    return b"".join(chunks), truncated


def _resolve_redirect(base: str, location: str, hop_no: int) -> str:
    try:
        return urljoin(base, location.strip())
    except ValueError:
        raise InvalidURLError(f"Redirect #{hop_no} pointed to a malformed URL.") from None


def _check_redirect(url: str, hop_no: int) -> tuple[ParsedTarget, list[str]]:
    """Re-run the SSRF policy on a redirect target before following it."""
    try:
        return check_url(url)
    except BlockedAddressError as exc:
        raise BlockedAddressError(
            f"Redirect #{hop_no} pointed to a blocked address and was not followed. {exc.message}",
            hint=exc.hint,
        ) from exc
    except PhishLensError as exc:
        raise type(exc)(f"Redirect #{hop_no} could not be followed: {exc.message}", hint=exc.hint) from exc


def _map_error(exc: requests.exceptions.RequestException, timeout: float) -> PhishLensError:
    text = str(exc).lower()
    if isinstance(exc, requests.exceptions.Timeout) or "timed out" in text:
        return FetchTimeoutError(f"The server did not answer within {timeout:g} seconds.")
    if isinstance(exc, (requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema, requests.exceptions.MissingSchema)):
        return InvalidURLError("The URL could not be used for a request.")
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return TooManyRedirectsError("The link redirected too many times.")
    if isinstance(exc, (requests.exceptions.ChunkedEncodingError, requests.exceptions.ContentDecodingError)):
        return FetchError("The server sent a malformed response.")
    if isinstance(exc, requests.exceptions.ConnectionError):
        return FetchConnectionError("Could not connect to the server. It may be offline, taken down, or blocking scanners.")
    return FetchError("The request failed unexpectedly.")

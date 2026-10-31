"""Typed errors shared across the analyzer.

Every error carries a machine-readable ``code``, an HTTP status and a
human-friendly hint, so the web layer and the CLI can show clear messages
without ever leaking a stack trace.
"""
from __future__ import annotations

from typing import Any


class PhishLensError(Exception):
    """Base class for all expected, user-facing analysis failures."""

    code = "internal_error"
    http_status = 500
    default_hint = "Please try again in a moment."

    def __init__(
        self,
        message: str,
        *,
        hint: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint if hint is not None else self.default_hint
        self.details = details or {}
        self.step: str | None = None  # pipeline step that was running when it failed

    def to_dict(self) -> dict[str, str]:
        """Serialise to the error payload used by the API."""
        return {"code": self.code, "message": self.message, "hint": self.hint}


class InvalidURLError(PhishLensError):
    code = "invalid_url"
    http_status = 400
    default_hint = "Enter a full link such as https://example.com/login."


class BlockedAddressError(PhishLensError):
    code = "blocked_address"
    http_status = 403
    default_hint = (
        "PhishLens only analyzes public internet addresses. Private, loopback and "
        "link-local targets are blocked to prevent server-side request forgery."
    )


class HostResolutionError(PhishLensError):
    code = "host_unresolved"
    http_status = 502
    default_hint = "Check the spelling of the domain. It may also have been taken down."


class FetchTimeoutError(PhishLensError):
    code = "timeout"
    http_status = 504
    default_hint = "The site may be offline, very slow, or deliberately stalling scanners."


class FetchConnectionError(PhishLensError):
    code = "connection_failed"
    http_status = 502
    default_hint = "Phishing sites are often taken down quickly. Try again later."


class TooManyRedirectsError(PhishLensError):
    code = "too_many_redirects"
    http_status = 422
    default_hint = "Long redirect chains are a common cloaking trick. Treat this link as suspicious."


class FetchError(PhishLensError):
    code = "fetch_failed"
    http_status = 502
    default_hint = "The server answered in a way PhishLens could not process."

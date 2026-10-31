"""Network safety helpers: URL validation and SSRF protection.

Every outbound connection PhishLens makes (page fetches, redirects, the TLS
probe and RDAP lookups) goes through this module. Two layers protect the host:

1. *Pre-flight checks* (:func:`check_url`) validate the scheme, reject local
   host names and resolve DNS, refusing any address that is not publicly
   routable. They run for the first URL and again for **every redirect target**.
2. A *connection guard* patched into urllib3 re-resolves and re-validates the
   address at connect time and connects to the validated IP. That closes the
   DNS-rebinding window between the check and the real connection.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import connection as _urllib3_connection

from .errors import BlockedAddressError, HostResolutionError, InvalidURLError

ALLOWED_SCHEMES = ("http", "https")
MAX_URL_LENGTH = 2048
USER_AGENT = "PhishLens-TN/1.0 (+defensive phishing analysis; static, no JavaScript executed)"

_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_EXPLICIT_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
_DANGEROUS_SCHEME_RE = re.compile(
    r"^(javascript|data|file|ftp|sftp|mailto|tel|vbscript|about|blob|gopher|ldap|dict|ws|wss|smb|view-source):",
    re.IGNORECASE,
)
_HOST_RE = re.compile(r"[a-z0-9._\-]+")
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".lan", ".home.arpa", ".intranet", ".corp")
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


@dataclass(frozen=True)
class ParsedTarget:
    """A validated, normalised analysis target."""

    url: str  # sanitised URL: no credentials, no fragment, punycode host
    scheme: str
    host: str  # lowercase ASCII (punycode) host
    unicode_host: str
    port: int  # effective port (explicit or scheme default)
    explicit_port: int | None
    has_userinfo: bool  # the submitted URL contained "user@"
    original: str


# --------------------------------------------------------------------------- #
# IP policy
# --------------------------------------------------------------------------- #
def _embedded_ipv4(addr: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses hidden inside an IPv6 address (mapped, 6to4, Teredo, NAT64)."""
    found: list[ipaddress.IPv4Address] = []
    if addr.ipv4_mapped:
        found.append(addr.ipv4_mapped)
    if addr.sixtofour:
        found.append(addr.sixtofour)
    if addr.teredo:
        found.extend(addr.teredo)
    if addr in _NAT64:
        found.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    if int(addr) < 2**32:  # deprecated IPv4-compatible form ::a.b.c.d
        found.append(ipaddress.IPv4Address(int(addr)))
    return found


def _is_blocked_single(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        addr.is_multicast
        or addr.is_unspecified
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_reserved
        or not addr.is_global
    )


def is_blocked_ip(ip: str) -> bool:
    """Return True when ``ip`` must never be contacted.

    Blocks loopback, private (RFC 1918 / ULA), link-local (including the cloud
    metadata address 169.254.169.254), carrier-grade NAT, multicast, reserved and
    unspecified addresses, plus IPv6 forms that embed such IPv4 addresses.
    """
    addr = ipaddress.ip_address(ip.split("%")[0])
    if _is_blocked_single(addr):
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        return any(_is_blocked_single(v4) for v4 in _embedded_ipv4(addr))
    return False


def resolve_host(host: str, port: int) -> list[str]:
    """Resolve ``host`` and return its addresses, refusing non-public ones.

    If *any* returned address is blocked the whole host is refused, which also
    defeats DNS answers that mix public and private records.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, ValueError) as exc:
        raise HostResolutionError(f"Could not resolve the host name '{host}'.") from exc
    addresses: list[str] = []
    for info in infos:
        ip = str(info[4][0]).split("%")[0]
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise HostResolutionError(f"The host name '{host}' has no IP address.")
    for ip in addresses:
        if is_blocked_ip(ip):
            raise BlockedAddressError(
                f"'{host}' points to a private or internal address ({ip}), so it was not contacted."
            )
    return addresses


# --------------------------------------------------------------------------- #
# URL parsing
# --------------------------------------------------------------------------- #
def parse_target(raw: str) -> ParsedTarget:
    """Validate and normalise a user-supplied URL (no DNS lookup).

    Raises :class:`InvalidURLError` for anything that is not a well-formed
    http(s) URL and :class:`BlockedAddressError` for local host names.
    """
    if not isinstance(raw, str):
        raise InvalidURLError("The URL must be a text value.")
    candidate = raw.strip()
    if not candidate:
        raise InvalidURLError("Please enter a URL to analyze.")
    if len(candidate) > MAX_URL_LENGTH:
        raise InvalidURLError(f"The URL is longer than {MAX_URL_LENGTH} characters.")
    if _CONTROL_RE.search(candidate) or "\\" in candidate:
        raise InvalidURLError("The URL contains spaces, backslashes or control characters.")
    if _DANGEROUS_SCHEME_RE.match(candidate):
        raise InvalidURLError("Only http:// and https:// URLs can be analyzed.")
    match = _EXPLICIT_SCHEME_RE.match(candidate)
    if match:
        if match.group(1).lower() not in ALLOWED_SCHEMES:
            raise InvalidURLError("Only http:// and https:// URLs can be analyzed.")
    elif candidate.startswith("//"):
        candidate = "http:" + candidate
    else:
        candidate = "http://" + candidate

    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        explicit_port = parts.port
    except ValueError:
        raise InvalidURLError("The URL is malformed. Check the host name and the port.") from None
    if not hostname or not hostname.strip("."):
        raise InvalidURLError("The URL has no host name.")
    if explicit_port is not None and not 1 <= explicit_port <= 65535:
        raise InvalidURLError("The port number must be between 1 and 65535.")

    hostname = hostname.rstrip(".")
    if ":" in hostname:  # IPv6 literal
        try:
            ascii_host = str(ipaddress.IPv6Address(hostname.split("%")[0]))
        except ValueError:
            raise InvalidURLError("The IPv6 address in the URL is invalid.") from None
        unicode_host = ascii_host
    else:
        try:
            ascii_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise InvalidURLError("The host name contains invalid characters.") from None
        if not _HOST_RE.fullmatch(ascii_host) or ".." in ascii_host or ascii_host.startswith("."):
            raise InvalidURLError("The host name contains invalid characters.")
        try:
            unicode_host = ascii_host.encode("ascii").decode("idna")
        except UnicodeError:
            unicode_host = hostname
        _reject_local_names(ascii_host)

    scheme = parts.scheme.lower()
    host_for_url = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    netloc = host_for_url + (f":{explicit_port}" if explicit_port else "")
    sanitized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return ParsedTarget(
        url=sanitized,
        scheme=scheme,
        host=ascii_host,
        unicode_host=unicode_host,
        port=explicit_port or (443 if scheme == "https" else 80),
        explicit_port=explicit_port,
        has_userinfo="@" in parts.netloc,
        original=raw.strip(),
    )


def _reject_local_names(host: str) -> None:
    if host == "localhost" or host.endswith(_LOCAL_SUFFIXES):
        raise BlockedAddressError(f"'{host}' is a local or internal name and cannot be analyzed.")


def check_url(url: str) -> tuple[ParsedTarget, list[str]]:
    """Full pre-flight check: parse, then resolve and validate every address."""
    target = parse_target(url)
    return target, resolve_host(target.host, target.port)


# --------------------------------------------------------------------------- #
# Connection guard (defence against DNS rebinding)
# --------------------------------------------------------------------------- #
def guarded_create_connection(
    address: tuple[str, int],
    timeout: float | object = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore[attr-defined]
    source_address: tuple[str, int] | None = None,
    socket_options: list[tuple[int, int, int]] | None = None,
) -> socket.socket:
    """Drop-in replacement for ``urllib3.util.connection.create_connection``.

    The host is resolved and validated *here*, and the socket connects to the
    validated IP, so a hostile DNS server cannot swap in a private address
    between the pre-flight check and the actual connection.
    """
    host, port = address
    host = host.strip("[]")
    addresses = resolve_host(host, port)
    last_error: OSError | None = None
    for ip in addresses:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock: socket.socket | None = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            for option in socket_options or []:
                sock.setsockopt(*option)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:  # type: ignore[attr-defined]
                sock.settimeout(timeout)  # type: ignore[arg-type]
            if source_address:
                sock.bind(source_address)
            sock.connect((ip, port))
            return sock
        except OSError as exc:
            last_error = exc
            if sock is not None:
                sock.close()
    raise last_error or OSError(f"Could not connect to {host}:{port}")


def install_connection_guard() -> None:
    """Install :func:`guarded_create_connection` into urllib3 (idempotent)."""
    if _urllib3_connection.create_connection is not guarded_create_connection:
        _urllib3_connection.create_connection = guarded_create_connection  # type: ignore[assignment]


def make_session() -> requests.Session:
    """Create a locked-down ``requests`` session.

    ``trust_env`` is disabled so proxy variables, ``.netrc`` and CA overrides from
    the environment can never route traffic around the SSRF guard.
    """
    install_connection_guard()
    session = requests.Session()
    session.trust_env = False
    session.max_redirects = 3
    adapter = HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=2)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
            "Accept-Language": "en,fr;q=0.8,ar;q=0.5",
        }
    )
    return session


install_connection_guard()

"""Domain and URL checks.

Covers the registered domain (via the bundled Public Suffix List snapshot, no
network), subdomain depth, suspicious TLDs, punycode / homoglyph detection,
free-hosting providers and domain age through RDAP. RDAP is best effort: any
failure degrades to "age unknown" and never breaks the analysis.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import requests
import tldextract

from .errors import PhishLensError
from .netsafe import ParsedTarget, make_session

# Offline extractor: uses the snapshot shipped with tldextract, never fetches the list.
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

#: TLDs that are disproportionately used for throwaway or abusive registrations.
SUSPICIOUS_TLDS = frozenset(
    "xyz top tk ml ga cf gq icu click link buzz cyou cfd sbs rest shop online site live work "
    "support zip mov monster quest bond cam loan men country kim stream download review vip "
    "lol fit rest bar uno surf today world life".split()
)
#: Providers where anybody can publish a page under a shared domain.
FREE_HOSTING_SUFFIXES = (
    "pages.dev", "workers.dev", "netlify.app", "vercel.app", "github.io", "gitlab.io", "weebly.com",
    "wixsite.com", "blogspot.com", "web.app", "firebaseapp.com", "herokuapp.com", "glitch.me",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "000webhostapp.com", "infinityfreeapp.com",
    "rf.gd", "epizy.com", "myshopify.com", "square.site", "webflow.io", "framer.app", "replit.app",
    "onrender.com", "surge.sh", "wordpress.com", "sites.google.com", "carrd.co",
)
URL_SHORTENERS = frozenset(
    "bit.ly tinyurl.com t.co cutt.ly is.gd rebrand.ly goo.gl ow.ly shorturl.at tiny.cc rb.gy "
    "buff.ly lnkd.in s.id t.ly v.gd shorte.st bl.ink".split()
)
HOST_KEYWORDS = (
    "login", "signin", "secure", "verify", "verification", "update", "account", "compte", "banking",
    "ebanking", "webbanking", "paiement", "payment", "confirm", "support", "wallet", "colis",
    "livraison", "facture", "remboursement", "suspend", "authentif", "otp", "connexion",
)
PATH_KEYWORDS = HOST_KEYWORDS + ("password", "mot-de-passe", "carte", "card", "3dsecure", "recharge", "douane")

#: Lookalike characters mapped to the ASCII letter they imitate.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ı": "i", "ɑ": "a",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "υ": "u", "ℓ": "l", "ǀ": "l",
}
_OBFUSCATED_IP_RE = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE)
_RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"
_RDAP_TTL = 3600.0


# --------------------------------------------------------------------------- #
# Host helpers
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class HostParts:
    host: str
    subdomain: str
    domain: str  # the registrable label, e.g. "biat" in biat.com.tn
    suffix: str
    registered_domain: str
    is_ip: bool


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_obfuscated_ip(host: str) -> bool:
    """Detect decimal/hex/octal IPv4 encodings such as ``2130706433`` or ``0x7f.1``."""
    return bool(_OBFUSCATED_IP_RE.match(host)) and not _is_ip(host)


def split_host(host: str) -> HostParts:
    """Split a host into subdomain / registrable label / public suffix."""
    host = host.lower().rstrip(".")
    if _is_ip(host):
        return HostParts(host, "", host, "", host, True)
    ext = _EXTRACTOR(host)
    registered = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
    return HostParts(host, ext.subdomain, ext.domain, ext.suffix, registered, False)


def registered_domain(host: str) -> str:
    """Registered domain of ``host`` (falls back to the host itself)."""
    return split_host(host).registered_domain if host else ""


def to_unicode_host(host: str) -> str:
    """Decode punycode labels (``xn--``) to Unicode."""
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def fold_confusables(text: str) -> str:
    """Lowercase, strip accents and map lookalike letters to ASCII."""
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(CONFUSABLES.get(ch, ch) for ch in decomposed if not unicodedata.combining(ch))


def host_skeleton(host: str) -> str:
    """ASCII 'skeleton' of a host: what a human would read it as."""
    return fold_confusables(to_unicode_host(host))


def _scripts(text: str) -> set[str]:
    scripts: set[str] = set()
    for ch in text:
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                continue
    return scripts


# --------------------------------------------------------------------------- #
# RDAP
# --------------------------------------------------------------------------- #
@dataclass
class RdapInfo:
    """Domain registration data (all fields optional)."""

    available: bool = False
    registered_at: str | None = None
    expires_at: str | None = None
    age_days: int | None = None
    registrar: str | None = None
    source: str | None = None
    error: str | None = None


_rdap_cache: dict[str, tuple[float, RdapInfo]] = {}
_rdap_lock = threading.Lock()


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _registrar(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict) or "registrar" not in [str(r).lower() for r in entity.get("roles", [])]:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    return str(item[3])[:120]
    return None


def parse_rdap(data: Any, now: datetime) -> RdapInfo:
    """Extract registration date, expiry and registrar from an RDAP document."""
    if not isinstance(data, dict):
        return RdapInfo(error="Unexpected RDAP response.")
    registered = expires = None
    for event in data.get("events") or []:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        when = _parse_dt(event.get("eventDate"))
        if when is None:
            continue
        if action == "registration" and registered is None:
            registered = when
        elif action == "expiration" and expires is None:
            expires = when
    if registered is None:
        return RdapInfo(error="The RDAP record has no registration date.")
    return RdapInfo(
        available=True,
        registered_at=registered.isoformat(),
        expires_at=expires.isoformat() if expires else None,
        age_days=max(0, (now - registered).days),
        registrar=_registrar(data),
        source="rdap.org",
    )


def lookup_rdap(domain: str, *, now: datetime | None = None, timeout: float = 6.0) -> RdapInfo:
    """Look up a registered domain via the rdap.org bootstrap service. Never raises."""
    now = now or datetime.now(timezone.utc)
    if not domain or "." not in domain:
        return RdapInfo(error="No registered domain to look up.")
    with _rdap_lock:
        cached = _rdap_cache.get(domain)
        if cached and time.monotonic() - cached[0] < _RDAP_TTL:
            return cached[1]
    try:
        session = make_session()
        session.headers["Accept"] = "application/rdap+json, application/json"
        try:
            response = session.get(_RDAP_ENDPOINT.format(domain=quote(domain, safe="")), timeout=timeout)
        finally:
            session.close()
        if response.status_code == 404:
            info = RdapInfo(error="No RDAP data is published for this domain or TLD.")
        elif response.status_code != 200:
            info = RdapInfo(error=f"RDAP service answered HTTP {response.status_code}.")
        else:
            info = parse_rdap(response.json(), now)
    except (requests.RequestException, ValueError, PhishLensError) as exc:
        info = RdapInfo(error=f"RDAP lookup failed ({type(exc).__name__}).")
    with _rdap_lock:
        if len(_rdap_cache) > 512:
            _rdap_cache.clear()
        _rdap_cache[domain] = (time.monotonic(), info)
    return info


# --------------------------------------------------------------------------- #
# Domain analysis
# --------------------------------------------------------------------------- #
@dataclass
class DomainInfo:
    """Static and registration facts about one host."""

    host: str
    registered_domain: str
    subdomain: str = ""
    subdomain_count: int = 0
    suffix: str = ""
    label: str = ""
    tld: str = ""
    is_ip: bool = False
    obfuscated_ip: bool = False
    suspicious_tld: bool = False
    punycode: bool = False
    unicode_host: str = ""
    skeleton: str = ""
    mixed_script: bool = False
    homoglyph: bool = False
    hyphen_count: int = 0
    digit_count: int = 0
    length: int = 0
    free_hosting: str | None = None
    rdap: RdapInfo = field(default_factory=RdapInfo)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_domain(
    host: str,
    *,
    use_rdap: bool = True,
    now: datetime | None = None,
    rdap_timeout: float = 6.0,
) -> DomainInfo:
    """Analyse ``host``. ``use_rdap=False`` skips the (slower) registration lookup."""
    host = host.lower().rstrip(".")
    parts = split_host(host)
    info = DomainInfo(
        host=host,
        registered_domain=parts.registered_domain,
        subdomain=parts.subdomain,
        suffix=parts.suffix,
        label=parts.domain,
        tld=parts.suffix.rsplit(".", 1)[-1] if parts.suffix else "",
        is_ip=parts.is_ip,
        length=len(host),
    )
    if parts.is_ip or is_obfuscated_ip(host):
        info.obfuscated_ip = not parts.is_ip
        info.rdap = RdapInfo(error="IP addresses have no domain registration data.")
        return info

    info.subdomain_count = len([p for p in parts.subdomain.split(".") if p and p != "www"])
    info.suspicious_tld = info.tld in SUSPICIOUS_TLDS
    info.hyphen_count = parts.domain.count("-")
    info.digit_count = sum(ch.isdigit() for ch in parts.domain)
    info.free_hosting = next((s for s in FREE_HOSTING_SUFFIXES if host == s or host.endswith("." + s)), None)

    info.punycode = any(label.startswith("xn--") for label in host.split("."))
    info.unicode_host = to_unicode_host(host)
    info.skeleton = fold_confusables(info.unicode_host)
    non_ascii = any(ord(ch) > 127 for ch in info.unicode_host)
    scripts = _scripts(info.unicode_host)
    info.mixed_script = len(scripts) > 1
    info.homoglyph = non_ascii and (info.mixed_script or info.skeleton != info.unicode_host.lower())

    if use_rdap:
        info.rdap = lookup_rdap(parts.registered_domain, now=now, timeout=rdap_timeout)
    else:
        info.rdap = RdapInfo(error="Domain age lookup was skipped.")
    return info


# --------------------------------------------------------------------------- #
# URL features
# --------------------------------------------------------------------------- #
@dataclass
class UrlFeatures:
    """Lexical features of a URL."""

    length: int
    has_userinfo: bool
    ip_host: bool
    nonstandard_port: int | None
    host_keywords: list[str]
    path_keywords: list[str]
    is_shortener: bool
    path: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_url_features(target: ParsedTarget) -> UrlFeatures:
    """Compute lexical URL features for a validated target."""
    parts = urlsplit(target.url)
    host = target.host
    path_blob = f"{parts.path}?{parts.query}".lower()
    ip_host = _is_ip(host) or is_obfuscated_ip(host)
    return UrlFeatures(
        length=len(target.original or target.url),
        has_userinfo=target.has_userinfo,
        ip_host=ip_host,
        nonstandard_port=target.explicit_port if target.explicit_port not in (None, 80, 443) else None,
        host_keywords=sorted({k for k in HOST_KEYWORDS if k in host}) if not ip_host else [],
        path_keywords=sorted({k for k in PATH_KEYWORDS if k in path_blob}),
        is_shortener=host in URL_SHORTENERS or registered_domain(host) in URL_SHORTENERS,
        path=parts.path,
    )

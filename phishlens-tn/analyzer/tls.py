"""TLS certificate inspection using only the standard library.

A verified handshake is attempted first. When verification fails (self-signed,
expired, wrong host ...) a second, unverified handshake still retrieves the
certificate so it can be described. The DER certificate is decoded by a small
built-in ASN.1 reader, so no third-party crypto package is required.
"""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from .errors import PhishLensError
from .netsafe import guarded_create_connection


@dataclass
class TLSInfo:
    """Certificate facts for the final host."""

    applicable: bool = True
    available: bool = False
    host: str = ""
    port: int = 443
    error: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    subject_cn: str | None = None
    subject_org: str | None = None
    issuer_cn: str | None = None
    issuer_org: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    age_days: int | None = None
    days_until_expiry: int | None = None
    validity_days: int | None = None
    expired: bool = False
    not_yet_valid: bool = False
    san: list[str] = field(default_factory=list)
    matches_domain: bool | None = None
    self_signed: bool = False
    trusted: bool | None = None
    verification_error: str | None = None
    sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def not_applicable(cls, host: str, port: int, reason: str) -> "TLSInfo":
        return cls(applicable=False, host=host, port=port, error=reason)


# --------------------------------------------------------------------------- #
# Minimal DER / X.509 reader
# --------------------------------------------------------------------------- #
class DerError(ValueError):
    """The certificate could not be decoded."""


def _tlv(data: bytes, pos: int) -> tuple[int, int, int, int]:
    """Read one TLV: returns (tag, value_start, value_end, next_position)."""
    if pos + 2 > len(data):
        raise DerError("truncated")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("unsupported tag")
    length = data[pos + 1]
    start = pos + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or start + count > len(data):
            raise DerError("bad length")
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    end = start + length
    if end > len(data):
        raise DerError("truncated")
    return tag, start, end, end


def _children(data: bytes, start: int, end: int) -> Iterator[tuple[int, int, int]]:
    pos = start
    while pos < end:
        tag, value_start, value_end, pos = _tlv(data, pos)
        yield tag, value_start, value_end


def _oid(data: bytes, start: int, end: int) -> str:
    if start >= end:
        raise DerError("empty oid")
    first = data[start]
    arcs = [first // 40, first % 40]
    value = 0
    for byte in data[start + 1:end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(map(str, arcs))


def _decode_string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:
        return raw.decode("utf-16-be", "replace")
    if tag == 0x1C:
        return raw.decode("utf-32-be", "replace")
    if tag == 0x0C:
        return raw.decode("utf-8", "replace")
    return raw.decode("latin-1")


_NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST"}


def _parse_name(data: bytes, start: int, end: int) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for _, rdn_start, rdn_end in _children(data, start, end):
        for _, atv_start, atv_end in _children(data, rdn_start, rdn_end):
            kids = list(_children(data, atv_start, atv_end))
            if len(kids) < 2:
                continue
            key = _NAME_OIDS.get(_oid(data, kids[0][1], kids[0][2]), "")
            if key:
                result.setdefault(key, []).append(_decode_string(kids[1][0], data[kids[1][1]:kids[1][2]]))
    return result


def _parse_time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii")
    if tag == 0x17:
        yy = int(text[:2])
        year, rest = (2000 + yy if yy < 50 else 1900 + yy), text[2:]
    elif tag == 0x18:
        year, rest = int(text[:4]), text[4:]
    else:
        raise DerError("bad time")
    second = int(rest[8:10]) if len(rest) >= 10 and rest[8:10].isdigit() else 0
    return datetime(year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]), second, tzinfo=timezone.utc)


def _parse_san(data: bytes, start: int, end: int) -> tuple[list[str], list[str]]:
    dns: list[str] = []
    ips: list[str] = []
    _, seq_start, seq_end, _ = _tlv(data, start)
    for tag, value_start, value_end in _children(data, seq_start, seq_end):
        raw = data[value_start:value_end]
        if tag == 0x82:
            dns.append(raw.decode("ascii", "replace").lower())
        elif tag == 0x87 and len(raw) in (4, 16):
            ips.append(str(ipaddress.ip_address(raw)))
    return dns, ips


def parse_certificate(der: bytes) -> dict[str, Any]:
    """Decode the fields PhishLens needs from a DER X.509 certificate."""
    try:
        _, cert_start, cert_end, _ = _tlv(der, 0)
        tbs_tag, tbs_start, tbs_end = next(_children(der, cert_start, cert_end))
        fields = list(_children(der, tbs_start, tbs_end))
        idx = 1 if fields[0][0] == 0xA0 else 0
        issuer = _parse_name(der, fields[idx + 2][1], fields[idx + 2][2])
        validity = list(_children(der, fields[idx + 3][1], fields[idx + 3][2]))
        not_before = _parse_time(validity[0][0], der[validity[0][1]:validity[0][2]])
        not_after = _parse_time(validity[1][0], der[validity[1][1]:validity[1][2]])
        subject = _parse_name(der, fields[idx + 4][1], fields[idx + 4][2])
        dns_names: list[str] = []
        ip_names: list[str] = []
        for tag, start, end in fields[idx + 6:]:
            if tag != 0xA3:
                continue
            for _, seq_start, seq_end in _children(der, start, end):
                for _, ext_start, ext_end in _children(der, seq_start, seq_end):
                    parts = list(_children(der, ext_start, ext_end))
                    if _oid(der, parts[0][1], parts[0][2]) == "2.5.29.17":
                        dns_names, ip_names = _parse_san(der, parts[-1][1], parts[-1][2])
    except (DerError, IndexError, ValueError, StopIteration) as exc:
        raise DerError(f"could not decode certificate: {exc}") from exc
    return {
        "subject": subject, "issuer": issuer, "not_before": not_before, "not_after": not_after,
        "dns_names": dns_names, "ip_names": ip_names,
    }


def _match_pattern(pattern: str, host: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == host
    if not pattern.startswith("*.") or "*" in pattern[2:] or pattern.count(".") < 2:
        return False
    return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")


def hostname_matches(host: str, dns_names: list[str], ip_names: list[str], common_name: str | None) -> bool:
    """RFC 6125 style match: SAN first, CN only when there is no SAN, single-label wildcards."""
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host in ip_names
    except ValueError:
        pass
    names = dns_names or ([common_name] if common_name else [])
    return any(_match_pattern(name, host) for name in names)


def describe_certificate(der: bytes, host: str, now: datetime | None = None) -> TLSInfo:
    """Build a :class:`TLSInfo` from a DER certificate (pure function, easy to test)."""
    now = now or datetime.now(timezone.utc)
    cert = parse_certificate(der)
    subject, issuer = cert["subject"], cert["issuer"]
    not_before, not_after = cert["not_before"], cert["not_after"]
    issuer_org = (issuer.get("O") or [None])[0]
    issuer_cn = (issuer.get("CN") or [None])[0]
    subject_cn = (subject.get("CN") or [None])[0]
    info = TLSInfo(
        available=True,
        host=host,
        subject_cn=subject_cn,
        subject_org=(subject.get("O") or [None])[0],
        issuer_cn=issuer_cn,
        issuer_org=issuer_org,
        issuer=", ".join(f"{k}={v[0]}" for k, v in issuer.items() if k in ("O", "CN") and v) or None,
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        age_days=(now - not_before).days,
        days_until_expiry=(not_after - now).days,
        validity_days=(not_after - not_before).days,
        expired=now > not_after,
        not_yet_valid=now < not_before,
        san=cert["dns_names"] + [f"IP:{ip}" for ip in cert["ip_names"]],
        matches_domain=hostname_matches(host, cert["dns_names"], cert["ip_names"], subject_cn),
        self_signed=bool(issuer) and issuer == subject,
        sha256=hashlib.sha256(der).hexdigest(),
    )
    return info


# --------------------------------------------------------------------------- #
# Live inspection
# --------------------------------------------------------------------------- #
def _handshake(host: str, port: int, timeout: float, verify: bool) -> tuple[bytes, str | None, str | None]:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    sock = guarded_create_connection((host, port), timeout)
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise ssl.SSLError("the server presented no certificate")
            cipher = tls.cipher()
            return der, tls.version(), cipher[0] if cipher else None
    except BaseException:
        sock.close()
        raise


def _friendly_error(exc: BaseException, port: int) -> str:
    if isinstance(exc, ConnectionRefusedError):
        return f"Port {port} refused the connection, so the site does not offer HTTPS there."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "The TLS handshake timed out."
    if isinstance(exc, ssl.SSLError):
        return f"TLS handshake failed: {getattr(exc, 'reason', None) or exc}"
    if isinstance(exc, PhishLensError):
        return exc.message
    return f"Could not open a TLS connection ({type(exc).__name__})."


def inspect_tls(host: str, port: int = 443, *, timeout: float = 10.0, now: datetime | None = None) -> TLSInfo:
    """Connect to ``host:port``, read the certificate and describe it. Never raises."""
    verification_error: str | None = None
    trusted: bool | None = None
    try:
        der, protocol, cipher = _handshake(host, port, timeout, verify=True)
        trusted = True
    except ssl.SSLCertVerificationError as exc:
        trusted = False
        verification_error = (getattr(exc, "verify_message", None) or str(exc)).strip()
        try:
            der, protocol, cipher = _handshake(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError, PhishLensError) as inner:
            return TLSInfo(host=host, port=port, trusted=False, verification_error=verification_error, error=_friendly_error(inner, port))
    except (OSError, ssl.SSLError, PhishLensError) as exc:
        return TLSInfo(host=host, port=port, error=_friendly_error(exc, port))
    try:
        info = describe_certificate(der, host, now)
    except DerError as exc:
        return TLSInfo(host=host, port=port, error=str(exc), trusted=trusted, verification_error=verification_error)
    info.port = port
    info.protocol = protocol
    info.cipher = cipher
    info.trusted = trusted
    info.verification_error = verification_error
    return info

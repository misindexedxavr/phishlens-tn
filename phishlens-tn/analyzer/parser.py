"""Static HTML analysis.

The page is parsed with BeautifulSoup's pure-Python parser. Nothing is executed
or rendered: scripts are only *read* as text to look for tell-tale patterns.
Forms are described, never submitted, and form actions are never followed.
"""
from __future__ import annotations

import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from .domain import registered_domain

_WS = re.compile(r"\s+")
_NON_INPUT_TYPES = {"hidden", "submit", "button", "checkbox", "radio", "file", "image", "reset", "range", "color"}
_CREDENTIAL_CATEGORIES = {"password", "card", "otp", "pin", "identity"}

_FIELD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("password", re.compile(r"passw|pwd|mot[\s_\-]*de[\s_\-]*passe|(?<![a-z])mdp(?![a-z])|current-password|new-password")),
    ("card", re.compile(r"card|carte|cc[\s_\-]?(num|exp|csc|cvc)|cvv|cvc|cvn|(?<![a-z])pan(?![a-z])|expir")),
    ("otp", re.compile(r"(?<![a-z])otp(?![a-z])|one[\s_\-]?time|sms[\s_\-]?code|code[\s_\-]?sms|verification[\s_\-]?code|code[\s_\-]?de[\s_\-]?verif|2fa|mfa|authenticator|3d[\s_\-]?secure|code[\s_\-]?secret")),
    ("pin", re.compile(r"(?<![a-z])pin(?![a-z])")),
    ("identity", re.compile(r"(?<![a-z])cin(?![a-z])|identit|passport|passeport|(?<![a-z])ssn(?![a-z])|(?<![a-z])iban(?![a-z])|(?<![a-z])rib(?![a-z])|date[\s_\-]?de[\s_\-]?naissance|birth|maiden|numero[\s_\-]*de[\s_\-]*compte|account[\s_\-]?number")),
    ("username", re.compile(r"user|login|identifiant|id[\s_\-]?client|client[\s_\-]?id|nom[\s_\-]?d.?utilisateur|matricule")),
)

_EXFIL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Telegram bot API", re.compile(r"api\.telegram\.org/bot", re.I)),
    ("Discord webhook", re.compile(r"discord(?:app)?\.com/api/webhooks", re.I)),
    ("Formspree", re.compile(r"formspree\.io", re.I)),
    ("Getform", re.compile(r"getform\.io", re.I)),
    ("FormSubmit", re.compile(r"formsubmit\.co", re.I)),
    ("Web3Forms", re.compile(r"web3forms\.com", re.I)),
    ("Google Apps Script", re.compile(r"script\.google\.com/macros", re.I)),
    ("webhook.site", re.compile(r"webhook\.site", re.I)),
    ("Pipedream", re.compile(r"pipedream\.net", re.I)),
    ("SMTP.js", re.compile(r"smtpjs\.com|Email\.send\s*\(", re.I)),
)
_SCRIPT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("eval", re.compile(r"\beval\s*\(")),
    ("atob", re.compile(r"\batob\s*\(")),
    ("unescape", re.compile(r"\bunescape\s*\(")),
    ("fromCharCode", re.compile(r"String\.fromCharCode")),
    ("hex_escapes", re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}")),
    ("long_encoded_string", re.compile(r"[A-Za-z0-9+/=]{400,}")),
)
_JS_REDIRECT = re.compile(
    r"""(?:\b(?:window|document|top|self|parent)\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]|location\.(?:replace|assign)\s*\(\s*['"]([^'"]+)['"]"""
)
_CONTEXT_MENU = re.compile(r"""oncontextmenu\s*=\s*["']?\s*return\s+false|addEventListener\(\s*['"]contextmenu""", re.I)
_REFRESH = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(?:[;,]\s*(?:url\s*=\s*)?['\"]?(.*?)['\"]?)?\s*$", re.I)
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|(?:width|height)\s*:\s*0(?:px)?\b", re.I)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class FormInput:
    tag: str
    type: str
    name: str
    id: str
    placeholder: str
    sensitive: list[str] = field(default_factory=list)


@dataclass
class FormInfo:
    index: int
    action: str
    resolved_action: str
    action_scheme: str
    action_host: str
    action_domain: str
    method: str
    inputs: list[FormInput]
    input_count: int
    hidden_count: int
    input_types: dict[str, int]
    has_password: bool
    sensitive_fields: list[str]
    external_action: bool
    submit_labels: list[str]

    @property
    def has_credentials(self) -> bool:
        return bool(set(self.sensitive_fields) & _CREDENTIAL_CATEGORIES)


@dataclass
class IframeInfo:
    src: str
    host: str
    domain: str
    external: bool
    hidden: bool
    sandboxed: bool
    srcdoc: bool


@dataclass
class MetaRefresh:
    delay: float
    url: str
    resolved_url: str
    host: str
    domain: str
    external: bool


@dataclass
class ParsedPage:
    """Everything extracted from the HTML."""

    is_html: bool = False
    title: str | None = None
    base_href: str | None = None
    forms: list[FormInfo] = field(default_factory=list)
    iframes: list[IframeInfo] = field(default_factory=list)
    meta_refresh: MetaRefresh | None = None
    favicon_url: str | None = None
    favicon_source: str | None = None  # link | default | inline
    favicon_domain: str | None = None
    favicon_external: bool = False
    resource_counts: dict[str, int] = field(default_factory=dict)
    external_domains: dict[str, dict[str, int]] = field(default_factory=dict)
    external_summary: list[dict[str, Any]] = field(default_factory=list)
    password_field_count: int = 0
    orphan_password_inputs: int = 0
    script_indicators: list[str] = field(default_factory=list)
    exfil_endpoints: list[str] = field(default_factory=list)
    js_redirect: str | None = None
    right_click_disabled: bool = False
    noindex: bool = False
    text_length: int = 0
    visible_text: str = field(default="", repr=False)
    notes: list[str] = field(default_factory=list)

    @property
    def has_login_form(self) -> bool:
        return self.password_field_count > 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("visible_text", None)
        for form_data, form in zip(data["forms"], self.forms):
            form_data["has_credentials"] = form.has_credentials
        data["has_login_form"] = self.has_login_form
        return data


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _clean(text: str | None, limit: int = 300) -> str:
    return _WS.sub(" ", text or "").strip()[:limit]


def _fold(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text.lower()) if not unicodedata.combining(c))


def _absolute(base: str, value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = re.sub(r"[\t\r\n]", "", value).strip()
    if not cleaned:
        return None
    try:
        return urljoin(base, cleaned)
    except ValueError:
        return None


def _host_of(url: str) -> tuple[str, str]:
    """Return (host, registered domain) for http(s) URLs, else ("", "")."""
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return "", ""
        host = parts.hostname.lower()
    except ValueError:
        return "", ""
    return host, registered_domain(host)


def classify_field(input_type: str, *attributes: str) -> list[str]:
    """Categorise an input as password / card / otp / pin / identity / username."""
    if input_type in _NON_INPUT_TYPES:
        return []
    blob = _fold(" ".join(a for a in attributes if a))
    categories = [name for name, pattern in _FIELD_PATTERNS if pattern.search(blob)]
    if input_type == "password" and "password" not in categories:
        categories.insert(0, "password")
    return categories


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def parse_html(content: bytes | str, page_url: str, *, max_elements: int = 5000) -> ParsedPage:
    """Parse ``content`` (fetched from ``page_url``) without executing anything."""
    page = ParsedPage()
    if not content:
        page.notes.append("The response body was empty.")
        return page
    soup = BeautifulSoup(content, "html.parser")
    page.is_html = soup.find(True) is not None
    if not page.is_html:
        page.notes.append("The response did not contain any HTML markup.")
        return page

    base_url = page_url
    base_tag = soup.find("base", href=True)
    if base_tag:
        candidate = _absolute(page_url, base_tag["href"])
        if candidate and urlsplit(candidate).scheme in ("http", "https"):
            base_url = candidate
            page.base_href = candidate
            page.notes.append("The page sets a <base href>, which changes how relative links resolve.")
    _, page_domain = _host_of(page_url)

    page.title = _clean(soup.title.get_text()) if soup.title else None

    totals: Counter[str] = Counter()
    external: dict[str, Counter[str]] = defaultdict(Counter)

    def register(category: str, value: Any) -> str | None:
        resolved = _absolute(base_url, value)
        if not resolved:
            return None
        host, domain = _host_of(resolved)
        if host:
            totals[category] += 1
            if domain and domain != page_domain:
                external[category][domain] += 1
        return resolved

    for tag in soup.find_all("a", href=True, limit=max_elements):
        register("links", tag["href"])
    for tag in soup.find_all("script", src=True, limit=max_elements):
        register("scripts", tag["src"])
    for tag in soup.find_all("img", src=True, limit=max_elements):
        register("images", tag["src"])
    icon_links = []
    for tag in soup.find_all("link", href=True, limit=max_elements):
        rel = [str(r).lower() for r in (tag.get("rel") or [])]
        if "stylesheet" in rel:
            register("stylesheets", tag["href"])
        if any("icon" in r for r in rel):
            icon_links.append((rel, tag["href"]))

    # Favicon
    chosen = next((href for rel, href in icon_links if "icon" in rel), None) or (icon_links[0][1] if icon_links else None)
    if chosen and str(chosen).strip().lower().startswith("data:"):
        page.favicon_source = "inline"
    elif chosen:
        resolved = _absolute(base_url, chosen)
        page.favicon_url, page.favicon_source = resolved, "link"
        host, domain = _host_of(resolved or "")
        page.favicon_domain = domain or None
        page.favicon_external = bool(domain and domain != page_domain)
    else:
        page.favicon_url, page.favicon_source = urljoin(base_url, "/favicon.ico"), "default"
        _, page.favicon_domain = _host_of(page.favicon_url)

    # Scripts (read as text only)
    inline = [(s.get_text() or "") for s in soup.find_all("script", limit=500) if not s.get("src")]
    script_blob = "\n".join(inline)[:300_000]

    # Forms
    all_password_inputs = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)}, limit=max_elements)
    page.password_field_count = len(all_password_inputs)
    page.orphan_password_inputs = sum(1 for i in all_password_inputs if i.find_parent("form") is None)
    form_sources: list[str] = []
    for index, form in enumerate(soup.find_all("form", limit=100), 1):
        page.forms.append(_parse_form(form, index, base_url, page_url, page_domain))
        form_sources.append(str(form.get("action", "")))
        if page.forms[-1].action_scheme in ("http", "https"):
            register("forms", form.get("action") or page_url)
    page.resource_counts = dict(totals)

    # Iframes
    for frame in soup.find_all("iframe", limit=100):
        src = str(frame.get("src", "")).strip()
        resolved = _absolute(base_url, src) or ""
        host, domain = _host_of(resolved)
        style = str(frame.get("style", ""))
        hidden = (
            frame.has_attr("hidden")
            or str(frame.get("width", "")).strip() in ("0", "1")
            or str(frame.get("height", "")).strip() in ("0", "1")
            or bool(_HIDDEN_STYLE.search(style))
        )
        if host:
            register("iframes", src)
        page.iframes.append(
            IframeInfo(
                src=src[:300], host=host, domain=domain, external=bool(domain and domain != page_domain),
                hidden=hidden, sandboxed=frame.has_attr("sandbox"), srcdoc=frame.has_attr("srcdoc"),
            )
        )

    # Meta refresh and robots
    for meta in soup.find_all("meta", limit=200):
        http_equiv = str(meta.get("http-equiv", "")).lower()
        name = str(meta.get("name", "")).lower()
        if http_equiv == "refresh" and page.meta_refresh is None:
            match = _REFRESH.match(str(meta.get("content", "")))
            if match and match.group(2):
                resolved = _absolute(base_url, match.group(2)) or ""
                host, domain = _host_of(resolved)
                page.meta_refresh = MetaRefresh(
                    delay=float(match.group(1)), url=match.group(2)[:300], resolved_url=resolved[:500],
                    host=host, domain=domain, external=bool(domain and domain != page_domain),
                )
        if name == "robots" and "noindex" in str(meta.get("content", "")).lower():
            page.noindex = True

    page.external_domains = {cat: dict(counter.most_common()) for cat, counter in external.items()}
    page.external_summary = _summarise_external(external, page.favicon_domain if page.favicon_external else None)

    # Script indicators
    page.script_indicators = [name for name, pattern in _SCRIPT_PATTERNS if pattern.search(script_blob)]
    redirect = _JS_REDIRECT.search(script_blob)
    if redirect:
        page.js_redirect = (redirect.group(1) or redirect.group(2))[:300]
    body_tag = soup.body
    page.right_click_disabled = bool(_CONTEXT_MENU.search(script_blob)) or bool(
        body_tag is not None and re.search(r"return\s+false", str(body_tag.get("oncontextmenu", "")), re.I)
    )
    exfil_blob = script_blob + "\n" + "\n".join(form_sources) + "\n" + "\n".join(
        str(t["src"]) for t in soup.find_all("script", src=True, limit=500)
    )
    page.exfil_endpoints = [name for name, pattern in _EXFIL_PATTERNS if pattern.search(exfil_blob)]

    # Visible text last (this removes script/style nodes from the tree)
    for node in soup(["script", "style", "noscript", "template"]):
        node.decompose()
    text = soup.get_text(" ", strip=True)
    page.text_length = len(text)
    page.visible_text = text[:200_000]
    return page


def _parse_form(form: Any, index: int, base_url: str, page_url: str, page_domain: str) -> FormInfo:
    raw_action = str(form.get("action", "") or "").strip()
    resolved = (_absolute(base_url, raw_action) if raw_action else page_url) or page_url
    scheme = urlsplit(resolved).scheme.lower() if resolved else ""
    if raw_action.lower().startswith(("javascript:", "mailto:", "data:")):
        scheme = raw_action.split(":", 1)[0].lower()
        resolved = raw_action
    host, domain = _host_of(resolved)
    method = str(form.get("method", "get") or "get").strip().lower()
    if method not in ("get", "post", "dialog"):
        method = "get"

    inputs: list[FormInput] = []
    type_counter: Counter[str] = Counter()
    sensitive: set[str] = set()
    submit_labels: list[str] = []
    hidden = 0
    elements = form.find_all(["input", "select", "textarea", "button"], limit=200)
    for el in elements:
        if el.name == "button":
            label = _clean(el.get_text(), 40)
            if label and len(submit_labels) < 3:
                submit_labels.append(label)
            continue
        input_type = str(el.get("type", "text") or "text").strip().lower() if el.name == "input" else el.name
        if input_type in ("submit", "button") and el.get("value") and len(submit_labels) < 3:
            submit_labels.append(_clean(str(el.get("value")), 40))
        if input_type == "hidden":
            hidden += 1
        type_counter[input_type] += 1
        categories = classify_field(
            input_type, str(el.get("name", "")), str(el.get("id", "")), str(el.get("placeholder", "")),
            str(el.get("autocomplete", "")), str(el.get("aria-label", "")),
        )
        sensitive.update(categories)
        if input_type not in ("submit", "button"):
            inputs.append(
                FormInput(
                    tag=el.name, type=input_type, name=_clean(str(el.get("name", "")), 80), id=_clean(str(el.get("id", "")), 80),
                    placeholder=_clean(str(el.get("placeholder", "")), 80), sensitive=categories,
                )
            )
    order = ["password", "card", "otp", "pin", "identity", "username"]
    return FormInfo(
        index=index,
        action=raw_action[:500],
        resolved_action=resolved[:500],
        action_scheme=scheme,
        action_host=host,
        action_domain=domain,
        method=method,
        inputs=inputs,
        input_count=len(inputs),
        hidden_count=hidden,
        input_types=dict(type_counter),
        has_password=type_counter.get("password", 0) > 0,
        sensitive_fields=[c for c in order if c in sensitive],
        external_action=bool(domain and domain != page_domain),
        submit_labels=submit_labels,
    )


def _summarise_external(external: dict[str, Counter[str]], favicon_domain: str | None) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for category, counter in external.items():
        for domain, count in counter.items():
            entry = merged.setdefault(domain, {"domain": domain, "count": 0, "categories": set()})
            entry["count"] += count
            entry["categories"].add(category)
    if favicon_domain:
        entry = merged.setdefault(favicon_domain, {"domain": favicon_domain, "count": 0, "categories": set()})
        entry["count"] += 1
        entry["categories"].add("favicon")
    summary = [{"domain": e["domain"], "count": e["count"], "categories": sorted(e["categories"])} for e in merged.values()]
    summary.sort(key=lambda e: (-e["count"], e["domain"]))
    return summary[:50]

"""Weighted rule engine.

A *rule* is a small function that receives an :class:`Evidence` bundle and
returns a :class:`Hit` (an explanation, optionally with its own weight) or
``None``. Rules are registered with the :func:`rule` decorator in
:mod:`analyzer.rules`; :func:`score` runs them all, adds the weights, clamps the
total to 0-100 and maps it to a level.

Weights are in "risk points". Negative weights are *mitigations* (for example,
the page is on an official domain). See ``analyzer/rules.py`` for how to add
your own rule.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from .brands import BrandAnalysis
from .domain import DomainInfo, UrlFeatures, registered_domain
from .fetcher import FetchResult
from .netsafe import ParsedTarget
from .parser import FormInfo, ParsedPage
from .tls import TLSInfo

log = logging.getLogger(__name__)

#: (level name, minimum score). Order matters.
LEVELS: tuple[tuple[str, int], ...] = (("Low", 0), ("Medium", 25), ("High", 50), ("Critical", 75))


def level_for(score: int) -> str:
    """Map a 0-100 score to Low / Medium / High / Critical."""
    name = LEVELS[0][0]
    for level, minimum in LEVELS:
        if score >= minimum:
            name = level
    return name


def severity_for(weight: int) -> str:
    """Colour bucket for a single signal."""
    if weight < 0:
        return "positive"
    if weight >= 30:
        return "critical"
    if weight >= 20:
        return "high"
    if weight >= 10:
        return "medium"
    return "low"


@dataclass
class Evidence:
    """Everything the rules may look at."""

    entry: ParsedTarget
    final: ParsedTarget
    fetch: FetchResult
    page: ParsedPage
    tls: TLSInfo
    domain: DomainInfo  # final host
    entry_domain: DomainInfo  # submitted host (same object when no host change)
    entry_features: UrlFeatures
    features: UrlFeatures  # final URL
    brands: BrandAnalysis

    @property
    def credential_forms(self) -> list[FormInfo]:
        return [f for f in self.page.forms if f.has_credentials]

    @property
    def asks_for_login(self) -> bool:
        return self.page.has_login_form

    @property
    def asks_for_sensitive_data(self) -> bool:
        return self.asks_for_login or bool(self.credential_forms)

    @property
    def chain_domains(self) -> list[str]:
        """Registered domain of every hop in the redirect chain."""
        domains: list[str] = []
        for hop in self.fetch.chain:
            host = urlsplit(hop.url).hostname or ""
            domains.append(registered_domain(host))
        return domains

    @property
    def cross_domain_hops(self) -> int:
        chain = self.chain_domains
        return sum(1 for a, b in zip(chain, chain[1:]) if a and b and a != b)


@dataclass(frozen=True)
class Hit:
    """A triggered rule: plain-English explanation and an optional weight override."""

    explanation: str
    weight: int | None = None


@dataclass(frozen=True)
class Rule:
    """A registered scoring rule."""

    id: str
    title: str
    weight: int
    category: str
    icon: str
    description: str
    check: Callable[[Evidence], Hit | None]


RULES: list[Rule] = []


def rule(*, id: str, title: str, weight: int, category: str, icon: str) -> Callable[[Callable[[Evidence], Hit | None]], Callable[[Evidence], Hit | None]]:
    """Register a scoring rule. The function's docstring becomes its documentation."""

    def decorator(func: Callable[[Evidence], Hit | None]) -> Callable[[Evidence], Hit | None]:
        if any(existing.id == id for existing in RULES):
            raise ValueError(f"Duplicate rule id: {id}")
        description = " ".join((func.__doc__ or "").split())
        RULES.append(Rule(id, title, weight, category, icon, description, func))
        return func

    return decorator


def get_rules() -> list[Rule]:
    """Return all registered rules (loading the built-in set on first use)."""
    from . import rules as _builtin  # noqa: F401  (import registers the rules)

    return list(RULES)


@dataclass
class Signal:
    """A triggered rule, ready for display."""

    id: str
    title: str
    weight: int
    severity: str
    category: str
    icon: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScoreResult:
    score: int
    raw_score: int
    level: str
    verdict: str
    signals: list[Signal] = field(default_factory=list)
    rule_errors: list[str] = field(default_factory=list)


def score(evidence: Evidence, rules: Sequence[Rule] | None = None) -> ScoreResult:
    """Run the rules, sum their weights and build the verdict."""
    active = list(rules) if rules is not None else get_rules()
    signals: list[Signal] = []
    errors: list[str] = []
    for item in active:
        try:
            hit = item.check(evidence)
        except Exception as exc:  # a faulty rule must never break the analysis
            log.exception("Rule %s failed", item.id)
            errors.append(f"{item.id}: {type(exc).__name__}")
            continue
        if hit is None:
            continue
        weight = item.weight if hit.weight is None else hit.weight
        signals.append(Signal(item.id, item.title, weight, severity_for(weight), item.category, item.icon, hit.explanation))
    signals.sort(key=lambda s: (-s.weight, s.title))
    raw = sum(s.weight for s in signals)
    final_score = max(0, min(100, raw))
    level = level_for(final_score)
    return ScoreResult(final_score, raw, level, build_verdict(level, signals, evidence.brands), signals, errors)


def build_verdict(level: str, signals: Sequence[Signal], brands: BrandAnalysis) -> str:
    """One plain-English sentence summarising the result."""
    risky = [s for s in signals if s.weight > 0]
    reasons = "; ".join(s.title.rstrip(".") for s in risky[:2])
    brand_signal = any(s.category == "brand" and s.weight >= 15 for s in risky)
    brand = brands.targeted_brands[0] if brands.targeted_brands and brand_signal else None
    if level == "Low":
        if brands.official_brand:
            return f"Low risk: this page is served from an official {brands.official_brand} domain. Always double-check the address bar."
        return "Low risk: no strong phishing indicators were found. A clean result is not proof of safety, so stay cautious."
    if level == "Medium":
        return f"Medium risk: some traits are suspicious ({reasons}). Verify the sender and the address through an official channel before trusting it."
    target = f" that appears to impersonate {brand}" if brand else ""
    if level == "High":
        return f"High risk: this looks like a deceptive page{target}. Main reasons: {reasons}. Do not enter any credentials."
    return f"Critical risk: this is very likely a phishing page{target}. Main reasons: {reasons}. Do not enter credentials, card numbers or codes."

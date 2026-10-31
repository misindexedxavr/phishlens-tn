"""Tunisian brand detection.

Brands and their official domains live in ``data/brands.json`` (override the
path with ``PHISHLENS_BRANDS_FILE``). Detection looks at:

* brand names in the page title and visible text (only when the page is not on
  an official domain),
* brand keywords inside the host name (subdomain or registered domain),
* the official domain embedded in a longer host (``biat.com.tn.evil.com``),
* typosquatting: edit distance, adjacent transpositions, repeated letters,
  look-alike characters (``rn``/``m``, ``1``/``l``, ``0``/``o`` ...) and
  TLD swaps,
* assets hot-linked from an official brand domain.
"""
from __future__ import annotations

import json
import os
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Sequence

from .domain import HostParts, host_skeleton, registered_domain, split_host

DEFAULT_BRANDS_FILE = Path(__file__).resolve().parent.parent / "data" / "brands.json"

_VISUAL_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_VISUAL_SINGLE = str.maketrans(
    {"1": "l", "i": "l", "|": "l", "0": "o", "5": "s", "$": "s", "3": "e", "4": "a", "@": "a", "7": "t"}
)
_SWAP_CHARS = set("013457|$@")


class BrandDataError(ValueError):
    """Raised when brands.json is missing or malformed."""


def fold_text(text: str) -> str:
    """Casefold and strip accents so 'Télécom' matches 'telecom'."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch)).casefold()


@dataclass(frozen=True)
class Brand:
    """A protected brand."""

    id: str
    name: str
    category: str
    official_domains: tuple[str, ...]
    names: tuple[str, ...] = ()
    acronyms: tuple[str, ...] = ()
    tokens: tuple[str, ...] = ()
    fuzzy: bool = True
    labels: tuple[str, ...] = field(init=False, default=())
    name_regexes: tuple[re.Pattern[str], ...] = field(init=False, default=(), compare=False, repr=False)
    acronym_regexes: tuple[re.Pattern[str], ...] = field(init=False, default=(), compare=False, repr=False)

    def __post_init__(self) -> None:
        labels = {split_host(d).domain.replace("-", "") for d in self.official_domains}
        labels |= {t.replace("-", "") for t in self.tokens if len(t.replace("-", "")) >= 3}
        object.__setattr__(self, "labels", tuple(sorted(labels)))
        name_re = tuple(
            re.compile(r"(?<![a-z0-9])" + r"[\s\-_]*".join(re.escape(w) for w in fold_text(n).split()) + r"(?![a-z0-9])")
            for n in self.names
        )
        acr_re = tuple(re.compile(rf"(?<![A-Za-z0-9]){re.escape(a)}(?![A-Za-z0-9])") for a in self.acronyms)
        object.__setattr__(self, "name_regexes", name_re)
        object.__setattr__(self, "acronym_regexes", acr_re)


@lru_cache(maxsize=4)
def _load(path_str: str) -> tuple[Brand, ...]:
    try:
        data = json.loads(Path(path_str).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BrandDataError(f"Cannot read brand list {path_str}: {exc}") from exc
    entries = data.get("brands") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise BrandDataError("brands.json must contain a non-empty 'brands' list.")
    brands: list[Brand] = []
    for entry in entries:
        try:
            domains = tuple(str(d).lower().strip() for d in entry["official_domains"])
            if not domains:
                raise KeyError("official_domains")
            brands.append(
                Brand(
                    id=str(entry["id"]),
                    name=str(entry["name"]),
                    category=str(entry.get("category", "other")),
                    official_domains=domains,
                    names=tuple(entry.get("names", ())),
                    acronyms=tuple(entry.get("acronyms", ())),
                    tokens=tuple(str(t).lower() for t in entry.get("tokens", ())),
                    fuzzy=bool(entry.get("fuzzy", True)),
                )
            )
        except (KeyError, TypeError) as exc:
            raise BrandDataError(f"Invalid brand entry {entry!r}: missing or bad field {exc}") from exc
    return tuple(brands)


def load_brands(path: str | os.PathLike[str] | None = None) -> list[Brand]:
    """Load the brand list (cached)."""
    chosen = path or os.environ.get("PHISHLENS_BRANDS_FILE") or DEFAULT_BRANDS_FILE
    return list(_load(str(chosen)))


# --------------------------------------------------------------------------- #
# String helpers
# --------------------------------------------------------------------------- #
def levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein edit distance (insert / delete / substitute)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def is_transposition(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ only by two swapped adjacent characters."""
    if len(a) != len(b) or a == b:
        return False
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]


def visual_skeleton(text: str) -> str:
    """Collapse look-alike characters so 'b1at' and 'biat' compare equal."""
    for src, dst in _VISUAL_MULTI:
        text = text.replace(src, dst)
    return text.translate(_VISUAL_SINGLE)


def label_contains_token(text: str, token: str) -> bool:
    """Does a host fragment contain a brand keyword?

    Short keywords (< 5 chars, e.g. ``stb``) must be a whole hyphen/dot separated
    part (or glued to digits, as in ``biat24``) to avoid matching inside words.
    """
    text, token = text.lower(), token.lower()
    parts = [p for p in re.split(r"[^a-z0-9]+", text) if p]
    if token in parts:
        return True
    if len(token) >= 5:
        return token in text
    return any(re.fullmatch(rf"(?:{re.escape(token)}\d+|\d+{re.escape(token)})", p) for p in parts)


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
@dataclass
class BrandHit:
    """A brand reference found somewhere on a non-official site."""

    brand_id: str
    brand: str
    category: str
    location: str  # title | text | domain | subdomain | path | asset
    evidence: str
    count: int = 1


@dataclass
class Typosquat:
    """A host that imitates an official domain."""

    brand_id: str
    brand: str
    official_domain: str
    candidate: str
    technique: str  # edit-distance | transposition | repeated-letter | character-swap | homoglyph | tld-swap | hyphenation
    distance: int | None = None
    fragment: str = ""  # the imitating name, for example "biatt"


@dataclass
class EmbeddedOfficial:
    """The official domain appears as part of a longer, unrelated host."""

    brand_id: str
    brand: str
    official_domain: str
    host: str


@dataclass
class BrandAnalysis:
    """All brand findings for one analysis."""

    official_brand: str | None = None
    hits: list[BrandHit] = field(default_factory=list)
    typosquats: list[Typosquat] = field(default_factory=list)
    embedded_official: list[EmbeddedOfficial] = field(default_factory=list)
    targeted_brands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def hits_at(self, *locations: str) -> list[BrandHit]:
        return [h for h in self.hits if h.location in locations]


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def _typosquat(parts: HostParts, brand: Brand) -> Typosquat | None:
    """Best typosquatting match of the registered label (and subdomain parts) against ``brand``."""
    raw_label = parts.domain
    squashed = raw_label.replace("-", "")
    own = {squashed} | {p for p in raw_label.split("-") if len(p) >= 4}
    sub = {p for p in re.split(r"[.\-]", parts.subdomain) if len(p) >= 4}
    official = brand.official_domains[0]
    best: Typosquat | None = None

    def consider(fragment: str, shown: str, technique: str, distance: int) -> None:
        nonlocal best
        if best is None or distance < (best.distance or 0):
            best = Typosquat(brand.id, brand.name, official, shown, technique, distance, fragment)

    candidates = [(c, parts.registered_domain, False) for c in sorted(own)] + [(c, parts.host, True) for c in sorted(sub)]
    for cand, shown, from_subdomain in candidates:
        for target in brand.labels:
            if cand == target:
                # Same name under another extension, or the official name with hyphens inserted.
                if not from_subdomain and cand == squashed and brand.fuzzy and len(target) >= 5:
                    consider(cand, shown, "tld-swap" if raw_label == target else "hyphenation", 0)
                continue
            if (len(target) >= 4 or any(c in _SWAP_CHARS for c in cand)) and visual_skeleton(cand) == visual_skeleton(target):
                consider(cand, shown, "character-swap", 0)
                continue
            if not brand.fuzzy or len(target) < 4:
                continue
            if len(target) == 4:  # very short names: only a doubled letter (biat -> biatt) is convincing
                if len(cand) == 5 and any(cand[:i] + cand[i + 1:] == target for i in range(5)) and any(
                    cand[i] == cand[i + 1] for i in range(4)
                ):
                    consider(cand, shown, "repeated-letter", 1)
                continue
            threshold = 1 if len(target) <= 7 else 2
            if is_transposition(cand, target):
                consider(cand, shown, "transposition", 1)
                continue
            distance = levenshtein(cand, target)
            if 0 < distance <= threshold:
                doubled = distance == 1 and len(cand) == len(target) + 1 and any(cand[i] == cand[i + 1] for i in range(len(cand) - 1))
                consider(cand, shown, "repeated-letter" if doubled else "edit-distance", distance)
    return best


def _check_host(host: str, brands: Sequence[Brand], result: BrandAnalysis) -> None:
    parts = split_host(host)
    if parts.is_ip:
        return
    skeleton = host_skeleton(host)
    sparts = split_host(skeleton) if skeleton != host else parts
    padded = f".{skeleton}."
    for brand in brands:
        if parts.registered_domain in brand.official_domains:
            continue
        if sparts is not parts and sparts.registered_domain in brand.official_domains:
            # Look-alike characters spell the official domain exactly (for example a Cyrillic 'i' in biat.com.tn).
            result.typosquats.append(
                Typosquat(brand.id, brand.name, sparts.registered_domain, parts.registered_domain, "homoglyph", 0, sparts.domain)
            )
            continue
        for official in brand.official_domains:
            if f".{official}." in padded:
                result.embedded_official.append(EmbeddedOfficial(brand.id, brand.name, official, host))
                break
        squat = _typosquat(sparts, brand)
        if squat:
            result.typosquats.append(squat)
        for token in brand.tokens:
            if sparts.subdomain and label_contains_token(sparts.subdomain, token):
                result.hits.append(BrandHit(brand.id, brand.name, brand.category, "subdomain", f"'{token}' appears in the subdomain of {host}"))
                break
        for token in brand.tokens:
            if squat and squat.technique == "tld-swap":
                break
            if not label_contains_token(sparts.domain, token):
                continue
            exact_short = len(token) < 5 and sparts.domain.replace("-", "") == token
            if exact_short and not sparts.suffix.endswith("tn"):
                continue  # e.g. atb.com is a Canadian bank, not an impersonation of ATB Tunisie
            result.hits.append(BrandHit(brand.id, brand.name, brand.category, "domain", f"'{token}' appears in the domain {sparts.registered_domain}"))
            break


def analyze_brands(
    *,
    hosts: Sequence[str],
    final_host: str,
    paths: Sequence[str] = (),
    title: str | None = None,
    text: str = "",
    external_domains: Mapping[str, Mapping[str, int]] | None = None,
    favicon_domain: str | None = None,
    brands: Sequence[Brand] | None = None,
) -> BrandAnalysis:
    """Find brand impersonation signals.

    ``hosts`` are the entry and final hosts; ``final_host`` is where the page was
    actually served. Pages served from an official domain are never flagged.
    """
    brands = list(brands) if brands is not None else load_brands()
    result = BrandAnalysis()
    final_reg = registered_domain(final_host)
    for brand in brands:
        if final_reg in brand.official_domains and result.official_brand is None:
            result.official_brand = brand.name

    for host in dict.fromkeys(hosts):
        _check_host(host, brands, result)

    if result.official_brand is None:
        _check_content(result, brands, paths, title, text, external_domains or {}, favicon_domain)

    seen: set[tuple[str, str, str]] = set()
    unique_hits: list[BrandHit] = []
    for hit in result.hits:
        key = (hit.brand_id, hit.location, hit.evidence)
        if key not in seen:
            seen.add(key)
            unique_hits.append(hit)
    result.hits = unique_hits
    result.targeted_brands = _targeted(result)
    return result


def _check_content(
    result: BrandAnalysis,
    brands: Sequence[Brand],
    paths: Sequence[str],
    title: str | None,
    text: str,
    external_domains: Mapping[str, Mapping[str, int]],
    favicon_domain: str | None,
) -> None:
    folded_title = fold_text(title or "")
    folded_text = fold_text(text[:200_000])
    raw_text = text[:200_000]
    for brand in brands:
        if title and (
            any(r.search(folded_title) for r in brand.name_regexes)
            or any(r.search(title) for r in brand.acronym_regexes)
        ):
            result.hits.append(BrandHit(brand.id, brand.name, brand.category, "title", f"The page title mentions {brand.name}"))
        mentions = sum(len(r.findall(folded_text)) for r in brand.name_regexes) + sum(
            len(r.findall(raw_text)) for r in brand.acronym_regexes
        )
        if mentions:
            result.hits.append(
                BrandHit(brand.id, brand.name, brand.category, "text", f"{mentions} mention(s) of {brand.name} in the page text", mentions)
            )
        for path in paths:
            if any(label_contains_token(path, t) for t in brand.tokens):
                result.hits.append(BrandHit(brand.id, brand.name, brand.category, "path", f"The URL path references {brand.name}: {path[:80]}"))
                break
        for category, domains in external_domains.items():
            for domain, count in domains.items():
                if domain in brand.official_domains:
                    result.hits.append(
                        BrandHit(brand.id, brand.name, brand.category, "asset", f"{count} {category} reference(s) point to the official domain {domain}", count)
                    )
        if favicon_domain and favicon_domain in brand.official_domains:
            result.hits.append(
                BrandHit(brand.id, brand.name, brand.category, "asset", f"The favicon is loaded from the official domain {favicon_domain}")
            )


def _targeted(result: BrandAnalysis) -> list[str]:
    ordered: list[str] = []

    def add(name: str) -> None:
        if name not in ordered:
            ordered.append(name)

    for item in result.embedded_official:
        add(item.brand)
    for item in result.typosquats:
        add(item.brand)
    for location in ("domain", "subdomain", "title", "asset", "path", "text"):
        for hit in result.hits_at(location):
            add(hit.brand)
    return ordered

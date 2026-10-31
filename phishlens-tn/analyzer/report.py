"""Report rendering: single-analysis Markdown, batch Markdown summary and CSV.

All renderers tolerate partial or hand-edited input (they use ``.get``
everywhere) because the web export endpoint renders a result posted by the
client. URLs are *defanged* (``hxxps://evil[.]com``) so reports are safe to paste
into chats and tickets.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

BATCH_CSV_FIELDS = (
    "url", "final_url", "status", "score", "level", "targeted_brands", "signals", "top_signal",
    "registered_domain", "domain_age_days", "tls_issuer", "tls_valid_to", "redirects", "forms",
    "login_form", "error",
)


def defang(url: str) -> str:
    """Make a URL non-clickable: hxxps://example[.]com/path."""
    text = re.sub(r"^http", "hxxp", str(url), flags=re.IGNORECASE)
    match = re.match(r"^(hxxps?://)([^/?#]*)(.*)$", text, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1) + match.group(2).replace(".", "[.]") + match.group(3)
    return text.replace(".", "[.]")


def md_escape(value: Any, limit: int = 400) -> str:
    """Escape Markdown/HTML control characters and flatten whitespace."""
    text = " ".join(str(value if value is not None else "").split())[:limit]
    return re.sub(r"([\\`*_\[\]<>|#~])", r"\\\1", text)


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _row(cells: Iterable[Any]) -> str:
    return "| " + " | ".join(md_escape(c) for c in cells) + " |"


def _fmt_date(value: Any) -> str:
    return str(value)[:10] if value else "n/a"


# --------------------------------------------------------------------------- #
# Single analysis
# --------------------------------------------------------------------------- #
def render_markdown(result: dict[str, Any]) -> str:
    """Render one analysis result as a Markdown report."""
    result = _d(result)
    domain, tls, page, fetch = _d(result.get("domain")), _d(result.get("tls")), _d(result.get("page")), _d(result.get("fetch"))
    brands = _d(result.get("brands"))
    signals = [s for s in _l(result.get("signals")) if isinstance(s, dict)]
    lines: list[str] = [
        f"# PhishLens TN report: {md_escape(result.get('level', 'n/a'))} risk ({md_escape(result.get('score', 'n/a'))}/100)",
        "",
        f"**Verdict:** {md_escape(result.get('verdict', ''), 600)}",
        "",
        f"- **Analyzed URL:** `{defang(result.get('url', ''))}`",
        f"- **Final URL:** `{defang(result.get('final_url', ''))}`",
        f"- **Analyzed at:** {md_escape(result.get('analyzed_at', 'n/a'))}",
        f"- **HTTP status:** {md_escape(fetch.get('status_code', 'n/a'))}",
        f"- **Page title:** {md_escape(page.get('title') or 'n/a')}",
        f"- **Targeted brands:** {md_escape(', '.join(map(str, _l(brands.get('targeted_brands')))) or 'none detected')}",
        "",
        "## Signals",
        "",
    ]
    if signals:
        lines += ["| Weight | Signal | Why it matters |", "| ---: | --- | --- |"]
        lines += [_row([f"{s.get('weight', 0):+d}" if isinstance(s.get("weight"), int) else s.get("weight"), s.get("title"), s.get("explanation")]) for s in signals]
    else:
        lines.append("No indicators were triggered.")

    lines += ["", "## Domain", ""]
    rdap = _d(domain.get("rdap"))
    lines += [
        f"- Registered domain: `{md_escape(domain.get('registered_domain', 'n/a'))}`",
        f"- Subdomain levels: {md_escape(domain.get('subdomain_count', 'n/a'))}",
        f"- Suspicious TLD: {'yes' if domain.get('suspicious_tld') else 'no'}",
        f"- Punycode / look-alike characters: {'yes' if domain.get('punycode') or domain.get('homoglyph') else 'no'}",
        f"- Registered: {_fmt_date(rdap.get('registered_at'))} ({md_escape(rdap.get('age_days', 'age unknown'))} days)" if rdap.get("available") else f"- Registration data: unavailable ({md_escape(rdap.get('error', 'unknown'))})",
    ]

    lines += ["", "## Certificate", ""]
    if tls.get("available"):
        lines += [
            f"- Issuer: {md_escape(tls.get('issuer', 'n/a'))}",
            f"- Valid: {_fmt_date(tls.get('not_before'))} to {_fmt_date(tls.get('not_after'))} (age {md_escape(tls.get('age_days', 'n/a'))} days)",
            f"- Matches domain: {md_escape(tls.get('matches_domain'))}; trusted by default store: {md_escape(tls.get('trusted'))}",
            f"- SAN: {md_escape(', '.join(map(str, _l(tls.get('san'))[:10])) or 'none')}",
        ]
        if tls.get("verification_error"):
            lines.append(f"- Verification problem: {md_escape(tls.get('verification_error'))}")
    else:
        lines.append(f"Not available: {md_escape(tls.get('error') or 'n/a')}")

    lines += ["", "## Redirect chain", ""]
    chain = [h for h in _l(fetch.get("redirect_chain")) if isinstance(h, dict)]
    lines += [f"{i}. `{defang(h.get('url', ''))}` (HTTP {md_escape(h.get('status', '?'))})" for i, h in enumerate(chain, 1)] or ["No redirects."]

    lines += ["", "## Forms", ""]
    forms = [f for f in _l(page.get("forms")) if isinstance(f, dict)]
    if forms:
        lines += ["| # | Method | Posts to | Sensitive fields | Password |", "| ---: | --- | --- | --- | --- |"]
        lines += [
            _row([f.get("index"), str(f.get("method", "")).upper(), defang(f.get("resolved_action", "")), ", ".join(map(str, _l(f.get("sensitive_fields")))) or "none", "yes" if f.get("has_password") else "no"])
            for f in forms
        ]
    else:
        lines.append("No forms found.")

    lines += ["", "## External domains", ""]
    external = [e for e in _l(page.get("external_summary")) if isinstance(e, dict)]
    if external:
        lines += ["| Domain | References | Used for |", "| --- | ---: | --- |"]
        lines += [_row([e.get("domain"), e.get("count"), ", ".join(map(str, _l(e.get("categories"))))]) for e in external[:25]]
    else:
        lines.append("No external domains referenced.")

    notes = [n for n in _l(page.get("notes"))]
    if notes:
        lines += ["", "## Notes", ""] + [f"- {md_escape(n)}" for n in notes]
    lines += ["", "---", "_Generated by PhishLens TN. Static analysis only: no JavaScript executed, no form submitted. Built by Xavyr._", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Batch
# --------------------------------------------------------------------------- #
def result_to_csv_row(item: dict[str, Any]) -> dict[str, Any]:
    """Flatten one batch item (a result or an error record) for CSV."""
    if "error" in item and "score" not in item:
        error = _d(item.get("error"))
        return {**{k: "" for k in BATCH_CSV_FIELDS}, "url": item.get("url", ""), "status": "error", "error": f"{error.get('code', 'error')}: {error.get('message', '')}"}
    domain, tls, page, fetch = _d(item.get("domain")), _d(item.get("tls")), _d(item.get("page")), _d(item.get("fetch"))
    signals = [s for s in _l(item.get("signals")) if isinstance(s, dict) and s.get("weight", 0) > 0]
    return {
        "url": item.get("url", ""),
        "final_url": item.get("final_url", ""),
        "status": "ok",
        "score": item.get("score", ""),
        "level": item.get("level", ""),
        "targeted_brands": "; ".join(map(str, _l(_d(item.get("brands")).get("targeted_brands")))),
        "signals": "; ".join(str(s.get("id")) for s in signals),
        "top_signal": signals[0].get("title", "") if signals else "",
        "registered_domain": domain.get("registered_domain", ""),
        "domain_age_days": _d(domain.get("rdap")).get("age_days", ""),
        "tls_issuer": tls.get("issuer", "") or "",
        "tls_valid_to": _fmt_date(tls.get("not_after")) if tls.get("not_after") else "",
        "redirects": fetch.get("redirect_count", ""),
        "forms": len(_l(page.get("forms"))),
        "login_form": "yes" if page.get("has_login_form") else "no",
        "error": "",
    }


def render_batch_markdown(items: Sequence[dict[str, Any]], *, source: str = "") -> str:
    """Summary report for a batch run: targeted brands, common tricks, average score."""
    ok = [i for i in items if "score" in i]
    failed = [i for i in items if "score" not in i]
    scores = [int(i["score"]) for i in ok if isinstance(i.get("score"), (int, float))]
    average = sum(scores) / len(scores) if scores else 0.0
    levels = Counter(str(i.get("level")) for i in ok)
    brand_counter: Counter[str] = Counter()
    trick_titles: dict[str, str] = {}
    trick_counter: Counter[str] = Counter()
    for item in ok:
        brand_counter.update(map(str, _l(_d(item.get("brands")).get("targeted_brands"))))
        for signal in _l(item.get("signals")):
            if isinstance(signal, dict) and signal.get("weight", 0) > 0:
                trick_counter[str(signal.get("id"))] += 1
                trick_titles[str(signal.get("id"))] = str(signal.get("title"))

    lines = [
        "# PhishLens TN batch summary",
        "",
        f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Input:** {md_escape(source or 'n/a')}",
        f"- **URLs analyzed:** {len(ok)} of {len(items)} ({len(failed)} failed)",
        f"- **Average score:** {average:.1f}/100",
        "",
        "## Risk levels",
        "",
        "| Level | URLs |",
        "| --- | ---: |",
    ]
    lines += [f"| {lvl} | {levels.get(lvl, 0)} |" for lvl in ("Critical", "High", "Medium", "Low")]

    lines += ["", "## Top targeted brands", ""]
    if brand_counter:
        lines += ["| Brand | URLs |", "| --- | ---: |"] + [_row([b, c]) for b, c in brand_counter.most_common(10)]
    else:
        lines.append("No brand impersonation detected.")

    lines += ["", "## Most common tricks", ""]
    if trick_counter:
        lines += ["| Signal | URLs | Share |", "| --- | ---: | ---: |"]
        lines += [_row([trick_titles[k], c, f"{100 * c / max(1, len(ok)):.0f}%"]) for k, c in trick_counter.most_common(10)]
    else:
        lines.append("No risk signals were triggered.")

    lines += ["", "## Highest-risk URLs", ""]
    top = sorted(ok, key=lambda i: -int(i.get("score", 0)))[:10]
    if top:
        lines += ["| Score | Level | URL | Brands |", "| ---: | --- | --- | --- |"]
        lines += [_row([i.get("score"), i.get("level"), defang(i.get("url", "")), ", ".join(map(str, _l(_d(i.get("brands")).get("targeted_brands")))) or "-"]) for i in top]
    else:
        lines.append("No successful analyses.")

    if failed:
        lines += ["", "## Failed URLs", "", "| URL | Reason |", "| --- | --- |"]
        lines += [_row([defang(i.get("url", "")), _d(i.get("error")).get("message", "unknown error")]) for i in failed]
    lines += ["", "---", "_Generated by PhishLens TN. Static analysis only. Built by Xavyr._", ""]
    return "\n".join(lines)

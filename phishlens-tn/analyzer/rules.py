"""Built-in scoring rules.

HOW TO ADD A RULE
-----------------
1. Write a function that takes an :class:`~analyzer.scoring.Evidence` and returns
   ``Hit("plain-English explanation")`` when the rule fires, otherwise ``None``.
2. Decorate it with ``@rule(id=..., title=..., weight=..., category=..., icon=...)``.
   * ``id``       unique snake_case identifier (shown in exports and tests)
   * ``title``    short name shown on the signal card
   * ``weight``   risk points added when it fires (negative = mitigation)
   * ``category`` url | domain | redirect | tls | form | brand | content | trust
   * ``icon``     one of the names in ``static/js/app.js`` (alert, globe, lock,
                  clock, redirect, form, tag, type, code, link, shield, check)
3. Optionally return ``Hit(text, weight=N)`` to override the weight for a
   specific severity (see ``new_domain``). The function docstring is used as the
   rule's documentation (README table and ``cli.py rules``).

The engine isolates failures, so a rule that raises simply does not fire.
Weights are summed and clamped to 0-100; levels are Low <25, Medium <50,
High <75, Critical >=75.
"""
from __future__ import annotations

from .scoring import Evidence, Hit, rule

# --- tunables ---------------------------------------------------------------
NEW_DOMAIN_DAYS = (30, 90, 180)  # <30d: +25, <90d: +15, <180d: +6
ESTABLISHED_DOMAIN_DAYS = 5 * 365
RECENT_CERT_DAYS = (7, 30)  # <=7d: +10, <=30d: +5
MAX_REDIRECT_HOPS_BEFORE_FLAG = 3
EXCESSIVE_SUBDOMAINS = 3


def _both_domains(ev: Evidence):
    seen = []
    for domain in (ev.entry_domain, ev.domain):
        if domain.host not in [d.host for d in seen]:
            seen.append(domain)
    return seen


def _brand_ids_with_squat_or_embed(ev: Evidence) -> set[str]:
    return {t.brand_id for t in ev.brands.typosquats} | {e.brand_id for e in ev.brands.embedded_official}


# =========================================================================== #
# URL and domain
# =========================================================================== #
@rule(id="ip_address_host", title="Link uses a raw IP address", weight=20, category="url", icon="globe")
def ip_address_host(ev: Evidence) -> Hit | None:
    """The link points to a bare (or obfuscated) IP address instead of a domain name."""
    for domain in _both_domains(ev):
        if domain.is_ip or domain.obfuscated_ip:
            return Hit(f"The address {domain.host} is an IP address, not a domain name. Banks and operators almost never ask customers to sign in on a bare IP.")
    return None


@rule(id="userinfo_in_url", title="Link hides its real destination behind 'user@'", weight=25, category="url", icon="alert")
def userinfo_in_url(ev: Evidence) -> Hit | None:
    """The URL contains a username section before an @ sign, a classic disguise."""
    if ev.entry.has_userinfo:
        return Hit(f"Everything before the @ in the link is ignored by the browser. The link really goes to {ev.entry.host}, whatever the first part looks like.")
    return None


@rule(id="homoglyph_host", title="Domain uses look-alike characters", weight=30, category="domain", icon="type")
def homoglyph_host(ev: Evidence) -> Hit | None:
    """The host mixes scripts or uses characters that imitate Latin letters."""
    for domain in _both_domains(ev):
        if domain.homoglyph:
            return Hit(f"The domain {domain.unicode_host} contains characters that imitate ordinary letters (it reads as '{domain.skeleton}'). Attackers use this to fake a trusted name.")
    return None


@rule(id="punycode_host", title="Internationalised (punycode) domain", weight=8, category="domain", icon="type")
def punycode_host(ev: Evidence) -> Hit | None:
    """The host uses an xn-- punycode label without looking like a spoof."""
    for domain in _both_domains(ev):
        if domain.punycode and not domain.homoglyph:
            return Hit(f"The domain {domain.host} is encoded as punycode (shown as {domain.unicode_host}). Legitimate in some cases, but unusual for Tunisian banks and operators.")
    return None


@rule(id="suspicious_tld", title="Domain ends in a frequently abused TLD", weight=12, category="domain", icon="globe")
def suspicious_tld(ev: Evidence) -> Hit | None:
    """The top-level domain is one that is heavily used for throwaway registrations."""
    for domain in _both_domains(ev):
        if domain.suspicious_tld:
            return Hit(f"The .{domain.tld} extension is cheap and heavily used for short-lived scam sites. Official Tunisian brands use .tn or .com.tn.")
    return None


@rule(id="excessive_subdomains", title="Unusually deep subdomain chain", weight=10, category="domain", icon="globe")
def excessive_subdomains(ev: Evidence) -> Hit | None:
    """The host has three or more subdomain labels, often used to bury the real domain."""
    for domain in _both_domains(ev):
        if domain.subdomain_count >= EXCESSIVE_SUBDOMAINS:
            return Hit(f"The host {domain.host} has {domain.subdomain_count} subdomain levels. Phishers stack labels so a familiar name appears at the start while the real domain is {domain.registered_domain}.")
    return None


@rule(id="long_hyphenated_host", title="Long or heavily hyphenated domain", weight=8, category="domain", icon="globe")
def long_hyphenated_host(ev: Evidence) -> Hit | None:
    """The registered domain label has three or more hyphens or the host is very long."""
    for domain in _both_domains(ev):
        if not domain.is_ip and (domain.hyphen_count >= 3 or domain.length > 45):
            return Hit(f"The domain {domain.host} is long or full of hyphens, a pattern typical of throwaway names such as bank-secure-login-update.")
    return None


@rule(id="suspicious_host_keywords", title="Urgent or account words in the host name", weight=8, category="url", icon="alert")
def suspicious_host_keywords(ev: Evidence) -> Hit | None:
    """The host contains words such as secure, login, verify or compte."""
    if ev.brands.official_brand:
        return None
    found = sorted(set(ev.entry_features.host_keywords) | set(ev.features.host_keywords))
    if found:
        return Hit(f"The host name contains {', '.join(repr(k) for k in found)}. Real banks rarely put such words in their domain name.")
    return None


@rule(id="suspicious_path_keywords", title="Login or verification words in the URL path", weight=4, category="url", icon="link")
def suspicious_path_keywords(ev: Evidence) -> Hit | None:
    """The path or query contains words such as login, verify, password or carte."""
    if ev.brands.official_brand:
        return None
    found = sorted(set(ev.entry_features.path_keywords) | set(ev.features.path_keywords))
    if found:
        return Hit(f"The URL path mentions {', '.join(repr(k) for k in found[:5])}, wording often used to lure people into entering details.")
    return None


@rule(id="nonstandard_port", title="Non-standard port", weight=8, category="url", icon="link")
def nonstandard_port(ev: Evidence) -> Hit | None:
    """The link uses a port other than 80 or 443."""
    port = ev.entry_features.nonstandard_port or ev.features.nonstandard_port
    if port:
        return Hit(f"The link uses port {port}. Legitimate public sites almost always use the standard web ports.")
    return None


@rule(id="url_shortener", title="Link goes through a URL shortener", weight=10, category="url", icon="redirect")
def url_shortener(ev: Evidence) -> Hit | None:
    """The submitted link is hosted on a known URL shortening service."""
    if ev.entry_features.is_shortener:
        return Hit(f"{ev.entry.host} is a link shortener, which hides the real destination. The page actually loaded from {ev.final.host}.")
    return None


@rule(id="free_hosting", title="Hosted on a free or shared platform", weight=12, category="domain", icon="globe")
def free_hosting(ev: Evidence) -> Hit | None:
    """The page lives on a free hosting, site-builder or tunnelling service."""
    for domain in _both_domains(ev):
        if domain.free_hosting:
            return Hit(f"The page is hosted on {domain.free_hosting}, a platform where anyone can publish. A bank or operator would use its own domain.")
    return None


@rule(id="new_domain", title="Domain registered very recently", weight=25, category="domain", icon="clock")
def new_domain(ev: Evidence) -> Hit | None:
    """The registration date (RDAP) is under 30 days (+25), 90 days (+15) or 180 days (+6)."""
    age = ev.domain.rdap.age_days
    if not ev.domain.rdap.available or age is None:
        return None
    first, second, third = NEW_DOMAIN_DAYS
    if age < first:
        return Hit(f"{ev.domain.registered_domain} was registered only {age} day(s) ago. Most phishing domains are used within days of registration.", 25)
    if age < second:
        return Hit(f"{ev.domain.registered_domain} was registered {age} days ago, which is very young for a bank or operator site.", 15)
    if age < third:
        return Hit(f"{ev.domain.registered_domain} is only {age} days old.", 6)
    return None


@rule(id="established_domain", title="Long-established domain", weight=-10, category="trust", icon="check")
def established_domain(ev: Evidence) -> Hit | None:
    """Mitigation: the domain has been registered for more than five years."""
    age = ev.domain.rdap.age_days
    if ev.domain.rdap.available and age is not None and age >= ESTABLISHED_DOMAIN_DAYS:
        return Hit(f"{ev.domain.registered_domain} has been registered for about {age // 365} years, which lowers the risk somewhat.")
    return None


# =========================================================================== #
# Redirects
# =========================================================================== #
@rule(id="cross_domain_redirects", title="Redirected across different domains", weight=12, category="redirect", icon="redirect")
def cross_domain_redirects(ev: Evidence) -> Hit | None:
    """The redirect chain moves between different registered domains (+18 for two or more hops)."""
    hops = ev.cross_domain_hops
    if hops:
        path = " > ".join(dict.fromkeys(d for d in ev.chain_domains if d))
        return Hit(f"The link jumped across {hops + 1} different domains ({path}). Chains like this are used to hide the final page and dodge blocklists.", 18 if hops >= 2 else 12)
    return None


@rule(id="many_redirects", title="Long redirect chain", weight=8, category="redirect", icon="redirect")
def many_redirects(ev: Evidence) -> Hit | None:
    """The link needed three or more redirects before reaching the page."""
    if ev.fetch.redirect_count >= MAX_REDIRECT_HOPS_BEFORE_FLAG:
        return Hit(f"The link needed {ev.fetch.redirect_count} redirects before loading. Legitimate sites rarely chain this many.")
    return None


@rule(id="meta_refresh_external", title="Page auto-redirects to another domain", weight=12, category="redirect", icon="redirect")
def meta_refresh_external(ev: Evidence) -> Hit | None:
    """A <meta http-equiv=refresh> tag sends the visitor to a different domain."""
    refresh = ev.page.meta_refresh
    if refresh and refresh.external:
        return Hit(f"The page contains a meta refresh to {refresh.domain} after {refresh.delay:g}s, handing the visitor to another site.")
    return None


@rule(id="js_redirect", title="Script redirects the browser", weight=5, category="redirect", icon="code")
def js_redirect(ev: Evidence) -> Hit | None:
    """An inline script assigns window.location (read statically, never executed)."""
    if ev.page.js_redirect:
        return Hit(f"An inline script sets the page location to {ev.page.js_redirect[:80]}. The script was only read, never run.")
    return None


# =========================================================================== #
# Transport security
# =========================================================================== #
@rule(id="no_https", title="Page is not served over HTTPS", weight=12, category="tls", icon="lock")
def no_https(ev: Evidence) -> Hit | None:
    """The final page was loaded over plain HTTP."""
    if ev.final.scheme == "http":
        return Hit("The page is served without encryption. Anything typed into it can be read on the network.")
    return None


@rule(id="credentials_over_http", title="Credentials requested over plain HTTP", weight=25, category="tls", icon="lock")
def credentials_over_http(ev: Evidence) -> Hit | None:
    """A password or sensitive form lives on, or posts to, an unencrypted URL."""
    if not ev.asks_for_sensitive_data:
        return None
    if ev.final.scheme == "http":
        return Hit("This page asks for sensitive data without HTTPS protection.")
    for form in ev.credential_forms:
        if form.action_scheme == "http":
            return Hit(f"A sensitive form posts to {form.resolved_action[:80]} over plain HTTP.")
    return None


@rule(id="cert_not_trusted", title="Certificate not trusted by browsers", weight=15, category="tls", icon="lock")
def cert_not_trusted(ev: Evidence) -> Hit | None:
    """The certificate chain failed verification (self-signed, expired or unknown issuer)."""
    tls = ev.tls
    if tls.applicable and tls.trusted is False and tls.matches_domain is not False:
        reason = tls.verification_error or ev.fetch.tls_verify_error or "verification failed"
        return Hit(f"Browsers would warn about this certificate ({reason}). Reputable organisations keep valid certificates.")
    return None


@rule(id="cert_hostname_mismatch", title="Certificate issued for a different domain", weight=20, category="tls", icon="lock")
def cert_hostname_mismatch(ev: Evidence) -> Hit | None:
    """The certificate does not list the visited host name."""
    tls = ev.tls
    if tls.available and tls.matches_domain is False:
        names = ", ".join(tls.san[:3]) or (tls.subject_cn or "unknown")
        return Hit(f"The certificate covers {names}, not {ev.final.host}. This usually means a misconfigured or hijacked server.")
    return None


@rule(id="cert_recent", title="Certificate issued very recently", weight=10, category="tls", icon="clock")
def cert_recent(ev: Evidence) -> Hit | None:
    """The certificate was issued in the last 7 days (+10) or 30 days (+5)."""
    age = ev.tls.age_days
    if not ev.tls.available or age is None or age < 0:
        return None
    short, long_ = RECENT_CERT_DAYS
    if age <= short:
        return Hit(f"The certificate was issued {age} day(s) ago. Fresh certificates are typical of newly built scam sites (though many legitimate sites renew often).")
    if age <= long_:
        return Hit(f"The certificate is only {age} days old.", 5)
    return None


@rule(id="organization_certificate", title="Certificate names an organisation", weight=-5, category="trust", icon="shield")
def organization_certificate(ev: Evidence) -> Hit | None:
    """Mitigation: a trusted certificate that includes a verified organisation name."""
    tls = ev.tls
    if tls.available and tls.trusted and tls.matches_domain and tls.subject_org:
        return Hit(f"The certificate identifies the organisation '{tls.subject_org}', a mildly positive sign (such certificates take more effort to obtain).")
    return None


# =========================================================================== #
# Forms
# =========================================================================== #
@rule(id="login_form_present", title="Page asks for a password", weight=8, category="form", icon="form")
def login_form_present(ev: Evidence) -> Hit | None:
    """The page contains a password field."""
    if ev.page.has_login_form:
        return Hit("The page contains a password field. Many legitimate sites do too, so this only matters together with the other signals.")
    return None


@rule(id="form_posts_external", title="Form sends data to another domain", weight=28, category="form", icon="form")
def form_posts_external(ev: Evidence) -> Hit | None:
    """A form submits to a different registered domain (+28 if it collects credentials, +6 otherwise)."""
    external = [f for f in ev.page.forms if f.external_action and f.action_scheme in ("http", "https")]
    sensitive = [f for f in external if f.has_credentials]
    if sensitive:
        form = sensitive[0]
        return Hit(f"A form collecting {', '.join(form.sensitive_fields) or 'credentials'} posts to {form.action_domain}, not to {ev.domain.registered_domain}. Whatever is typed would be sent to a third party.", 28)
    if external:
        form = external[0]
        return Hit(f"A form submits to {form.action_domain}, a different site from the page itself.", 6)
    return None


@rule(id="form_mailto_action", title="Form submits by e-mail", weight=20, category="form", icon="form")
def form_mailto_action(ev: Evidence) -> Hit | None:
    """A form uses a mailto: action, sending its contents to an e-mail address."""
    if any(f.action_scheme == "mailto" for f in ev.page.forms):
        return Hit("A form is wired to a mailto: address. Real services process forms on their own servers, but this sends entries straight to someone's inbox.")
    return None


@rule(id="password_form_get", title="Password sent with the GET method", weight=15, category="form", icon="form")
def password_form_get(ev: Evidence) -> Hit | None:
    """A form with a password field uses GET, exposing it in the URL."""
    if any(f.has_password and f.method == "get" and f.action_scheme in ("http", "https") for f in ev.page.forms):
        return Hit("A password form uses the GET method, which puts the password in the URL. Sloppy, and typical of quickly built phishing kits.")
    return None


@rule(id="card_data_requested", title="Payment card details requested", weight=25, category="form", icon="form")
def card_data_requested(ev: Evidence) -> Hit | None:
    """A form asks for card number, expiry or CVV."""
    if any("card" in f.sensitive_fields for f in ev.page.forms):
        return Hit("The page asks for payment card details (number, expiry or CVV). Banks never request these through a link you received.")
    return None


@rule(id="otp_pin_requested", title="One-time code or PIN requested", weight=15, category="form", icon="form")
def otp_pin_requested(ev: Evidence) -> Hit | None:
    """A form asks for an SMS/OTP code or a PIN."""
    if any({"otp", "pin"} & set(f.sensitive_fields) for f in ev.page.forms):
        return Hit("The page asks for a one-time code or PIN. Attackers relay these in real time to take over accounts and approve payments.")
    return None


@rule(id="identity_data_requested", title="Identity or account numbers requested", weight=15, category="form", icon="form")
def identity_data_requested(ev: Evidence) -> Hit | None:
    """A form asks for CIN, passport, RIB/IBAN or date of birth."""
    if any("identity" in f.sensitive_fields for f in ev.page.forms):
        return Hit("The page asks for identity or account identifiers (such as CIN, RIB/IBAN or date of birth), which are valuable for fraud.")
    return None


@rule(id="exfil_service", title="Data is sent to a chat bot or form-collection service", weight=30, category="form", icon="alert")
def exfil_service(ev: Evidence) -> Hit | None:
    """The page code references Telegram bots, Discord webhooks or similar collection endpoints."""
    if ev.page.exfil_endpoints:
        return Hit(f"The page references {', '.join(ev.page.exfil_endpoints)}. Phishing kits use these to deliver stolen entries to the attacker.")
    return None


# =========================================================================== #
# Brand impersonation
# =========================================================================== #
@rule(id="official_domain_embedded", title="Official domain used as a decoy inside another host", weight=40, category="brand", icon="tag")
def official_domain_embedded(ev: Evidence) -> Hit | None:
    """The host contains an official brand domain, such as biat.com.tn.evil.com."""
    if ev.brands.embedded_official:
        item = ev.brands.embedded_official[0]
        return Hit(f"The host {item.host} starts with the official-looking {item.official_domain}, but the real domain is {ev.domain.registered_domain}. This is a textbook {item.brand} impersonation.")
    return None


@rule(id="typosquatting", title="Look-alike of an official brand domain", weight=38, category="brand", icon="type")
def typosquatting(ev: Evidence) -> Hit | None:
    """The domain is a near miss of an official brand domain (typo, swapped or look-alike characters)."""
    if not ev.brands.typosquats:
        return None
    squat = ev.brands.typosquats[0]
    how = {
        "edit-distance": f"differs from {squat.official_domain} by only {squat.distance} character(s)",
        "transposition": f"swaps two neighbouring letters of {squat.official_domain}",
        "repeated-letter": f"adds a repeated letter to {squat.official_domain}",
        "character-swap": f"replaces letters of {squat.official_domain} with look-alike characters (such as rn for m or 1 for l)",
        "homoglyph": f"spells {squat.official_domain} with look-alike Unicode characters",
        "tld-swap": f"copies the name of {squat.official_domain} under a different extension",
        "hyphenation": f"inserts hyphens into the name of {squat.official_domain}",
    }.get(squat.technique, f"imitates {squat.official_domain}")
    weight = 30 if squat.technique in ("tld-swap", "hyphenation") else 38
    name = squat.fragment or squat.candidate
    return Hit(f"The name '{name}' in {squat.candidate} {how}. It is not an official {squat.brand} domain.", weight)


@rule(id="brand_in_domain", title="Brand name inside an unrelated domain", weight=30, category="brand", icon="tag")
def brand_in_domain(ev: Evidence) -> Hit | None:
    """A brand keyword appears in the subdomain or registered domain, but the domain is not official."""
    covered = _brand_ids_with_squat_or_embed(ev)
    for hit in ev.brands.hits_at("domain", "subdomain"):
        if hit.brand_id in covered:
            continue
        return Hit(f"{hit.evidence}, but the domain is not an official {hit.brand} domain. Real brands do not host customer pages on someone else's domain.")
    return None


@rule(id="brand_in_title", title="Page title claims to be a brand", weight=18, category="brand", icon="tag")
def brand_in_title(ev: Evidence) -> Hit | None:
    """The page title names a Tunisian brand while the site is not on its official domain."""
    hits = ev.brands.hits_at("title")
    if hits:
        return Hit(f"{hits[0].evidence}, yet the page is served from {ev.domain.registered_domain} rather than an official {hits[0].brand} domain.")
    return None


@rule(id="brand_in_text", title="Brand repeatedly mentioned on an unofficial site", weight=8, category="brand", icon="tag")
def brand_in_text(ev: Evidence) -> Hit | None:
    """A brand is mentioned at least twice in the page text and the site is not official."""
    hits = [h for h in ev.brands.hits_at("text") if h.count >= 2]
    if hits:
        return Hit(f"{hits[0].evidence}. Impersonation pages repeat the brand name to look authentic.")
    return None


@rule(id="brand_in_path", title="Brand name in the URL path", weight=8, category="brand", icon="link")
def brand_in_path(ev: Evidence) -> Hit | None:
    """The URL path references a brand on a non-official domain."""
    hits = ev.brands.hits_at("path")
    if hits:
        return Hit(f"{hits[0].evidence}. Putting a brand in the path is a cheap way to look official.")
    return None


@rule(id="brand_assets_hotlinked", title="Images or styles copied live from the official site", weight=18, category="brand", icon="link")
def brand_assets_hotlinked(ev: Evidence) -> Hit | None:
    """Logos, scripts or the favicon are loaded straight from an official brand domain."""
    hits = ev.brands.hits_at("asset")
    if hits:
        return Hit(f"{hits[0].evidence}. Phishing kits often reuse the real site's logo to look authentic.")
    return None


@rule(id="brand_credential_combo", title="Brand impersonation combined with a login or payment form", weight=15, category="brand", icon="alert")
def brand_credential_combo(ev: Evidence) -> Hit | None:
    """Impersonation signals and a page that collects sensitive data appear together."""
    if not ev.asks_for_sensitive_data:
        return None
    strong = (
        ev.brands.typosquats
        or ev.brands.embedded_official
        or ev.brands.hits_at("domain", "subdomain", "title", "asset")
    )
    if strong and ev.brands.targeted_brands:
        return Hit(f"The page imitates {ev.brands.targeted_brands[0]} and also asks for sensitive information. That combination is the signature of credential phishing.")
    return None


# =========================================================================== #
# Page technique
# =========================================================================== #
@rule(id="suspicious_iframe", title="Embedded frame from another site", weight=8, category="content", icon="code")
def suspicious_iframe(ev: Evidence) -> Hit | None:
    """The page embeds an external iframe (+14 if it is hidden)."""
    external = [f for f in ev.page.iframes if f.external or f.srcdoc]
    hidden = [f for f in external if f.hidden]
    if hidden:
        return Hit(f"A hidden frame loads content from {hidden[0].domain or 'inline HTML'}. Invisible frames are used to track victims or load malicious content.", 14)
    if external:
        return Hit(f"The page embeds a frame from {external[0].domain or 'inline HTML'}.")
    return None


@rule(id="obfuscated_javascript", title="Obfuscated JavaScript", weight=10, category="content", icon="code")
def obfuscated_javascript(ev: Evidence) -> Hit | None:
    """Inline scripts combine several obfuscation techniques (eval, atob, long encoded strings ...)."""
    indicators = ev.page.script_indicators
    if len(indicators) >= 2:
        return Hit(f"Inline scripts use {', '.join(indicators)}. Hiding code this way is common in phishing kits. The code was only read, never executed.")
    return None


@rule(id="right_click_disabled", title="Right-click is disabled", weight=6, category="content", icon="code")
def right_click_disabled(ev: Evidence) -> Hit | None:
    """The page blocks the context menu to discourage inspection."""
    if ev.page.right_click_disabled:
        return Hit("The page blocks the right-click menu, a trick used to discourage visitors and researchers from inspecting it.")
    return None


@rule(id="external_favicon", title="Favicon loaded from another domain", weight=4, category="content", icon="link")
def external_favicon(ev: Evidence) -> Hit | None:
    """The site icon is hosted on a different registered domain."""
    page = ev.page
    if page.favicon_external and not ev.brands.hits_at("asset"):
        return Hit(f"The site icon comes from {page.favicon_domain}, a different domain from the page.")
    return None


@rule(id="noindex_meta", title="Page asks search engines not to index it", weight=3, category="content", icon="alert")
def noindex_meta(ev: Evidence) -> Hit | None:
    """A robots meta tag contains noindex on a page that asks for a login."""
    if ev.page.noindex and ev.asks_for_login:
        return Hit("A login page that asks to stay out of search results is typical of short-lived phishing pages.")
    return None


# =========================================================================== #
# Mitigations
# =========================================================================== #
@rule(id="official_domain", title="Served from an official brand domain", weight=-35, category="trust", icon="shield")
def official_domain(ev: Evidence) -> Hit | None:
    """Mitigation: the registered domain is listed as official for a known brand."""
    if ev.brands.official_brand:
        return Hit(f"{ev.domain.registered_domain} is listed as an official {ev.brands.official_brand} domain. Still confirm that you typed it yourself or reached it from the official app.")
    return None

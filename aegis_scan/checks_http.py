"""Passive header, cookie, CORS, and HTTP method checks for the landing page."""

from __future__ import annotations

import re
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from .registry import SCOPE_ENTRY, SOURCE_ACTIVE, SOURCE_PASSIVE, CheckContext, register

BASE_REMEDIATION = "Follow the OWASP Secure Headers Project guidance and retest after deployment."


def _entry(ctx: CheckContext):
    return ctx.entry or ctx.page


def _cookies(ctx: CheckContext) -> list[tuple[str, dict]]:
    page = _entry(ctx)
    if page is None:
        return []
    found: list[tuple[str, dict]] = []
    for raw in page.response.header_all("set-cookie"):
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            name = raw.split("=", 1)[0].strip()
            if name:
                found.append((name, {}))
            continue
        for name, morsel in jar.items():
            attrs: dict = {}
            for key in morsel.keys():
                value = morsel[key]
                if key.lower() in ("secure", "httponly"):
                    value = bool(value)
                if value:
                    attrs[key.lower()] = value
            found.append((name, attrs))
    return found


@register(
    "AEG-HDR-001",
    "Missing HTTP Strict Transport Security (HSTS)",
    "Headers",
    "medium",
    SCOPE_ENTRY,
    cwe="CWE-319",
    remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains over HTTPS.",
    description="Without HSTS, browsers may be downgraded to plaintext HTTP by an active attacker.",
    source=SOURCE_PASSIVE,
)
def missing_hsts(ctx: CheckContext):
    page = _entry(ctx)
    if page is None or urlsplit(page.url).scheme != "https":
        return None
    if page.response.header("strict-transport-security"):
        return None
    return ctx.finding(
        "No Strict-Transport-Security header on an HTTPS response.",
        url=page.url,
        source=SOURCE_PASSIVE,
    )


@register(
    "AEG-HDR-002",
    "Weak HSTS policy",
    "Headers",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-319",
    remediation="Use max-age of at least 15552000 seconds and add includeSubDomains.",
    description="A short HSTS lifetime or missing subdomain coverage weakens downgrade protection.",
    source=SOURCE_PASSIVE,
)
def weak_hsts(ctx: CheckContext):
    page = _entry(ctx)
    if page is None or urlsplit(page.url).scheme != "https":
        return None
    value = page.response.header("strict-transport-security")
    if not value:
        return None
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    max_age = int(match.group(1)) if match else 0
    if max_age >= 15552000 and "includesubdomains" in value.lower():
        return None
    issue = []
    if max_age < 15552000:
        issue.append(f"max-age={max_age}")
    if "includesubdomains" not in value.lower():
        issue.append("includeSubDomains missing")
    return ctx.finding(f"HSTS policy is weak ({', '.join(issue)}): {value}")


@register(
    "AEG-HDR-003",
    "Missing Content-Security-Policy",
    "Headers",
    "medium",
    SCOPE_ENTRY,
    cwe="CWE-693",
    remediation="Deploy a restrictive Content-Security-Policy with nonce- or hash-based scripts.",
    description="CSP limits the impact of XSS and third-party script injection.",
    source=SOURCE_PASSIVE,
)
def missing_csp(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    if page.response.header("content-security-policy"):
        return None
    return ctx.finding("No Content-Security-Policy header was returned.", url=page.url)


@register(
    "AEG-HDR-004",
    "Permissive Content-Security-Policy",
    "Headers",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-693",
    remediation="Remove unsafe-inline, unsafe-eval, and wildcard sources; adopt strict-dynamic with nonces.",
    description="A CSP containing unsafe directives or wildcards provides little XSS mitigation.",
    source=SOURCE_PASSIVE,
)
def weak_csp(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    value = page.response.header("content-security-policy")
    if not value:
        return None
    lowered = value.lower()
    issues = []
    if "unsafe-inline" in lowered:
        issues.append("unsafe-inline")
    if "unsafe-eval" in lowered:
        issues.append("unsafe-eval")
    if re.search(r"(?:default-src|script-src)[^;]*\s(?:\*|data:)\b", lowered):
        issues.append("wildcard/data script source")
    if not issues:
        return None
    return ctx.finding(
        f"Permissive CSP directives: {', '.join(issues)}. Policy: {value}",
        severity="medium" if "wildcard/data script source" in issues else "low",
    )


@register(
    "AEG-HDR-005",
    "Missing clickjacking protection",
    "Headers",
    "medium",
    SCOPE_ENTRY,
    cwe="CWE-1021",
    remediation="Set X-Frame-Options: DENY or add frame-ancestors 'none'/'self' to the CSP.",
    description="The page can be framed by an attacker, enabling UI-redress and clickjacking attacks.",
    source=SOURCE_PASSIVE,
)
def missing_frame_protection(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    xfo = page.response.header("x-frame-options")
    csp = page.response.header("content-security-policy").lower()
    if xfo or "frame-ancestors" in csp:
        return None
    return ctx.finding("Neither X-Frame-Options nor CSP frame-ancestors is present.")


@register(
    "AEG-HDR-006",
    "Missing X-Content-Type-Options",
    "Headers",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-693",
    remediation="Send X-Content-Type-Options: nosniff.",
    description="Browsers may MIME-sniff responses and execute content as a different type.",
    source=SOURCE_PASSIVE,
)
def missing_nosniff(ctx: CheckContext):
    page = _entry(ctx)
    if page is None or page.response.header("x-content-type-options"):
        return None
    return ctx.finding("No X-Content-Type-Options header was returned.")


@register(
    "AEG-HDR-007",
    "Missing or unsafe Referrer-Policy",
    "Headers",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-200",
    remediation="Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    description="Referrer leakage can expose tokens, internal paths, or sensitive query strings.",
    source=SOURCE_PASSIVE,
)
def referrer_policy(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    value = page.response.header("referrer-policy")
    if not value:
        return ctx.finding("No Referrer-Policy header was returned.")
    if "unsafe-url" in value.lower():
        return ctx.finding(f"Referrer-Policy permits full URL leakage: {value}", severity="medium")
    return None


@register(
    "AEG-HDR-008",
    "Missing Permissions-Policy",
    "Headers",
    "info",
    SCOPE_ENTRY,
    cwe="CWE-693",
    remediation="Declare Permissions-Policy to disable browser features the application does not need.",
    description="Feature-policy hardening gap; not directly exploitable on its own.",
    source=SOURCE_PASSIVE,
)
def permissions_policy(ctx: CheckContext):
    page = _entry(ctx)
    if page is None or page.response.header("permissions-policy"):
        return None
    return ctx.finding("No Permissions-Policy header was returned.")


@register(
    "AEG-HDR-009",
    "Missing Cross-Origin-Opener-Policy",
    "Headers",
    "info",
    SCOPE_ENTRY,
    cwe="CWE-693",
    remediation="Send Cross-Origin-Opener-Policy: same-origin on sensitive pages.",
    description="Without COOP, a cross-origin opener may retain a window reference to the page.",
    source=SOURCE_PASSIVE,
)
def missing_coop(ctx: CheckContext):
    page = _entry(ctx)
    if page is None or page.response.header("cross-origin-opener-policy"):
        return None
    return ctx.finding("No Cross-Origin-Opener-Policy header was returned.")


@register(
    "AEG-HDR-010",
    "Missing Cross-Origin-Embedder-Policy",
    "Headers",
    "info",
    SCOPE_ENTRY,
    cwe="CWE-693",
    remediation="Send Cross-Origin-Embedder-Policy: require-corp when cross-origin isolation is needed.",
    description="Cross-origin isolation hardening gap.",
    source=SOURCE_PASSIVE,
)
def missing_coep(ctx: CheckContext):
    page = _entry(ctx)
    if page is None or page.response.header("cross-origin-embedder-policy"):
        return None
    return ctx.finding("No Cross-Origin-Embedder-Policy header was returned.")


@register(
    "AEG-HDR-011",
    "Server version disclosure",
    "Headers",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-200",
    remediation="Remove or generalize the Server header at the reverse proxy.",
    description="Version strings help attackers select exploits for known server builds.",
    source=SOURCE_PASSIVE,
)
def server_banner(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    value = page.response.header("server")
    if not value:
        return None
    if not re.search(r"\d", value) and "/" not in value:
        return None
    return ctx.finding(f"Server header discloses software/build: {value}")


@register(
    "AEG-HDR-012",
    "Technology disclosure via X-Powered-By",
    "Headers",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-200",
    remediation="Disable X-Powered-By and similar framework banners.",
    description="Framework fingerprinting lowers the cost of targeted exploitation.",
    source=SOURCE_PASSIVE,
)
def powered_by(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    value = page.response.header("x-powered-by")
    if not value:
        return None
    return ctx.finding(f"X-Powered-By: {value}")


@register(
    "AEG-HDR-013",
    "ASP.NET version disclosure",
    "Headers",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-200",
    remediation="Remove X-AspNet-Version / X-AspNetMvc-Version in web.config or IIS.",
    description="Exact runtime versions make framework-specific exploit selection easier.",
    source=SOURCE_PASSIVE,
)
def aspnet_version(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    values = []
    for name in ("x-aspnet-version", "x-aspnetmvc-version"):
        value = page.response.header(name)
        if value:
            values.append(f"{name}: {value}")
    if not values:
        return None
    return ctx.finding("; ".join(values))


@register(
    "AEG-CORS-001",
    "CORS wildcard allows any origin",
    "CORS",
    "medium",
    SCOPE_ENTRY,
    cwe="CWE-942",
    remediation="Whitelist trusted origins and never combine wildcard origins with credentials.",
    description="A wildcard Access-Control-Allow-Origin exposes readable responses to any site.",
    source=SOURCE_PASSIVE,
)
def cors_wildcard(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    origin = "https://aegis.invalid"
    response = ctx.client.get(page.url, headers={"Origin": origin}, follow=False)
    allow_origin = response.header("access-control-allow-origin")
    if allow_origin.strip() != "*":
        return None
    credentials = response.header("access-control-allow-credentials").lower() == "true"
    return ctx.finding(
        "Access-Control-Allow-Origin: *"
        + (" with Access-Control-Allow-Credentials: true" if credentials else ""),
        severity="high" if credentials else "medium",
    )


@register(
    "AEG-CORS-002",
    "CORS reflects arbitrary Origin",
    "CORS",
    "high",
    SCOPE_ENTRY,
    cwe="CWE-942",
    remediation="Validate the Origin header against a strict allowlist; never echo it unconditionally.",
    description="Reflecting any origin can let an attacker-controlled site read authenticated responses.",
    source=SOURCE_ACTIVE,
)
def cors_reflected(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    origin = "https://aegis.invalid"
    response = ctx.client.get(page.url, headers={"Origin": origin}, follow=False)
    allow_origin = response.header("access-control-allow-origin").strip()
    if allow_origin != origin:
        return None
    credentials = response.header("access-control-allow-credentials").lower() == "true"
    confirm = ctx.client.get(page.url, headers={"Origin": "https://aegis2.invalid"}, follow=False)
    if confirm.header("access-control-allow-origin").strip() != "https://aegis2.invalid":
        return None
    return ctx.finding(
        f"Server reflected Origin {origin!r}"
        + (" and allows credentials." if credentials else "."),
        severity="high" if credentials else "medium",
    )


@register(
    "AEG-CORS-003",
    "CORS accepts the null Origin",
    "CORS",
    "medium",
    SCOPE_ENTRY,
    cwe="CWE-942",
    remediation="Reject the null Origin and use an explicit allowlist.",
    description="Sandboxed iframes and some local files send Origin: null.",
    source=SOURCE_ACTIVE,
)
def cors_null(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    response = ctx.client.get(page.url, headers={"Origin": "null"}, follow=False)
    if response.header("access-control-allow-origin").strip().lower() != "null":
        return None
    return ctx.finding("Access-Control-Allow-Origin: null was returned for a null Origin.")


@register(
    "AEG-HTTP-001",
    "Dangerous HTTP methods advertised",
    "HTTP Methods",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-650",
    remediation="Disable PUT/DELETE/PATCH at the edge unless explicitly required and authenticated.",
    description="Write-capable verbs on a public endpoint expand the attack surface.",
    source=SOURCE_ACTIVE,
)
def dangerous_methods(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    response = ctx.client.options(page.url, follow=False)
    value = response.header("allow") or response.header("public")
    if not value:
        return None
    allowed = {item.strip().upper() for item in re.split(r"[,\s]+", value) if item.strip()}
    risky = sorted(allowed & {"PUT", "DELETE", "PATCH"})
    if not risky:
        return None
    return ctx.finding(f"Allow header advertises: {', '.join(risky)} ({value})")


@register(
    "AEG-HTTP-002",
    "HTTP TRACE method enabled",
    "HTTP Methods",
    "medium",
    SCOPE_ENTRY,
    cwe="CWE-693",
    remediation="Disable TRACE at the web server or reverse proxy.",
    description="TRACE can be abused for Cross-Site Tracing (XST) in legacy browser scenarios.",
    source=SOURCE_ACTIVE,
)
def trace_enabled(ctx: CheckContext):
    page = _entry(ctx)
    if page is None:
        return None
    response = ctx.client.trace(page.url, follow=False)
    if response.status != 200:
        return None
    looks_like_trace = (
        "message/http" in response.content_type.lower()
        or "trace /" in response.text.lower()
        or "aegis" in response.text.lower()[:500]
    )
    if not looks_like_trace:
        return None
    return ctx.finding("TRACE returned HTTP 200 with echoed request content.")


@register(
    "AEG-CKE-001",
    "Cookie without Secure flag",
    "Cookies",
    "medium",
    SCOPE_ENTRY,
    cwe="CWE-614",
    remediation="Mark all session and authentication cookies Secure.",
    description="Cookies without Secure can be transmitted over plaintext HTTP.",
    source=SOURCE_PASSIVE,
)
def cookie_secure(ctx: CheckContext):
    page = _entry(ctx)
    if page is None or urlsplit(page.url).scheme != "https":
        return None
    missing = [name for name, attrs in _cookies(ctx) if not attrs.get("secure")]
    if not missing:
        return None
    return ctx.finding(f"Cookies missing Secure: {', '.join(sorted(set(missing)))}", parameter=", ".join(sorted(set(missing))))


@register(
    "AEG-CKE-002",
    "Cookie without HttpOnly flag",
    "Cookies",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-1004",
    remediation="Mark authentication and session cookies HttpOnly.",
    description="HttpOnly prevents JavaScript from reading cookies after an XSS foothold.",
    source=SOURCE_PASSIVE,
)
def cookie_httponly(ctx: CheckContext):
    missing = [name for name, attrs in _cookies(ctx) if not attrs.get("httponly")]
    if not missing:
        return None
    return ctx.finding(
        f"Cookies missing HttpOnly: {', '.join(sorted(set(missing)))}",
        parameter=", ".join(sorted(set(missing))),
    )


@register(
    "AEG-CKE-003",
    "Cookie without SameSite protection",
    "Cookies",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-1275",
    remediation="Set SameSite=Lax or Strict (and Secure with SameSite=None).",
    description="Missing SameSite increases exposure to cross-site request forgery.",
    source=SOURCE_PASSIVE,
)
def cookie_samesite(ctx: CheckContext):
    risky = []
    for name, attrs in _cookies(ctx):
        same_site = str(attrs.get("samesite", "")).lower()
        if same_site not in {"lax", "strict"}:
            if not (same_site == "none" and attrs.get("secure")):
                risky.append(name)
    if not risky:
        return None
    return ctx.finding(
        f"Cookies missing a strong SameSite attribute: {', '.join(sorted(set(risky)))}",
        parameter=", ".join(sorted(set(risky))),
    )


@register(
    "AEG-CKE-004",
    "Cookie scoped to a parent domain",
    "Cookies",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-1275",
    remediation="Avoid Domain attributes unless subdomains must share the cookie; prefer host-only cookies.",
    description="Parent-domain cookies are exposed to every subdomain, including less trusted ones.",
    source=SOURCE_PASSIVE,
)
def cookie_domain(ctx: CheckContext):
    parent = []
    for name, attrs in _cookies(ctx):
        domain = str(attrs.get("domain", ""))
        if domain.startswith(".") and domain.strip("."):
            parent.append(f"{name} (Domain={domain})")
    if not parent:
        return None
    return ctx.finding(f"Parent-domain cookies: {', '.join(sorted(set(parent)))}")


@register(
    "AEG-CKE-005",
    "Cookie prefix constraints violated",
    "Cookies",
    "low",
    SCOPE_ENTRY,
    cwe="CWE-614",
    remediation="Honor __Host- (Secure, Path=/, no Domain) and __Secure- (Secure) cookie prefixes.",
    description="Violating cookie prefix rules can let sibling origins overwrite security cookies.",
    source=SOURCE_PASSIVE,
)
def cookie_prefix(ctx: CheckContext):
    issues = []
    for name, attrs in _cookies(ctx):
        lowered = name.lower()
        if lowered.startswith("__host-"):
            okay = attrs.get("secure") and attrs.get("path") == "/" and not attrs.get("domain")
            if not okay:
                issues.append(name)
        elif lowered.startswith("__secure-") and not attrs.get("secure"):
            issues.append(name)
    if not issues:
        return None
    return ctx.finding(f"Prefix rules violated: {', '.join(sorted(set(issues)))}")


__all__ = []

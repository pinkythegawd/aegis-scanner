"""Content, form, and client-side exposure checks."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .registry import SCOPE_FORM, SCOPE_PAGE, SOURCE_PASSIVE, CheckContext, register

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
COMMENT_SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)"
    r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-]{6,}"
)
DEBUG_RE = re.compile(
    r"(?i)(Traceback \(most recent call last\)|Fatal error: Uncaught|Parse error:.*? in "
    r"|Stack trace:|Server Error in '/' Application|Whoops, looks like something went wrong"
    r"|DEBUG\s*=\s*True|at [\w.$]+\([\w.$]+:\d+\)|System\.[A-Za-z.]+Exception)"
)
SOURCE_MAP_RE = re.compile(r"(?i)sourceMappingURL\s*=\s*([^\s*]+)")
DOM_SOURCES_RE = re.compile(
    r"(?i)(location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)"
    r"|window\.name|event\.data|postMessage)"
)
DOM_SINKS_RE = re.compile(
    r"(?i)(innerHTML|outerHTML|document\.write(?:ln)?\s*\(|eval\s*\("
    r"|set(?:Timeout|Interval)\s*\(\s*['\"]|insertAdjacentHTML|\.html\s*\()"
)
KNOWN_SECRETS = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "medium"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "high"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "high"),
)
GENERIC_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|auth[_-]?token|access[_-]?token|password)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
)


@register(
    "AEG-CNT-001",
    "Mixed content on HTTPS page",
    "Content",
    "medium",
    SCOPE_PAGE,
    cwe="CWE-319",
    remediation="Load every script, stylesheet, image, and frame over HTTPS.",
    description="Plaintext subresources on an HTTPS page can be modified by a network attacker.",
    source=SOURCE_PASSIVE,
)
def mixed_content(ctx: CheckContext):
    page = ctx.page
    if page is None or urlsplit(page.url).scheme != "https":
        return None
    insecure = sorted({item.url for item in page.parsed.resources if item.url.lower().startswith("http://")})
    if not insecure:
        return None
    return ctx.finding("Insecure subresources: " + ", ".join(insecure[:4]), url=page.url)


@register(
    "AEG-CNT-002",
    "Form submits credentials over HTTP",
    "Content",
    "medium",
    SCOPE_PAGE,
    cwe="CWE-319",
    remediation="Use HTTPS for all form actions and redirect HTTP to HTTPS.",
    description="A secure page that posts to HTTP leaks form contents in transit.",
    source=SOURCE_PASSIVE,
)
def insecure_form_action(ctx: CheckContext):
    page = ctx.page
    if page is None or urlsplit(page.url).scheme != "https":
        return None
    insecure = [form.action for form in page.parsed.forms if form.action.lower().startswith("http://")]
    if not insecure:
        return None
    return ctx.finding("Form actions use HTTP: " + ", ".join(sorted(set(insecure))[:4]))


@register(
    "AEG-FRM-001",
    "Password form submitted with GET",
    "Forms",
    "high",
    SCOPE_FORM,
    cwe="CWE-598",
    remediation="Submit authentication forms with POST and TLS; never place secrets in a URL.",
    description="GET credentials are stored in browser history, proxies, and server access logs.",
)
def password_form_get(ctx: CheckContext):
    form = ctx.form
    if form is None or not form.has_password or form.method != "GET":
        return None
    return ctx.finding(
        "A form containing a password input uses method=GET.",
        url=form.action,
        parameter="form",
        method="GET",
    )


@register(
    "AEG-FRM-002",
    "Password field permits autocomplete",
    "Forms",
    "low",
    SCOPE_FORM,
    cwe="CWE-522",
    remediation="Set autocomplete=\"off\" or \"new-password\" on sensitive password inputs.",
    description="Password-manager/autofill behavior on shared devices can expose credentials.",
)
def password_autocomplete(ctx: CheckContext):
    form = ctx.form
    if form is None:
        return None
    offenders = []
    for field in form.fields:
        if field.type.lower() != "password":
            continue
        autocomplete = field.attributes.get("autocomplete", "").lower()
        if autocomplete not in {"off", "new-password", "current-password", "one-time-code"}:
            offenders.append(field.name)
    if not offenders:
        return None
    return ctx.finding(
        f"Password fields without restrictive autocomplete: {', '.join(offenders)}",
        url=form.action,
        parameter=", ".join(offenders),
        method=form.method,
    )


@register(
    "AEG-FRM-003",
    "POST form without anti-CSRF token",
    "Forms",
    "low",
    SCOPE_FORM,
    cwe="CWE-352",
    remediation="Use per-session anti-CSRF tokens and SameSite cookies for state-changing forms.",
    description="A POST form without a recognizable token may be vulnerable to cross-site request forgery.",
)
def csrf_token_missing(ctx: CheckContext):
    form = ctx.form
    if form is None or form.method != "POST":
        return None
    if not form.fields or form.token_fields():
        return None
    fields = ", ".join(sorted({field.name for field in form.fields if field.name})[:8])
    return ctx.finding(
        f"No anti-CSRF token field detected. Fields: {fields}",
        url=form.action,
        parameter="csrf",
        method="POST",
        confidence="medium",
    )


@register(
    "AEG-CNT-003",
    "Source map exposed",
    "Content",
    "low",
    SCOPE_PAGE,
    cwe="CWE-540",
    remediation="Remove .map references and production source maps from public builds.",
    description="Source maps reconstruct frontend code, comments, and internal API routes.",
    source=SOURCE_PASSIVE,
)
def source_map(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    hits = [script.src for script in page.parsed.scripts if script.src.lower().endswith(".map")]
    for inline in page.parsed.inline_scripts:
        for match in SOURCE_MAP_RE.finditer(inline):
            hits.append(match.group(1)[:160])
    if not hits:
        return None
    return ctx.finding("Source map references: " + ", ".join(sorted(set(hits))[:4]))


@register(
    "AEG-CNT-004",
    "Generator version disclosed",
    "Content",
    "low",
    SCOPE_PAGE,
    cwe="CWE-200",
    remediation="Remove versioned generator metadata from production HTML.",
    description="CMS/framework versions help attackers choose matching exploits.",
    source=SOURCE_PASSIVE,
)
def generator_version(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    generator = page.parsed.generator or page.parsed.meta.get("generator", "")
    if not generator or not re.search(r"\d", generator):
        return None
    return ctx.finding(f"Meta generator: {generator}")


@register(
    "AEG-CNT-005",
    "Email addresses exposed",
    "Content",
    "info",
    SCOPE_PAGE,
    cwe="CWE-200",
    remediation="Obfuscate or remove personal email addresses from public pages where appropriate.",
    description="Harvestable addresses enable phishing and spam; low direct security impact.",
    source=SOURCE_PASSIVE,
)
def email_disclosure(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    found = sorted(
        {
            email
            for email in EMAIL_RE.findall(page.response.text or "")
            if not email.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js"))
            and not email.lower().startswith("support@aegis")
        }
    )
    if not found:
        return None
    return ctx.finding("Addresses: " + ", ".join(found[:5]))


@register(
    "AEG-CNT-006",
    "Secrets in HTML comments",
    "Content",
    "medium",
    SCOPE_PAGE,
    cwe="CWE-615",
    remediation="Remove credentials and internal notes from production markup; use build-time stripping.",
    description="Developer comments sometimes survive deployment and leak secrets or infrastructure details.",
    source=SOURCE_PASSIVE,
)
def comment_secrets(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    hits = [comment for comment in page.parsed.comments if COMMENT_SECRET_RE.search(comment)]
    if not hits:
        return None
    return ctx.finding("Sensitive comment: " + hits[0][:300], confidence="high")


@register(
    "AEG-CNT-007",
    "Verbose error output",
    "Content",
    "medium",
    SCOPE_PAGE,
    cwe="CWE-209",
    remediation="Disable debug mode and return generic error pages in production.",
    description="Stack traces reveal file paths, framework versions, queries, and internal structure.",
    source=SOURCE_PASSIVE,
)
def verbose_errors(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    match = DEBUG_RE.search(page.response.text or "")
    if not match:
        return None
    severity = "high" if "traceback" in match.group(0).lower() or "stack trace" in match.group(0).lower() else "medium"
    return ctx.finding(f"Error/debug signature: {match.group(0)[:160]}", severity=severity)


@register(
    "AEG-CNT-008",
    "DOM XSS source-to-sink pattern",
    "Content",
    "medium",
    SCOPE_PAGE,
    cwe="CWE-79",
    remediation="Avoid passing location/document sources into HTML sinks; use safe DOM APIs and sanitizers.",
    description="Inline JavaScript reads a controllable source and writes to an HTML sink (manual review required).",
    source=SOURCE_PASSIVE,
)
def dom_xss_sink(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    for inline in page.parsed.inline_scripts:
        source = DOM_SOURCES_RE.search(inline)
        sink = DOM_SINKS_RE.search(inline)
        if source and sink:
            return ctx.finding(
                f"Source {source.group(1)!r} and sink {sink.group(1)!r} occur in inline JavaScript.",
                confidence="low",
            )
    return None


@register(
    "AEG-CNT-009",
    "Secret or API token in client-side code",
    "Content",
    "high",
    SCOPE_PAGE,
    cwe="CWE-798",
    remediation="Move secrets server-side; rotate any credential exposed in shipped JavaScript.",
    description="Known token formats or hardcoded credentials are readable by every visitor.",
    source=SOURCE_PASSIVE,
)
def inline_secret(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    haystack = "\n".join(page.parsed.inline_scripts)
    for name, pattern, severity in KNOWN_SECRETS:
        match = pattern.search(haystack)
        if match:
            masked = match.group(0)[:6] + "…"
            return ctx.finding(f"{name} detected in inline script ({masked})", severity=severity)
    generic = GENERIC_SECRET_RE.search(haystack)
    if generic:
        return ctx.finding(
            f"Hardcoded secret-like value in inline script: {generic.group(1)[:8]}…",
            severity="medium",
            confidence="medium",
        )
    return None


@register(
    "AEG-CNT-010",
    "Third-party script without Subresource Integrity",
    "Content",
    "low",
    SCOPE_PAGE,
    cwe="CWE-353",
    remediation="Add integrity and crossorigin attributes to external scripts served from CDNs.",
    description="Without SRI, a compromised third-party host can inject arbitrary JavaScript.",
    source=SOURCE_PASSIVE,
)
def missing_sri(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    page_host = (urlsplit(page.url).hostname or "").lower()
    offenders = []
    for script in page.parsed.scripts:
        host = (urlsplit(script.src).hostname or "").lower()
        if host and host != page_host and not script.integrity:
            offenders.append(script.src)
    if not offenders:
        return None
    return ctx.finding("External scripts without integrity: " + ", ".join(sorted(set(offenders))[:4]))


@register(
    "AEG-CNT-011",
    "Reverse tabnabbing via target=_blank",
    "Content",
    "info",
    SCOPE_PAGE,
    cwe="CWE-1022",
    remediation="Add rel=\"noopener noreferrer\" to external links that open a new tab.",
    description="The opened page can access window.opener and navigate the original tab.",
    source=SOURCE_PASSIVE,
)
def reverse_tabnabbing(ctx: CheckContext):
    page = ctx.page
    if page is None:
        return None
    offenders = []
    for anchor in page.parsed.anchors:
        if "_blank" not in anchor.target.lower():
            continue
        rel = anchor.rel.lower()
        if "noopener" not in rel and "noreferrer" not in rel:
            offenders.append(anchor.href)
    if not offenders:
        return None
    return ctx.finding("Links without noopener: " + ", ".join(sorted(set(offenders))[:4]))


__all__ = []

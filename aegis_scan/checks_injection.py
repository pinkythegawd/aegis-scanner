"""Proof-based active injection checks: SQLi, XSS, CMDi, XXE, and more."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import payloads as P
from .models import Response
from .registry import (
    SCOPE_PARAM,
    SCOPE_TARGET,
    SOURCE_ACTIVE,
    CheckContext,
    register,
)


def _baseline_text(ctx: CheckContext) -> str:
    if ctx.param_baseline is not None:
        return ctx.param_baseline.text
    if ctx.page is not None:
        return ctx.page.response.text
    return ""


def _send(ctx: CheckContext, value: str, *, follow: bool = True, headers: dict | None = None) -> Response:
    if ctx.mutate is None:
        return Response(url=ctx.target.url, error="mutation engine unavailable")
    return ctx.mutate(value, follow=follow, headers=headers)


def _is_html_response(response: Response) -> bool:
    ctype = response.content_type.lower()
    return not ctype or "html" in ctype


def _length(value: str) -> int:
    return len(value or "")


# ---------------------------------------------------------------------- SQLi
@register(
    "AEG-SQLI-001",
    "SQL injection — error-based",
    "Injection",
    "critical",
    SCOPE_PARAM,
    cwe="CWE-89",
    remediation="Use parameterized queries/prepared statements and suppress database errors.",
    description="A crafted quote sequence triggered a database error signature absent from the control response.",
)
def sqli_error(ctx: CheckContext):
    baseline = _baseline_text(ctx)
    suffixes = P.SQL_ERROR_SUFFIXES_DEEP if ctx.config.deep else P.SQL_ERROR_SUFFIXES
    for index, (name, suffix) in enumerate(suffixes):
        if ctx.config.max_params and index >= 6 and not ctx.config.deep:
            break
        test_value = f"{ctx.param.base_value}{suffix}"
        response = _send(ctx, test_value)
        if response.error or not response.text:
            continue
        signature = P.find_sql_error(response.text, baseline)
        if not signature:
            continue
        confirm = _send(ctx, test_value)
        if confirm.error or not P.find_sql_error(confirm.text, baseline):
            continue
        return ctx.finding(
            f"{signature} appeared after injecting {name}; the control response had no SQL error.",
            payload=test_value,
            confidence="high",
        )
    return None


@register(
    "AEG-SQLI-002",
    "SQL injection — boolean differential",
    "Injection",
    "high",
    SCOPE_PARAM,
    cwe="CWE-89",
    remediation="Use parameterized queries/prepared statements and consistent error handling.",
    description="A true/false SQL condition produced materially different responses while the control stayed stable.",
)
def sqli_boolean(ctx: CheckContext):
    baseline = _baseline_text(ctx)
    if not baseline or len(baseline) < 20:
        return None
    pairs = P.SQL_BOOLEAN_PAIRS if ctx.config.deep else P.SQL_BOOLEAN_PAIRS[:2]
    base_len = _length(baseline)
    for name, true_suffix, false_suffix in pairs:
        true_value = f"{ctx.param.base_value}{true_suffix}"
        false_value = f"{ctx.param.base_value}{false_suffix}"
        true_response = _send(ctx, true_value)
        false_response = _send(ctx, false_value)
        if true_response.error or false_response.error:
            continue
        if not (200 <= true_response.status < 300 and 200 <= false_response.status < 300):
            continue
        true_len = _length(true_response.text)
        false_len = _length(false_response.text)
        delta = abs(true_len - false_len)
        threshold = max(32, int(base_len * 0.03))
        true_stable = (
            abs(true_len - base_len) <= max(240, int(base_len * 0.08))
            and P.similarity(true_response.text, baseline) >= 0.97
        )
        false_differs = (
            delta >= threshold
            and (abs(false_len - base_len) >= max(24, int(base_len * 0.015))
                 or P.similarity(false_response.text, baseline) <= 0.95)
        )
        if not (true_stable and false_differs):
            continue
        # Re-confirm the differential to reject transient/dynamic pages.
        true_again = _send(ctx, true_value)
        false_again = _send(ctx, false_value)
        if true_again.error or false_again.error:
            continue
        delta2 = abs(_length(true_again.text) - _length(false_again.text))
        if delta2 < threshold or not P.similarity(true_again.text, baseline) >= 0.96:
            continue
        return ctx.finding(
            f"{name} boolean pair changed response length by {delta} bytes "
            f"(true={true_len}, false={false_len}, control={base_len}); differential reproduced.",
            payload=f"{true_value}  vs  {false_value}",
            confidence="medium",
        )
    return None


@register(
    "AEG-SQLI-003",
    "SQL injection — time-based",
    "Injection",
    "high",
    SCOPE_PARAM,
    cwe="CWE-89",
    remediation="Use parameterized queries and enforce a strict database query timeout.",
    description="A database sleep payload produced a reproducible delay absent from control requests.",
)
def sqli_time(ctx: CheckContext):
    if not ctx.config.time_based:
        return None
    control_one = _send(ctx, ctx.param.base_value)
    control_two = _send(ctx, ctx.param.base_value)
    if control_one.error or control_two.error:
        return None
    control_time = min(control_one.elapsed, control_two.elapsed)
    if control_time > 1.8:
        return None
    probes = P.SQL_TIME_PROBES if ctx.config.deep else P.SQL_TIME_PROBES[:3]
    for name, suffix, threshold in probes:
        if threshold <= 0:
            continue
        value = f"{ctx.param.base_value}{suffix}"
        first = _send(ctx, value)
        if first.error or first.elapsed < threshold * 0.75:
            continue
        second = _send(ctx, value)
        if second.error or second.elapsed < threshold * 0.75:
            continue
        return ctx.finding(
            f"{name} delayed responses by {first.elapsed:.2f}s and {second.elapsed:.2f}s "
            f"versus {control_time:.2f}s controls.",
            payload=value,
            confidence="medium",
        )
    return None


# ----------------------------------------------------------------------- XSS
@register(
    "AEG-XSS-001",
    "Reflected cross-site scripting",
    "Injection",
    "high",
    SCOPE_PARAM,
    cwe="CWE-79",
    remediation="Contextually encode output and adopt a strict CSP; never reflect raw HTML.",
    description="A unique script/SVG payload was reflected unencoded in an HTML response and reproduced.",
)
def xss_reflected(ctx: CheckContext):
    token = P.make_token(8)
    probes = P.xss_payloads(token, ctx.config.deep)
    baseline = _baseline_text(ctx)
    for probe in probes:
        response = _send(ctx, probe.payload)
        if response.error or not _is_html_response(response):
            continue
        if token in baseline:
            continue
        if not P.xss_reflected(response.text, probe.payload):
            continue
        confirm = _send(ctx, probe.payload)
        if confirm.error or not P.xss_reflected(confirm.text, probe.payload):
            continue
        return ctx.finding(
            f"{probe.name} payload reflected unencoded in HTML and reproduced.",
            payload=probe.payload,
            confidence="high",
        )
    return None


# -------------------------------------------------------------- command inj
@register(
    "AEG-CMDI-001",
    "OS command injection",
    "Injection",
    "critical",
    SCOPE_PARAM,
    cwe="CWE-78",
    remediation="Never pass user input to a shell; use fixed argument lists and allowlists.",
    description="A shell metacharacter payload produced a computed runtime marker on the server.",
)
def command_injection(ctx: CheckContext):
    token = P.make_token(6)
    probes = P.command_payloads(token, ctx.config.deep)
    baseline = _baseline_text(ctx)
    for probe in probes:
        if not probe.expected or probe.expected.lower() in probe.payload.lower():
            continue
        response = _send(ctx, probe.payload)
        if response.error:
            continue
        if probe.expected.lower() in baseline.lower():
            continue
        if probe.expected.lower() not in (response.text or "").lower():
            continue
        confirm = _send(ctx, probe.payload)
        if confirm.error or probe.expected.lower() not in (confirm.text or "").lower():
            continue
        return ctx.finding(
            f"{probe.name} produced computed marker {probe.expected!r} (absent from control).",
            payload=probe.payload,
            confidence="high",
        )
    return None


# ---------------------------------------------------------------------- SSTI
@register(
    "AEG-SSTI-001",
    "Server-side template injection",
    "Injection",
    "high",
    SCOPE_PARAM,
    cwe="CWE-1336",
    remediation="Do not build templates from user input; use logic-less templates or sandboxed rendering.",
    description="A template arithmetic expression was evaluated by the server into its computed product.",
)
def ssti(ctx: CheckContext):
    baseline = _baseline_text(ctx)
    for probe in P.ssti_payloads(ctx.config.deep):
        if probe.expected in probe.payload:
            continue
        response = _send(ctx, probe.payload)
        if response.error or not response.text:
            continue
        if probe.expected in baseline:
            continue
        if probe.expected not in response.text:
            continue
        confirm = _send(ctx, probe.payload)
        if confirm.error or probe.expected not in confirm.text:
            continue
        return ctx.finding(
            f"{probe.name} evaluated {probe.payload!r} to {probe.expected!r}.",
            payload=probe.payload,
            confidence="high",
        )
    return None


# ----------------------------------------------------------------------- LFI
@register(
    "AEG-LFI-001",
    "Local file inclusion / path traversal",
    "Injection",
    "high",
    SCOPE_PARAM,
    cwe="CWE-22",
    remediation="Resolve user paths against a fixed base, reject traversal, and use an allowlist of files.",
    description="A traversal payload returned recognizable local file contents not present in the control.",
)
def lfi(ctx: CheckContext):
    baseline = _baseline_text(ctx)
    probes = P.LFI_PAYLOADS_DEEP if ctx.config.deep else P.LFI_PAYLOADS[:3]
    for name, value in probes:
        response = _send(ctx, value)
        if response.error or not response.text:
            continue
        evidence = P.lfi_evidence(response.text, baseline)
        if not evidence:
            continue
        confirm = _send(ctx, value)
        if confirm.error or not P.lfi_evidence(confirm.text, baseline):
            continue
        return ctx.finding(
            f"{name} returned file signature {evidence!r}; control response did not.",
            payload=value,
            confidence="high",
        )
    return None


# ------------------------------------------------------------- open redirect
@register(
    "AEG-REDIR-001",
    "Open redirect",
    "Injection",
    "medium",
    SCOPE_PARAM,
    cwe="CWE-601",
    remediation="Only redirect to relative paths or a strict allowlist of trusted destinations.",
    description="A redirect parameter accepted an external destination and returned it in Location.",
)
def open_redirect(ctx: CheckContext):
    if not P.REDIRECT_PARAM_RE.match(ctx.param.param or ""):
        return None
    token = P.make_token(6)
    payload = P.redirect_payload(token)
    response = _send(ctx, payload, follow=False)
    if response.error:
        return None
    location = response.header("location", "")
    if "example.org/aegis-" not in location.lower():
        return None
    token_two = P.make_token(6)
    payload_two = P.redirect_payload(token_two)
    confirm = _send(ctx, payload_two, follow=False)
    if confirm.error or f"aegis-{token_two.lower()}" not in confirm.header("location", "").lower():
        return None
    return ctx.finding(
        f"External redirect honoured in Location: {location}" if len(location) < 200 else "External redirect honoured.",
        payload=payload,
        confidence="high",
    )


# ----------------------------------------------------------------------- CRLF
@register(
    "AEG-CRLF-001",
    "HTTP response splitting / CRLF injection",
    "Injection",
    "medium",
    SCOPE_PARAM,
    cwe="CWE-93",
    remediation="Reject CR/LF in header-bound input and use framework header APIs.",
    description="A CRLF payload introduced an attacker-controlled response header.",
)
def crlf(ctx: CheckContext):
    token = P.make_token(6)
    payload, header_name = P.crlf_payload(token)
    response = _send(ctx, payload, follow=False)
    if response.error:
        return None
    if response.header(header_name).strip().lower() != "hit":
        return None
    token_two = P.make_token(6)
    payload_two, header_two = P.crlf_payload(token_two)
    confirm = _send(ctx, payload_two, follow=False)
    if confirm.error or confirm.header(header_two).strip().lower() != "hit":
        return None
    return ctx.finding(
        f"Response contained injected header {header_name}: hit",
        payload=repr(payload),
        confidence="high",
    )


# ---------------------------------------------------------------------- NoSQL
@register(
    "AEG-NOSQL-001",
    "NoSQL injection — error-based",
    "Injection",
    "high",
    SCOPE_PARAM,
    cwe="CWE-943",
    remediation="Validate and cast query operators; never deserialize raw client operators into queries.",
    description="Operator/quote payloads triggered a database driver error absent from the control.",
)
def nosql(ctx: CheckContext):
    baseline = _baseline_text(ctx)
    for name, value in P.NOSQL_VALUES:
        response = _send(ctx, value)
        if response.error or not response.text:
            continue
        signature = P.find_nosql_error(response.text, baseline)
        if not signature:
            continue
        confirm = _send(ctx, value)
        if confirm.error or not P.find_nosql_error(confirm.text, baseline):
            continue
        return ctx.finding(f"{signature} appeared after {name}; control had no driver error.", payload=value, confidence="medium")
    return None


# ----------------------------------------------------------------------- LDAP
@register(
    "AEG-LDAP-001",
    "LDAP injection — error-based",
    "Injection",
    "medium",
    SCOPE_PARAM,
    cwe="CWE-90",
    remediation="Escape LDAP filter metacharacters and validate inputs against a strict allowlist.",
    description="Filter metacharacters produced an LDAP parser/driver error absent from the control.",
)
def ldap(ctx: CheckContext):
    baseline = _baseline_text(ctx)
    for name, value in P.LDAP_VALUES:
        response = _send(ctx, value)
        if response.error or not response.text:
            continue
        signature = P.find_ldap_error(response.text, baseline)
        if not signature:
            continue
        confirm = _send(ctx, value)
        if confirm.error or not P.find_ldap_error(confirm.text, baseline):
            continue
        return ctx.finding(f"{signature} appeared after {name}; control had no LDAP error.", payload=value, confidence="medium")
    return None


# ------------------------------------------------------------------------ XXE
@register(
    "AEG-XXE-001",
    "XML external entity injection",
    "Injection",
    "critical",
    SCOPE_TARGET,
    cwe="CWE-611",
    remediation="Disable DTD/external entities in every XML parser and use hardened parser defaults.",
    description="An XML document with a SYSTEM entity returned local file contents.",
)
def xxe(ctx: CheckContext):
    entry = ctx.entry
    if entry is None:
        return None
    baseline = entry.response.text or ""
    for name, payload in P.XXE_PAYLOADS:
        response = ctx.client.post(
            entry.url,
            data=payload,
            headers={"Content-Type": "application/xml", "Accept": "*/*"},
            follow=True,
        )
        if response.error or not response.text:
            continue
        evidence = P.xxe_evidence(response.text, baseline)
        if not evidence:
            continue
        return ctx.finding(
            f"{name} returned local file signature {evidence!r}.",
            url=entry.url,
            method="POST",
            payload=payload,
            confidence="high",
        )
    return None


__all__ = []

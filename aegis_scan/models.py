"""Shared data models used by the scanner, checks, and reporters."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit, urlunsplit

from .constants import (
    DEFAULT_DEPTH,
    DEFAULT_MAX_PAGES,
    DEFAULT_MAX_PARAMS,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
)

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def normalize_severity(value: str) -> str:
    value = (value or "info").strip().lower()
    return value if value in SEVERITY_RANK else "info"


@dataclass
class Target:
    raw: str
    url: str
    scheme: str
    host: str
    port: int
    netloc: str
    origin: str

    @classmethod
    def parse(cls, raw: str) -> "Target":
        raw = (raw or "").strip()
        if not raw:
            raise ValueError("target URL is empty")
        candidate = raw if "://" in raw else "https://" + raw
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("target must use http:// or https://")
        if not parts.hostname:
            raise ValueError("target has no hostname")
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise ValueError("target port is invalid") from exc
        netloc = parts.netloc
        path = parts.path or "/"
        url = urlunsplit((scheme, netloc, path, parts.query, ""))
        origin = urlunsplit((scheme, netloc, "", "", ""))
        return cls(raw=raw, url=url, scheme=scheme, host=parts.hostname, port=port, netloc=netloc, origin=origin)

    @property
    def is_loopback(self) -> bool:
        host = self.host.lower()
        return host in {"localhost", "127.0.0.1", "::1", "[::1]"} or host.startswith("127.")

    def root_url(self, path: str = "/") -> str:
        return f"{self.origin}/{path.lstrip('/')}"

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "url": self.url,
            "origin": self.origin,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
        }


@dataclass
class Response:
    url: str
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    headers_list: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    text: str = ""
    elapsed: float = 0.0
    history: list[str] = field(default_factory=list)
    error: str = ""
    method: str = "GET"

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 400

    @property
    def content_type(self) -> str:
        return self.header("content-type", "")

    @property
    def is_html(self) -> bool:
        ctype = self.content_type.lower()
        if not ctype:
            return bool(re.search(r"(?i)<(?:html|head|body|form)\b", self.text[:4000]))
        return "html" in ctype or "xhtml" in ctype or "xml" in ctype

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def header_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.headers_list if key.lower() == lowered]

    def to_dict(self, include_body: bool = False) -> dict:
        data = {
            "url": self.url,
            "status": self.status,
            "reason": self.reason,
            "elapsed": round(self.elapsed, 4),
            "content_type": self.content_type,
            "headers": dict(self.headers_list),
            "history": list(self.history),
            "error": self.error,
        }
        if include_body:
            data["body"] = self.text[:20000]
        return data


@dataclass
class FormField:
    name: str
    value: str = ""
    type: str = "text"
    tag: str = "input"
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class Form:
    page_url: str
    action: str
    method: str = "GET"
    enctype: str = "application/x-www-form-urlencoded"
    fields: list[FormField] = field(default_factory=list)
    raw_action: str = ""

    @property
    def has_password(self) -> bool:
        return any(field.type.lower() == "password" for field in self.fields)

    def field_data(self) -> dict[str, str]:
        data: dict[str, str] = {}
        for item in self.fields:
            if item.name and item.type not in {"submit", "button", "reset", "image", "file"}:
                data.setdefault(item.name, item.value)
        return data

    def token_fields(self) -> list[str]:
        tokens = []
        for item in self.fields:
            name = item.name.lower()
            if item.type.lower() == "hidden" and any(
                key in name for key in ("csrf", "xsrf", "token", "nonce", "authenticity")
            ):
                tokens.append(item.name)
        return tokens


@dataclass
class ScriptRef:
    src: str
    integrity: str = ""
    crossorigin: str = ""


@dataclass
class ResourceRef:
    tag: str
    url: str
    attribute: str = "src"


@dataclass
class AnchorRef:
    href: str
    target: str = ""
    rel: str = ""


@dataclass
class ParsedPage:
    title: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    generator: str = ""
    scripts: list[ScriptRef] = field(default_factory=list)
    resources: list[ResourceRef] = field(default_factory=list)
    anchors: list[AnchorRef] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)


@dataclass
class PageData:
    url: str
    response: Response
    parsed: ParsedPage = field(default_factory=ParsedPage)
    depth: int = 0

    @property
    def is_html(self) -> bool:
        return self.response.is_html


@dataclass
class ParamTarget:
    page_url: str
    endpoint: str
    method: str
    param: str
    base_value: str = ""
    form_fields: dict[str, str] | None = None
    input_type: str = "text"
    location: str = "query"

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.method.upper(), self.endpoint, self.param, self.location)

    @property
    def label(self) -> str:
        prefix = "form " if self.location == "form" else ""
        return f"{prefix}{self.param}"

    def build_url(self, value: str) -> str:
        parts = urlsplit(self.endpoint)
        pairs = []
        replaced = False
        for key, existing in _parse_pairs(parts.query):
            if key == self.param and not replaced:
                pairs.append((key, value))
                replaced = True
            else:
                pairs.append((key, existing))
        if not replaced:
            pairs.append((self.param, value))
        query = urlencode(pairs, doseq=True, safe="")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))

    def build_form_data(self, value: str) -> dict[str, str]:
        data = dict(self.form_fields or {})
        data[self.param] = value
        return data


def _parse_pairs(query: str) -> list[tuple[str, str]]:
    from urllib.parse import parse_qsl

    return parse_qsl(query, keep_blank_values=True)


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    category: str
    url: str
    cwe: str = ""
    remediation: str = ""
    description: str = ""
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    confidence: str = "high"
    source: str = "active"

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)

    @property
    def dedupe_key(self) -> tuple[str, str, str, str]:
        parts = urlsplit(self.url)
        endpoint = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        return (self.check_id, endpoint.lower(), self.parameter.lower(), self.method.upper())

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "source": self.source,
            "method": self.method,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "description": self.description,
        }


@dataclass
class ScanConfig:
    target_raw: str = ""
    threads: int = DEFAULT_THREADS
    timeout: float = DEFAULT_TIMEOUT
    delay: float = 0.0
    max_pages: int = DEFAULT_MAX_PAGES
    depth: int = DEFAULT_DEPTH
    max_params: int = DEFAULT_MAX_PARAMS
    deep: bool = False
    time_based: bool = False
    test_forms: bool = False
    insecure: bool = False
    headers: list[str] = field(default_factory=list)
    cookie: str = ""
    user_agent: str = DEFAULT_USER_AGENT
    output: str = ""
    fmt: str = "auto"
    authorized: bool = False
    no_banner: bool = False
    quiet: bool = False
    verbose: bool = False

    def public_dict(self) -> dict:
        return {
            "threads": self.threads,
            "timeout": self.timeout,
            "delay": self.delay,
            "max_pages": self.max_pages,
            "depth": self.depth,
            "max_params": self.max_params,
            "deep_payloads": self.deep,
            "time_based": self.time_based,
            "test_forms": self.test_forms,
            "tls_verification": not self.insecure,
            "authorized": self.authorized,
        }


@dataclass
class ScanSummary:
    total: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: {name: 0 for name in SEVERITIES})
    pages_crawled: int = 0
    parameters_tested: int = 0
    requests: int = 0
    request_errors: int = 0
    duration: float = 0.0
    checks_available: int = 0
    checks_executed: int = 0
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "by_severity": dict(self.by_severity),
            "pages_crawled": self.pages_crawled,
            "parameters_tested": self.parameters_tested,
            "requests": self.requests,
            "request_errors": self.request_errors,
            "duration_seconds": round(self.duration, 3),
            "checks_available": self.checks_available,
            "checks_executed": self.checks_executed,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


@dataclass
class ScanReport:
    target: Target
    findings: list[Finding] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    executed_checks: set[str] = field(default_factory=set)
    failed_checks: list[str] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    scan_id: str = ""
    notes: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda item: (SEVERITY_RANK.get(item.severity, 9), item.category.lower(), item.check_id),
        )

    def as_dict(self) -> dict:
        from . import constants

        return {
            "report": {
                "tool": constants.TOOL_NAME,
                "full_name": constants.FULL_NAME,
                "version": constants.VERSION,
                "author": constants.AUTHOR,
                "github": constants.REPO_URL,
                "scan_id": self.scan_id,
                "generated_at": self.summary.finished_at,
                "support": constants.SUPPORT_LINE,
            },
            "target": self.target.to_dict(),
            "config": self.config,
            "summary": self.summary.to_dict(),
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
            "checks_executed": sorted(self.executed_checks),
            "checks_failed": list(self.failed_checks),
            "notes": list(self.notes),
        }


__all__ = [
    "SEVERITIES",
    "SEVERITY_RANK",
    "Target",
    "Response",
    "FormField",
    "Form",
    "ScriptRef",
    "ResourceRef",
    "AnchorRef",
    "ParsedPage",
    "PageData",
    "ParamTarget",
    "Finding",
    "ScanConfig",
    "ScanSummary",
    "ScanReport",
]

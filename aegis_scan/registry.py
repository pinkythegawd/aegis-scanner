"""Check registration and the per-check execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .models import (
    Finding,
    Form,
    PageData,
    ParamTarget,
    Response,
    ScanConfig,
    Target,
    normalize_severity,
)

SCOPE_TARGET = "target"
SCOPE_ENTRY = "entry"
SCOPE_PAGE = "page"
SCOPE_FORM = "form"
SCOPE_PARAM = "param"

SCOPES = (SCOPE_TARGET, SCOPE_ENTRY, SCOPE_PAGE, SCOPE_FORM, SCOPE_PARAM)
SOURCE_PASSIVE = "passive"
SOURCE_ACTIVE = "active"


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    category: str
    severity: str
    scope: str
    func: Callable[["CheckContext"], Iterable[Finding] | Finding | None]
    cwe: str = ""
    remediation: str = ""
    description: str = ""
    source: str = SOURCE_ACTIVE

    def __post_init__(self) -> None:
        if self.scope not in SCOPES:
            raise ValueError(f"invalid scope {self.scope!r} for {self.id}")
        if not (self.id or "").strip():
            raise ValueError("check id is required")


REGISTRY: dict[str, CheckSpec] = {}


def register(
    check_id: str,
    title: str,
    category: str,
    severity: str,
    scope: str,
    *,
    cwe: str = "",
    remediation: str = "",
    description: str = "",
    source: str = SOURCE_ACTIVE,
) -> Callable[[Callable[["CheckContext"], Any]], Callable[["CheckContext"], Any]]:
    def decorator(func: Callable[["CheckContext"], Any]) -> Callable[["CheckContext"], Any]:
        if check_id in REGISTRY:
            raise RuntimeError(f"duplicate check id: {check_id}")
        REGISTRY[check_id] = CheckSpec(
            id=check_id,
            title=title,
            category=category,
            severity=normalize_severity(severity),
            scope=scope,
            func=func,
            cwe=cwe,
            remediation=remediation,
            description=description,
            source=source,
        )
        return func

    return decorator


@dataclass
class CheckContext:
    spec: CheckSpec
    client: Any
    target: Target
    config: ScanConfig
    entry: PageData | None = None
    page: PageData | None = None
    form: Form | None = None
    param: ParamTarget | None = None
    param_baseline: Response | None = None
    soft_404: Response | None = None
    shared: dict[str, Any] = field(default_factory=dict)
    mutate: Callable[..., Response] | None = None

    def finding(
        self,
        evidence: str,
        *,
        url: str | None = None,
        parameter: str | None = None,
        method: str | None = None,
        payload: str = "",
        confidence: str = "high",
        title: str | None = None,
        severity: str | None = None,
        source: str | None = None,
    ) -> Finding:
        if url is None:
            if self.form is not None:
                url = self.form.action
            elif self.param is not None:
                url = self.param.endpoint
            elif self.page is not None:
                url = self.page.url
            else:
                url = self.target.url
        if parameter is None:
            parameter = self.param.param if self.param is not None else ""
        if method is None:
            if self.param is not None:
                method = self.param.method
            elif self.form is not None:
                method = self.form.method
            else:
                method = "GET"
        return Finding(
            check_id=self.spec.id,
            title=title or self.spec.title,
            severity=normalize_severity(severity or self.spec.severity),
            category=self.spec.category,
            url=url,
            cwe=self.spec.cwe,
            remediation=self.spec.remediation,
            description=self.spec.description,
            parameter=parameter or "",
            method=(method or "GET").upper(),
            payload=payload,
            evidence=_clean(evidence),
            confidence=confidence,
            source=source or self.spec.source,
        )


def _clean(value: str, limit: int = 800) -> str:
    text = " ".join((value or "").split())
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def checks_for(scope: str) -> list[CheckSpec]:
    return sorted((spec for spec in REGISTRY.values() if spec.scope == scope), key=lambda item: item.id)


def all_checks() -> list[CheckSpec]:
    return sorted(REGISTRY.values(), key=lambda item: item.id)


def category_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in REGISTRY.values():
        counts[spec.category] = counts.get(spec.category, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: item[0].lower()))


__all__ = [
    "SCOPE_TARGET",
    "SCOPE_ENTRY",
    "SCOPE_PAGE",
    "SCOPE_FORM",
    "SCOPE_PARAM",
    "SCOPES",
    "SOURCE_PASSIVE",
    "SOURCE_ACTIVE",
    "CheckSpec",
    "CheckContext",
    "REGISTRY",
    "register",
    "checks_for",
    "all_checks",
    "category_counts",
]

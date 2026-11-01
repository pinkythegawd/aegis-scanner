"""Multithreaded crawl and scan orchestration."""

from __future__ import annotations

import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import checks_content, checks_http, checks_infra, checks_injection  # noqa: F401
from .colors import BOLD, CYAN, GREEN, GREY, YELLOW, Terminal
from .html_parser import parse_html, same_site_origin
from .http_client import HttpClient, inspect_tls
from .models import (
    Finding,
    PageData,
    ParamTarget,
    ParsedPage,
    Response,
    ScanConfig,
    ScanReport,
    ScanSummary,
    Target,
)
from .registry import (
    SCOPE_ENTRY,
    SCOPE_FORM,
    SCOPE_PAGE,
    SCOPE_PARAM,
    SCOPE_TARGET,
    CheckContext,
    CheckSpec,
    all_checks,
    checks_for,
)

STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".map", ".json", ".xml", ".rss", ".atom", ".txt",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".webm", ".ogg", ".wav",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".exe", ".dmg", ".apk", ".iso",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
}
SKIP_PARAM_RE = re.compile(
    r"^(?:csrf|csrf_token|_csrf|_token|authenticity_token|xsrf|nonce|session|sess|sid|"
    r"jsessionid|phpsessid|asp\.net_sessionid|utm_.*|gclid|fbclid|_ga|_gl)$",
    re.I,
)
DESTRUCTIVE_PATH_RE = re.compile(r"(?:^|/)(?:logout|signout|sign-out|logoff|delete|remove|destroy)(?:/|\.|$)", re.I)
INJECTABLE_TYPES = {"text", "search", "email", "url", "tel", "number", "textarea", "date", "password", ""}


class ScanError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _norm_severity(items: Iterable[Finding]) -> None:
    for item in items:
        item.severity = item.severity.lower()


class Scanner:
    def __init__(self, config: ScanConfig, term: Terminal):
        self.config = config
        self.term = term
        self.client = HttpClient(config)
        self.target: Target | None = None
        self.entry: PageData | None = None
        self.pages: list[PageData] = []
        self.findings: list[Finding] = []
        self.executed: set[str] = set()
        self.failed: list[str] = []
        self.notes: list[str] = []
        self.soft_404: Response | None = None
        self.shared: dict = {}
        self.scan_id = secrets.token_hex(5)
        self._params_truncated = False
        self._crawl_truncated = False
        self._insecure_fallback = False
        self._started = time.perf_counter()
        self._started_at = _utc_now()
        self.params_tested: list[ParamTarget] = []

    # ------------------------------------------------------------------- public
    def run(self) -> ScanReport:
        self.target = Target.parse(self.config.target_raw)
        self.client.scope_host = self.target.host
        self.shared = {}

        self._preflight()
        assert self.target is not None and self.entry is not None
        self._fetch_soft_404()
        self._inspect_transport()
        self._phase("01", "INFRASTRUCTURE & EXPOSURE LIBRARY", f"{len(checks_for(SCOPE_TARGET))} checks")
        self._run_target_checks()

        self._phase("02", "CRAWL & PASSIVE ANALYSIS", f"depth {self.config.depth}, max {self.config.max_pages} pages")
        self._crawl()
        self._run_entry_checks()
        self._run_page_checks()
        self._run_form_checks()

        self._phase("03", "ACTIVE PROOF ENGINE", "confirmed, marker-based payloads")
        self._run_injection_checks()

        report = self._finalize()
        return report

    # ------------------------------------------------------------------ phases
    def _preflight(self) -> None:
        assert self.target is not None
        self.term.write(
            "  " + self.term.paint("› preflight ", GREY) + self.term.paint(self.target.url, CYAN)
        )
        response = self.client.get(self.target.url, follow=True)
        if response.error and "certificate" in response.error.lower() and not self.client.insecure:
            self.term.write(
                "  " + self.term.paint("! TLS verification failed; retrying without verification for this scan.", YELLOW)
            )
            self.client.enable_insecure()
            self._insecure_fallback = True
            self.notes.append("TLS verification failed; the scan continued with --insecure behavior.")
            response = self.client.get(self.target.url, follow=True)

        if response.error and "://" not in self.config.target_raw:
            http_target = Target.parse("http://" + self.config.target_raw)
            self.term.write(
                "  " + self.term.paint(f"! HTTPS unavailable ({response.error}); trying {http_target.url}", YELLOW)
            )
            retry = self.client.get(http_target.url, follow=True)
            if not retry.error:
                self.target = Target.parse(retry.url)
                self.target.raw = self.config.target_raw
                self.client.scope_host = self.target.host
                response = retry
                self.notes.append("HTTPS was unavailable; the scan fell back to HTTP.")

        if response.error:
            raise ScanError(f"could not reach target: {response.error}")

        final_parts = urlsplit(response.url)
        if final_parts.hostname and final_parts.hostname.lower() != self.target.host.lower():
            self.target = Target.parse(response.url)
            self.target.raw = self.config.target_raw
            self.client.scope_host = self.target.host
            self.notes.append(f"Landing page redirected to {response.url}.")

        parsed = parse_html(response.text, response.url) if response.is_html else ParsedPage()
        self.entry = PageData(url=response.url, response=response, parsed=parsed, depth=0)
        size_kb = len(response.body) / 1024
        self.term.write(
            "  "
            + self.term.paint("✓ reachable ", GREEN)
            + self.term.paint(f"HTTP {response.status} · {size_kb:.1f} KB · {response.elapsed:.2f}s", GREY)
        )
        if response.status >= 500:
            self.notes.append(f"Landing page returned HTTP {response.status}.")
        if self.target.scheme != urlsplit(response.url).scheme:
            self.target = Target.parse(response.url)
            self.target.raw = self.config.target_raw
            self.client.scope_host = self.target.host
        if self._insecure_fallback:
            self.term.write("  " + self.term.paint("! certificate findings will still be reported.", GREY))

    def _fetch_soft_404(self) -> None:
        assert self.target is not None
        path = f"/aegis-{secrets.token_hex(4)}-not-found"
        response = self.client.get(self.target.root_url(path), follow=True)
        self.soft_404 = None if response.error else response

    def _inspect_transport(self) -> None:
        assert self.target is not None
        port = self.target.port if self.target.scheme == "https" else 443
        self.term.write("  " + self.term.paint("› transport ", GREY) + self.term.paint(f"{self.target.host}:{port}", CYAN))
        info = inspect_tls(self.target.host, port, timeout=min(self.config.timeout, 6.0))
        self.shared["tls"] = info
        if info.get("supported"):
            verified = bool(info.get("verified"))
            status = "verified" if verified else "untrusted"
            self.term.write(
                "  " + self.term.paint("✓ TLS " if verified else "! TLS ", GREEN if verified else YELLOW)
                + self.term.paint(f"{info.get('version') or 'unknown'} · {info.get('cipher') or 'unknown'} · {status}", GREY)
            )
        else:
            self.term.write("  " + self.term.paint(f"! TLS: {info.get('error', 'not supported')}", YELLOW))

    # ------------------------------------------------------------------- tasks
    def _run_one(self, spec: CheckSpec, ctx: CheckContext) -> list[Finding]:
        result = spec.func(ctx)
        if result is None:
            return []
        if isinstance(result, Finding):
            return [result]
        return [item for item in result if isinstance(item, Finding)]

    def _execute(
        self,
        label: str,
        specs: list[CheckSpec],
        context_for: Callable[[CheckSpec], CheckContext],
        *,
        tasks: list[tuple[CheckSpec, CheckContext]] | None = None,
        show_progress: bool = True,
    ) -> list[Finding]:
        work = tasks if tasks is not None else [(spec, context_for(spec)) for spec in specs]
        if not work:
            return []
        collected: list[Finding] = []
        self.term.write(
            "  " + self.term.paint(f"› {label} ", GREY) + self.term.paint(f"{len(work)} checks", GREY)
        )
        workers = max(1, min(self.config.threads, len(work)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="aegis") as pool:
            futures = {pool.submit(self._run_one, spec, ctx): spec for spec, ctx in work}
            for index, future in enumerate(as_completed(futures), 1):
                spec = futures[future]
                self.executed.add(spec.id)
                try:
                    found = future.result()
                except Exception as exc:  # individual checks must never kill a scan
                    self.failed.append(f"{spec.id}: {type(exc).__name__}: {exc}")
                    found = []
                if found:
                    collected.extend(found)
                if show_progress:
                    self.term.progress(f"    {label}  {index}/{len(work)}  ·  {len(collected)} finding(s)")
        if show_progress:
            self.term.finish_progress()
            self.term.write(
                "  " + self.term.paint("✓ ", GREEN) + self.term.paint(label, GREY)
                + self.term.paint(f" · {len(work)} checks · {len(collected)} finding(s)", GREY)
            )
        return collected

    def _base_context(self, spec: CheckSpec, **kwargs) -> CheckContext:
        assert self.target is not None
        return CheckContext(
            spec=spec,
            client=self.client,
            target=self.target,
            config=self.config,
            entry=self.entry,
            soft_404=self.soft_404,
            shared=self.shared,
            **kwargs,
        )

    def _run_target_checks(self) -> None:
        specs = checks_for(SCOPE_TARGET)
        found = self._execute("exposures, transport & active infra", specs, lambda spec: self._base_context(spec))
        self.findings.extend(found)

    def _run_entry_checks(self) -> None:
        if self.entry is None:
            return
        specs = checks_for(SCOPE_ENTRY)
        found = self._execute(
            "header, cookie, CORS & method policy",
            specs,
            lambda spec: self._base_context(spec, page=self.entry),
        )
        self.findings.extend(found)

    def _run_page_checks(self) -> None:
        html_pages = [page for page in self.pages if page.response.is_html]
        if not html_pages:
            self.notes.append("No HTML pages were available for content analysis.")
            return
        specs = checks_for(SCOPE_PAGE)
        tasks = [(spec, self._base_context(spec, page=page)) for page in html_pages for spec in specs]
        found = self._execute("content & client-side analysis", specs, lambda spec: self._base_context(spec), tasks=tasks)
        self.findings.extend(found)

    def _run_form_checks(self) -> None:
        html_pages = [page for page in self.pages if page.response.is_html]
        forms = [(page, form) for page in html_pages for form in page.parsed.forms]
        if not forms:
            self.notes.append("No HTML forms were discovered; form checks were not applicable.")
            return
        specs = checks_for(SCOPE_FORM)
        tasks = [
            (spec, self._base_context(spec, page=page, form=form))
            for page, form in forms
            for spec in specs
        ]
        found = self._execute("form security analysis", specs, lambda spec: self._base_context(spec), tasks=tasks)
        self.findings.extend(found)

    # ------------------------------------------------------------------- crawl
    def _fetch_page(self, url: str, depth: int) -> PageData | None:
        response = self.client.get(url, follow=True)
        if response.error:
            return None
        parsed = parse_html(response.text, response.url) if response.is_html else ParsedPage()
        return PageData(url=response.url, response=response, parsed=parsed, depth=depth)

    def _crawl(self) -> None:
        assert self.entry is not None and self.target is not None
        self.pages = [self.entry]
        visited = {self.entry.url}
        current = [self.entry]

        if self.config.max_pages <= 1 or self.config.depth <= 0:
            self.term.write("  " + self.term.paint("→ crawl disabled (max-pages/depth)", GREY))
            return

        for level in range(1, self.config.depth + 1):
            remaining = self.config.max_pages - len(self.pages)
            if remaining <= 0:
                self._crawl_truncated = True
                break
            candidates: list[str] = []
            seen_level: set[str] = set()
            for page in current:
                if not page.response.is_html:
                    continue
                for link in page.parsed.links:
                    if link in visited or link in seen_level:
                        continue
                    if not self._crawlable(link):
                        continue
                    seen_level.add(link)
                    candidates.append(link)
            candidates = candidates[:remaining]
            if not candidates:
                break
            for link in candidates:
                visited.add(link)
            if len(seen_level) > remaining:
                self._crawl_truncated = True

            self.term.write(
                "  " + self.term.paint(f"› crawl depth {level}/{self.config.depth} ", GREY)
                + self.term.paint(f"{len(candidates)} page(s)", GREY)
            )
            fetched: list[PageData] = []
            workers = max(1, min(self.config.threads, len(candidates)))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="crawl") as pool:
                futures = {pool.submit(self._fetch_page, url, level): url for url in candidates}
                for index, future in enumerate(as_completed(futures), 1):
                    page = future.result()
                    if page is not None:
                        fetched.append(page)
                    self.term.progress(f"    crawling  {index}/{len(candidates)}  ·  {len(fetched)} reachable")
            self.term.finish_progress()
            self.pages.extend(fetched)
            current = fetched
            if len(self.pages) >= self.config.max_pages:
                self._crawl_truncated = True
                break
        self.term.write(
            "  " + self.term.paint("✓ ", GREEN)
            + self.term.paint(f"crawled {len(self.pages)} page(s)", GREY)
        )

    def _crawlable(self, url: str) -> bool:
        assert self.target is not None
        if not same_site_origin(url, self.target.origin):
            return False
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        path = parts.path or "/"
        ext = ("." + path.rsplit(".", 1)[-1].lower()) if "." in path.rsplit("/", 1)[-1] else ""
        if ext in STATIC_EXTENSIONS:
            return False
        if DESTRUCTIVE_PATH_RE.search(path):
            return False
        if re.search(r"(?i)(?:^|[?&])(?:action|do|op)=(?:delete|remove|logout|signout)\b", parts.query):
            return False
        if len(url) > 2000:
            return False
        return True

    # -------------------------------------------------------------- injection
    def _collect_params(self) -> list[ParamTarget]:
        assert self.target is not None
        collected: list[ParamTarget] = []
        keys: set[tuple[str, str, str, str]] = set()

        for page in self.pages:
            parts = urlsplit(page.url)
            path_key = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            for name, value in parse_qsl(parts.query, keep_blank_values=True):
                if not name or SKIP_PARAM_RE.match(name) or len(name) > 80:
                    continue
                key = ("GET", path_key, name, "query")
                if key in keys:
                    continue
                keys.add(key)
                collected.append(
                    ParamTarget(
                        page_url=page.url,
                        endpoint=page.url,
                        method="GET",
                        param=name,
                        base_value=value,
                        location="query",
                    )
                )

        if self.config.test_forms:
            for page in self.pages:
                if not page.response.is_html:
                    continue
                for form in page.parsed.forms:
                    if form.has_password or form.enctype.startswith("multipart"):
                        continue
                    if not same_site_origin(form.action, self.target.origin):
                        continue
                    parts = urlsplit(form.action)
                    if DESTRUCTIVE_PATH_RE.search(parts.path):
                        continue
                    path_key = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
                    for field in form.fields:
                        field_type = (field.type or "text").lower()
                        if field_type not in INJECTABLE_TYPES or field.tag == "select":
                            continue
                        if not field.name or SKIP_PARAM_RE.match(field.name):
                            continue
                        if field_type in {"file", "hidden", "submit", "button", "reset", "image", "checkbox", "radio"}:
                            continue
                        key = (form.method, path_key, field.name, "form")
                        if key in keys:
                            continue
                        keys.add(key)
                        collected.append(
                            ParamTarget(
                                page_url=page.url,
                                endpoint=form.action,
                                method=form.method,
                                param=field.name,
                                base_value=field.value,
                                form_fields=form.field_data(),
                                input_type=field_type,
                                location="form",
                            )
                        )

        if len(collected) > self.config.max_params:
            self._params_truncated = True
            collected = collected[: self.config.max_params]
        return collected

    def _baseline_for(self, param: ParamTarget, page_by_url: dict[str, PageData], cache: dict) -> Response | None:
        if param.location == "query":
            page = page_by_url.get(param.endpoint)
            if page is not None:
                return page.response
            if param.endpoint in cache:
                return cache[param.endpoint]
            response = self.client.get(param.endpoint, follow=True)
            cache[param.endpoint] = response
            return response

        fields = param.form_fields or {}
        key = (param.endpoint, param.method, tuple(sorted(fields.items())))
        if key in cache:
            return cache[key]
        if param.method == "POST":
            response = self.client.post(param.endpoint, data=fields, follow=True)
        else:
            parts = urlsplit(param.endpoint)
            query = urlencode(fields, doseq=True)
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
            response = self.client.get(url, follow=True)
        cache[key] = response
        return response

    def _mutator(self, param: ParamTarget):
        assert self.target is not None

        def mutate(value: str, *, follow: bool = True, headers: dict | None = None) -> Response:
            if param.method == "POST":
                return self.client.post(
                    param.endpoint,
                    data=param.build_form_data(value),
                    headers=headers,
                    follow=follow,
                )
            if param.form_fields is not None:
                fields = dict(param.form_fields)
                fields[param.param] = value
                parts = urlsplit(param.endpoint)
                query = urlencode(fields, doseq=True)
                url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
            else:
                url = param.build_url(value)
            return self.client.get(url, headers=headers, follow=follow)

        return mutate

    def _run_injection_checks(self) -> None:
        assert self.entry is not None
        params = self._collect_params()
        specs = checks_for(SCOPE_PARAM)
        html_pages = [page for page in self.pages if page.response.is_html]
        page_by_url = {page.url: page for page in html_pages}
        page_by_url.setdefault(self.entry.url, self.entry)

        if not params:
            self.notes.append("No testable GET/form parameters were discovered; injection checks were skipped.")
            self.term.write("  " + self.term.paint("→ no injectable parameters found", YELLOW))
            return

        self.term.write(
            "  " + self.term.paint("› discovered ", GREY)
            + self.term.paint(f"{len(params)} parameter(s)", CYAN)
            + self.term.paint(
                f" · {sum(1 for item in params if item.location == 'form')} form field(s)"
                f" · {sum(1 for item in params if item.location == 'query')} query parameter(s)",
                GREY,
            )
        )
        if self._params_truncated:
            self.term.write(
                "  " + self.term.paint(f"! parameter cap reached ({self.config.max_params}); use --max-params to expand.", YELLOW)
            )
        self.params_tested = params

        baseline_cache: dict = {}
        tasks: list[tuple[CheckSpec, CheckContext]] = []
        for param in params:
            baseline = self._baseline_for(param, page_by_url, baseline_cache)
            page = page_by_url.get(param.endpoint) or page_by_url.get(param.page_url) or self.entry
            for spec in specs:
                ctx = self._base_context(
                    spec,
                    page=page,
                    param=param,
                    param_baseline=baseline,
                )
                ctx.mutate = self._mutator(param)
                tasks.append((spec, ctx))

        self.term.write(
            "  " + self.term.paint("› active probes ", GREY)
            + self.term.paint(f"{len(tasks)} tests", GREY)
            + self.term.paint(
                " · time-based " + ("on" if self.config.time_based else "off")
                + " · deep " + ("on" if self.config.deep else "off"),
                GREY,
            )
        )
        found = self._execute("injection proof engine", specs, lambda spec: self._base_context(spec), tasks=tasks)
        self.findings.extend(found)

    # ------------------------------------------------------------------ report
    def _finalize(self) -> ScanReport:
        assert self.target is not None and self.entry is not None
        unique: dict[tuple, Finding] = {}
        for finding in self.findings:
            unique.setdefault(finding.dedupe_key, finding)
        findings = list(unique.values())
        _norm_severity(findings)
        for finding in findings:
            if finding.severity == "critical":
                self.notes.append(f"Critical confirmation: {finding.check_id} on {finding.url}")
        findings.sort(key=lambda item: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(item.severity, 9), item.check_id))

        stats = self.client.stats()
        summary = ScanSummary(
            total=len(findings),
            by_severity={name: sum(1 for f in findings if f.severity == name) for name in ("critical", "high", "medium", "low", "info")},
            pages_crawled=len(self.pages),
            parameters_tested=len(self.params_tested),
            requests=stats["requests"],
            request_errors=stats["errors"],
            duration=time.perf_counter() - self._started,
            checks_available=len(all_checks()),
            checks_executed=len(self.executed),
            started_at=self._started_at,
            finished_at=_utc_now(),
        )
        if not self.config.time_based:
            self.notes.append("Time-based SQL injection was not requested; enable --time-based for delay confirmation.")
        if not self.config.test_forms:
            self.notes.append("Form fields were not actively injected; enable --test-forms for POST/GET form testing.")
        if self._crawl_truncated:
            self.notes.append("Crawl coverage hit --max-pages; increase it for broader coverage.")
        if self._params_truncated:
            self.notes.append(f"Parameter testing was capped at {self.config.max_params}; increase --max-params to expand.")
        if not findings:
            self.notes.append("No findings does not guarantee the target is secure; manual review is still required.")
        self.notes.append("Automated evidence should be validated manually before remediation or disclosure.")

        return ScanReport(
            target=self.target,
            findings=findings,
            summary=summary,
            executed_checks=set(self.executed),
            failed_checks=list(self.failed),
            config=self.config.public_dict(),
            scan_id=self.scan_id,
            notes=self.notes,
        )

    # --------------------------------------------------------------- printing
    def _phase(self, number: str, title: str, detail: str) -> None:
        self.term.write("")
        self.term.write(
            "  " + self.term.paint(number + " / " + title, CYAN, BOLD)
            + "  " + self.term.paint(detail, GREY)
        )
        self.term.write("  " + self.term.rule(74))


__all__ = ["Scanner", "ScanError"]

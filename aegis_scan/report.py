"""Terminal report rendering, check catalogue display, and txt/json exports."""

from __future__ import annotations

import json
import re
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Iterable

from . import constants
from .colors import BOLD, CYAN, GREEN, GREY, MAGENTA, WHITE, YELLOW, Terminal
from .models import SEVERITIES, Finding, ScanReport
from .registry import CheckSpec, all_checks, category_counts

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _wrap(text: str, width: int = 96, indent: int = 6) -> str:
    return textwrap.fill(
        " ".join((text or "").split()),
        width=width,
        initial_indent=" " * indent,
        subsequent_indent=" " * indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def _finding_block(term: Terminal, index: int, finding: Finding) -> list[str]:
    lines = []
    label = term.severity(finding.severity, finding.severity.upper().ljust(8))
    lines.append(
        f"  {term.paint(str(index).rjust(3), GREY)}  {label} "
        f"{term.paint(finding.check_id, CYAN)}  {term.paint(finding.title, WHITE, BOLD)}"
    )
    meta = (
        f"{finding.method} {finding.url}"
        + (f"  ·  param: {finding.parameter}" if finding.parameter else "")
        + f"  ·  confidence: {finding.confidence}"
        + (f"  ·  {finding.cwe}" if finding.cwe else "")
    )
    lines.append(_wrap(meta, width=110, indent=9))
    if finding.payload:
        payload = finding.payload if len(finding.payload) < 300 else finding.payload[:299] + "…"
        lines.append(_wrap("payload: " + payload, indent=9))
    if finding.evidence:
        lines.append(_wrap("proof:   " + finding.evidence, indent=9))
    if finding.remediation:
        lines.append(_wrap("fix:     " + finding.remediation, indent=9))
    return lines


def render_report(report: ScanReport, term: Terminal) -> None:
    summary = report.summary
    term.write("")
    term.write("  " + term.paint("━" * 74, CYAN))
    term.write("  " + term.paint("SCAN COMPLETE", CYAN, BOLD) + "  " + term.paint(report.target.url, WHITE))
    term.write("  " + term.paint("━" * 74, CYAN))
    term.write(
        "  "
        + term.paint("duration ", GREY)
        + term.paint(f"{summary.duration:.2f}s", WHITE)
        + term.paint("   requests ", GREY)
        + term.paint(f"{summary.requests:,}", WHITE)
        + term.paint("   pages ", GREY)
        + term.paint(str(summary.pages_crawled), WHITE)
        + term.paint("   parameters ", GREY)
        + term.paint(str(summary.parameters_tested), WHITE)
    )
    term.write(
        "  "
        + term.paint("checks ", GREY)
        + term.paint(f"{summary.checks_executed}/{summary.checks_available} executed", WHITE)
        + term.paint(f"   errors {summary.request_errors}", GREY)
        + (term.paint(f"   failed checks {len(report.failed_checks)}", YELLOW) if report.failed_checks else "")
    )
    term.write("")

    counts = []
    for severity in SEVERITY_ORDER:
        counts.append(
            term.severity(severity, f"{severity.upper():>8} {summary.by_severity.get(severity, 0):>3}")
        )
    term.write("  " + "   ".join(counts))
    term.write("")

    if report.findings:
        for severity in SEVERITY_ORDER:
            group = [item for item in report.sorted_findings() if item.severity == severity]
            if not group:
                continue
            term.write("")
            term.write(
                "  " + term.severity(severity, f"{severity.upper()} · {len(group)}")
                + "  " + term.paint("─" * max(4, 60 - len(severity)), GREY)
            )
            for index, finding in enumerate(group, 1):
                for line in _finding_block(term, index, finding):
                    term.write(line)
    else:
        term.write("  " + term.paint("No findings.", GREEN, BOLD))
        term.write("  " + term.paint("This does not guarantee the target is secure; manual review is still required.", GREY))

    if report.notes:
        term.write("")
        term.write("  " + term.paint("NOTES", GREY, BOLD))
        confirmations = [note for note in report.notes if note.startswith("Critical confirmation")]
        others = [note for note in report.notes if not note.startswith("Critical confirmation")]
        for note in (others + confirmations)[:8]:
            term.write(_wrap("· " + note, width=110, indent=4))

    term.write("")
    term.write("  " + term.rule(74))
    term.write(
        "  " + term.paint("Docs & payload catalogue  ", GREY) + term.link(constants.DOCS_URL)
    )
    term.write(
        "  " + term.paint("Report an issue           ", GREY) + term.link(constants.ISSUES_URL)
    )
    term.write("  " + term.paint(constants.SUPPORT_LINE, WHITE, BOLD))
    term.write("  " + term.paint(f"Scan ID {report.scan_id}  ·  AEGIS v{constants.VERSION}  ·  by {constants.AUTHOR}", GREY))
    term.write("")


def print_check_catalogue(term: Terminal, category: str | None = None) -> None:
    checks: list[CheckSpec] = all_checks()
    if category:
        checks = [spec for spec in checks if spec.category.lower() == category.lower()]
    if not checks:
        term.write(term.paint(f"No checks matched category {category!r}.", YELLOW))
        return
    counts = category_counts()
    term.write(term.paint(f"{constants.TOOL_NAME} check library · {len(all_checks())} checks", CYAN, BOLD))
    term.write(
        "  ".join(term.paint(f"{name}: {count}", GREY) for name, count in counts.items())
    )
    term.write("")
    term.write(
        term.paint(f"{'ID':<14}{'SEV':<10}{'SCOPE':<8}{'CATEGORY':<16}TITLE", GREY, BOLD)
    )
    for spec in checks:
        term.write(
            term.paint(f"{spec.id:<14}", CYAN)
            + term.severity(spec.severity, f"{spec.severity.upper():<10}")
            + f"{spec.scope:<8}"
            + f"{spec.category:<16}"
            + f"{spec.title}"
        )
    term.write("")
    term.write(term.paint(f"Docs: {constants.DOCS_URL}", GREY))


# ------------------------------------------------------------------- exports
def _txt_report(report: ScanReport) -> str:
    summary = report.summary
    width = 100
    line = "=" * width
    parts = [
        line,
        f" {constants.TOOL_NAME}  ·  {constants.FULL_NAME}",
        f" v{constants.VERSION}  ·  created by {constants.AUTHOR}",
        f" {constants.SUPPORT_LINE}",
        line,
        "",
        "SCAN METADATA",
        f"  Scan ID       : {report.scan_id}",
        f"  Target        : {report.target.url}",
        f"  Started (UTC) : {summary.started_at}",
        f"  Finished (UTC): {summary.finished_at}",
        f"  Duration      : {summary.duration:.2f}s",
        f"  Requests      : {summary.requests} ({summary.request_errors} errors)",
        f"  Pages crawled : {summary.pages_crawled}",
        f"  Parameters    : {summary.parameters_tested}",
        f"  Checks        : {summary.checks_executed}/{summary.checks_available} executed",
        f"  Configuration : {json.dumps(report.config, sort_keys=True)}",
        "",
        "SUMMARY",
    ]
    for severity in SEVERITY_ORDER:
        parts.append(f"  {severity.upper():<9}: {summary.by_severity.get(severity, 0)}")
    parts.append(f"  {'TOTAL':<9}: {summary.total}")
    parts.append("")
    parts.append(line)
    parts.append("FINDINGS")
    parts.append(line)
    if not report.findings:
        parts.append("  No findings. This does not guarantee the target is secure.")
    for index, finding in enumerate(report.sorted_findings(), 1):
        parts.extend(
            [
                "",
                f"[{index}] {finding.severity.upper()}  {finding.check_id}  {finding.title}",
                f"    URL        : {finding.url}",
                f"    Method     : {finding.method}",
                f"    Parameter  : {finding.parameter or '-'}",
                f"    Confidence : {finding.confidence}",
                f"    CWE        : {finding.cwe or '-'}",
                f"    Source     : {finding.source}",
            ]
        )
        if finding.payload:
            parts.append(f"    Payload    : {finding.payload}")
        if finding.evidence:
            parts.append(_wrap("Evidence   : " + finding.evidence, width=width, indent=4))
        if finding.remediation:
            parts.append(_wrap("Remediation: " + finding.remediation, width=width, indent=4))
    parts.extend(["", line, "NOTES"])
    for note in report.notes:
        parts.append(_wrap("  · " + note, width=width, indent=0))
    if report.failed_checks:
        parts.append("")
        parts.append("CHECK ERRORS")
        for error in report.failed_checks:
            parts.append(f"  · {error}")
    parts.extend(
        [
            "",
            line,
            f" Docs    : {constants.DOCS_URL}",
            f" Issues  : {constants.ISSUES_URL}",
            f" Support : {constants.REPO_URL}",
            line,
            "",
        ]
    )
    return "\n".join(parts)


def _sanitize_host(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    return cleaned or "target"


def resolve_outputs(output: str, fmt: str, host: str) -> list[tuple[Path, str]]:
    fmt = (fmt or "auto").lower()
    if output:
        path = Path(output).expanduser()
        if path.is_dir():
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            path = path / f"aegis_{_sanitize_host(host)}_{stamp}"
        ext = path.suffix.lower()
        if fmt == "auto":
            if ext == ".json":
                return [(path, "json")]
            if ext == ".txt":
                return [(path, "txt")]
            return [(path.with_suffix(".json"), "json"), (path.with_suffix(".txt"), "txt")]
        if fmt == "both":
            base = path.with_suffix("") if ext in {".json", ".txt"} else path
            return [(Path(str(base) + ".json"), "json"), (Path(str(base) + ".txt"), "txt")]
        if fmt == "json":
            return [(path if ext == ".json" else path.with_suffix(".json"), "json")]
        return [(path if ext == ".txt" else path.with_suffix(".txt"), "txt")]

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = Path("reports") / f"aegis_{_sanitize_host(host)}_{stamp}"
    if fmt == "json":
        return [(base.with_suffix(".json"), "json")]
    if fmt == "txt":
        return [(base.with_suffix(".txt"), "txt")]
    return [(base.with_suffix(".json"), "json"), (base.with_suffix(".txt"), "txt")]


def export_report(report: ScanReport, output: str, fmt: str, term: Terminal) -> list[Path]:
    targets = resolve_outputs(output, fmt, report.target.netloc)
    written: list[Path] = []
    for path, kind in targets:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if kind == "json":
                content = json.dumps(report.as_dict(), indent=2, ensure_ascii=False, sort_keys=False) + "\n"
            else:
                content = _txt_report(report)
            path.write_text(content, encoding="utf-8")
            written.append(path)
            term.write(
                "  " + term.paint("saved ", GREEN)
                + term.paint(str(path.resolve()), WHITE)
                + term.paint(f"  ({kind})", GREY)
            )
        except OSError as exc:
            term.write("  " + term.paint(f"! could not write {path}: {exc}", YELLOW))
    return written


__all__ = ["render_report", "print_check_catalogue", "export_report", "resolve_outputs"]

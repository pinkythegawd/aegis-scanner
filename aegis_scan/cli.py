"""Command-line interface for AEGIS."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from . import constants
from .banner import print_scan_launch, print_welcome
from .colors import BOLD, CYAN, GREY, WHITE, YELLOW, Terminal
from .engine import ScanError, Scanner
from .models import ScanConfig, Target
from .registry import all_checks
from .report import export_report, print_check_catalogue, render_report

EPILOG = """examples:
  aegis https://authorized-target.example
  aegis scan https://authorized-target.example --deep --time-based -o report.json
  aegis https://authorized-target.example --test-forms --threads 24 -o reports/scan
  aegis checks
  python lab/vulnerable_server.py    # local intentionally-vulnerable lab

safe defaults:
  GET parameters only, time-based probes off, forms off, read-only payloads.
  Enable deeper testing only on systems you are authorized to test.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description=f"{constants.TOOL_NAME} — {constants.FULL_NAME}",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="target URL (http/https); bare hosts default to HTTPS")
    parser.add_argument("-t", "--threads", type=int, default=16, help="worker threads (default: 16, max: 64)")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds (default: 8)")
    parser.add_argument("--delay", type=float, default=0.0, help="minimum seconds between requests, globally (default: 0)")
    parser.add_argument("--max-pages", type=int, default=40, help="maximum pages to crawl (default: 40)")
    parser.add_argument("--depth", type=int, default=2, help="crawl depth (default: 2)")
    parser.add_argument("--max-params", type=int, default=40, help="maximum parameters to injection-test (default: 40)")
    parser.add_argument("--deep", action="store_true", help="use the expanded payload set (more requests)")
    parser.add_argument("--time-based", action="store_true", help="enable delay-based SQL injection probes")
    parser.add_argument("--test-forms", action="store_true", help="actively test form fields (POST/GET); may change state")
    parser.add_argument("-k", "--insecure", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'", help="extra request header (repeatable)")
    parser.add_argument("--cookie", default="", help="Cookie header value for authenticated scans")
    parser.add_argument("--user-agent", default=constants.DEFAULT_USER_AGENT, help="override the User-Agent")
    parser.add_argument("-o", "--output", default="", help="export path (.json/.txt or base name)")
    parser.add_argument("-f", "--format", choices=("auto", "json", "txt", "both"), default="auto", help="export format (default: infer)")
    parser.add_argument("-y", "--authorized", action="store_true", help="confirm written authorization for non-loopback targets")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--no-banner", action="store_true", help="suppress the ASCII welcome banner")
    parser.add_argument("--list-checks", action="store_true", help="print the check library and exit")
    parser.add_argument("-V", "--version", action="store_true", help="print version and exit")
    return parser


def _version(term: Terminal) -> int:
    term.write(term.paint(f"{constants.TOOL_NAME} v{constants.VERSION}", CYAN, BOLD))
    term.write(f"{constants.FULL_NAME}")
    term.write(f"created by {constants.AUTHOR}")
    term.write(constants.SUPPORT_LINE)
    term.write("Docs: " + term.link(constants.DOCS_URL))
    return 0


def _welcome_and_help(term: Terminal, parser: argparse.ArgumentParser) -> int:
    print_welcome(term)
    term.write(term.paint("QUICK START", CYAN, BOLD))
    term.write("  python aegis.py https://authorized-target.example")
    term.write("  python aegis.py https://authorized-target.example --deep --time-based -o report.json")
    term.write("  python aegis.py checks")
    term.write("  python lab/vulnerable_server.py   " + term.paint("# local lab, 127.0.0.1 only", GREY))
    term.write("")
    term.write(term.paint(f"Library: {len(all_checks())} checks", GREY))
    term.write("")
    term.write(parser.format_help())
    return 0


def _checks_command(args: list[str], term: Terminal) -> int:
    category = None
    if args:
        if args[0].startswith("-"):
            term.write(term.paint("Usage: aegis checks [category]", YELLOW))
            return 2
        category = args[0]
    print_check_catalogue(term, category)
    return 0


def _validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.target:
        parser.error("a target URL is required")
    if not 1 <= args.threads <= 64:
        parser.error("--threads must be between 1 and 64")
    if not 1 <= args.timeout <= 120:
        parser.error("--timeout must be between 1 and 120 seconds")
    if not 0 <= args.delay <= 60:
        parser.error("--delay must be between 0 and 60 seconds")
    if not 1 <= args.max_pages <= 500:
        parser.error("--max-pages must be between 1 and 500")
    if not 0 <= args.depth <= 5:
        parser.error("--depth must be between 0 and 5")
    if not 1 <= args.max_params <= 500:
        parser.error("--max-params must be between 1 and 500")
    for header in args.header:
        if ":" not in header:
            parser.error(f"invalid header {header!r}; expected 'Name: value'")
        name = header.split(":", 1)[0].strip()
        if not name or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name):
            parser.error(f"invalid header name {name!r}")
        if re.search(r"[\r\n]", header):
            parser.error("header values must not contain CR or LF")
    if re.search(r"[\r\n]", args.cookie or ""):
        parser.error("--cookie must not contain CR or LF")


def _authorize(target: Target, args: argparse.Namespace, term: Terminal) -> bool:
    if args.authorized:
        return True
    if target.is_loopback:
        term.write(
            "  " + term.paint("loopback target detected — authorization prompt skipped for local testing.", GREY)
        )
        return True
    term.write("")
    term.write("  " + term.paint("AUTHORIZATION REQUIRED", YELLOW, BOLD))
    term.write("  " + term.paint(constants.AUTHORIZATION_NOTICE, WHITE))
    term.write("  " + term.paint(f"Target: {target.url}", GREY))
    if not sys.stdin.isatty():
        term.write(
            "  " + term.paint('Non-interactive session: rerun with --authorized once you have written permission.', YELLOW)
        )
        return False
    try:
        answer = input(term.paint('  Type "I HAVE AUTHORIZATION" to continue: ', CYAN, BOLD))
    except (EOFError, KeyboardInterrupt):
        term.write("")
        return False
    if " ".join(answer.strip().upper().split()) != "I HAVE AUTHORIZATION":
        term.write("  " + term.paint("Authorization not confirmed. Scan aborted.", YELLOW))
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    force_no_color = "--no-color" in raw_args or os.environ.get("NO_COLOR") is not None
    term = Terminal(color=False if force_no_color else None)

    if raw_args and raw_args[0] in ("version", "--version", "-V"):
        return _version(term)
    if raw_args and raw_args[0] in ("checks", "list-checks", "--list-checks"):
        return _checks_command(raw_args[1:], term)

    parser = build_parser()
    if not raw_args:
        return _welcome_and_help(term, parser)
    if raw_args[0] in ("-h", "--help"):
        return _welcome_and_help(term, parser)
    if raw_args[0] == "scan":
        raw_args = raw_args[1:]

    args = parser.parse_args(raw_args)
    if args.version:
        return _version(term)
    if args.list_checks:
        print_check_catalogue(term)
        return 0
    _validate(args, parser)

    try:
        target = Target.parse(args.target)
    except ValueError as exc:
        term.write(term.paint(f"error: {exc}", YELLOW))
        return 2

    if not args.no_banner:
        print_scan_launch(term, target.url)
    if not _authorize(target, args, term):
        return 2

    config = ScanConfig(
        target_raw=args.target,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        max_pages=args.max_pages,
        depth=args.depth,
        max_params=args.max_params,
        deep=args.deep,
        time_based=args.time_based,
        test_forms=args.test_forms,
        insecure=args.insecure,
        headers=args.header,
        cookie=args.cookie,
        user_agent=args.user_agent,
        output=args.output,
        fmt=args.format,
        authorized=True,
        no_banner=args.no_banner,
    )
    mode = "deep" if args.deep else "standard"
    safety = "forms ON" if args.test_forms else "forms off"
    timing = "time-based ON" if args.time_based else "time-based off"
    term.write(
        "  " + term.paint("config ", GREY)
        + term.paint(f"threads={args.threads} · {mode} payloads · {safety} · {timing}", WHITE)
    )
    term.write(
        "  " + term.paint(
            "Only scan systems you own or have written permission to test. Payloads are read-only where possible.",
            GREY,
        )
    )

    try:
        scanner = Scanner(config, term)
        report = scanner.run()
    except ScanError as exc:
        term.write("")
        term.write("  " + term.paint(f"scan failed: {exc}", YELLOW, BOLD))
        term.write("  " + term.paint("Check the URL, network path, --timeout, and TLS settings (--insecure).", GREY))
        term.write("  " + term.paint("Docs: ", GREY) + term.link(constants.DOCS_URL))
        return 1
    except KeyboardInterrupt:
        term.write("")
        term.write("  " + term.paint("scan interrupted by user.", YELLOW))
        return 130

    render_report(report, term)

    if args.output or args.format != "auto":
        term.write("")
        export_report(report, args.output, args.format, term)
        term.write("")
    else:
        term.write(
            "  " + term.paint("Save results with: ", GREY)
            + term.paint(f"aegis {args.target} -o report.json", CYAN)
        )
        term.write("")

    return 0


__all__ = ["main", "build_parser"]

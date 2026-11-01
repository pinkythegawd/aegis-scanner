"""ASCII identity and welcome/launch screens."""

from __future__ import annotations

from . import constants
from .colors import BOLD, CYAN, DIM, GREY, MAGENTA, WHITE, Terminal

LOGO = (
    " █████╗  ███████╗  ██████╗  ██╗  ███████╗",
    "██╔══██╗ ██╔════╝ ██╔════╝  ██║  ██╔════╝",
    "███████║ █████╗   ██║  ███╗ ██║  ███████╗",
    "██╔══██║ ██╔══╝   ██║   ██║ ██║  ╚════██║",
    "██║  ██║ ███████╗ ╚██████╔╝ ██║  ███████║",
    "╚═╝  ╚═╝ ╚══════╝  ╚═════╝  ╚═╝  ╚══════╝",
)

_TAGLINE = "Automated Exposure & Guard Inspection Scanner"
_TECH = "proof-first detection · multithreaded · zero dependencies"


def print_banner(term: Terminal) -> None:
    palette = (CYAN, CYAN, WHITE, WHITE, MAGENTA, MAGENTA)
    for line, color in zip(LOGO, palette):
        term.write(term.paint(line, color, BOLD))
    term.write(term.paint(f"  {constants.TOOL_NAME} // {_TAGLINE}", CYAN, BOLD))
    term.write(term.paint(f"  {_TECH}", GREY))
    term.write("")


def print_support_line(term: Terminal) -> None:
    link = term.link(constants.REPO_URL)
    term.write(f"  {term.paint(constants.SUPPORT_LINE, WHITE, BOLD)}")
    term.write(
        "  "
        + term.paint("created by ", GREY)
        + term.paint("MikePinku", CYAN, BOLD)
        + term.paint("  ·  ", GREY)
        + term.paint(constants.GITHUB_HANDLE, CYAN)
        + term.paint("  ·  ", GREY)
        + link
    )


def print_welcome(term: Terminal, version: str = constants.VERSION) -> None:
    print_banner(term)
    term.write(term.rule(76))
    print_support_line(term)
    term.write("  " + term.paint("v" + version + "  ·  " + constants.WELCOME_SUBTITLE, DIM))
    term.write(term.rule(76))
    term.write("  " + term.paint(constants.AUTHORIZATION_NOTICE, GREY))
    term.write("  " + term.paint("Docs & payload catalogue: ", GREY) + term.link(constants.DOCS_URL))
    term.write("")


def print_scan_launch(term: Terminal, target: str) -> None:
    print_banner(term)
    term.write(term.rule(76))
    print_support_line(term)
    term.write(term.rule(76))
    term.write(
        "  "
        + term.paint("target  ", GREY)
        + term.paint(target, CYAN, BOLD)
        + term.paint("   docs  ", GREY)
        + term.link(constants.DOCS_URL)
    )
    term.write("  " + term.paint("Scope: passive + proof-based active checks, no destructive payloads.", GREY))
    term.write("")


__all__ = [
    "LOGO",
    "print_banner",
    "print_support_line",
    "print_welcome",
    "print_scan_launch",
]

"""ANSI color and terminal hyperlink support for Windows and POSIX shells."""

from __future__ import annotations

import os
import sys
from typing import TextIO

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
ITALIC = "\x1b[3m"
UNDERLINE = "\x1b[4m"

BLACK = "\x1b[30m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"
WHITE = "\x1b[37m"
GREY = "\x1b[90m"
BRIGHT_RED = "\x1b[91m"
BRIGHT_GREEN = "\x1b[92m"
BRIGHT_YELLOW = "\x1b[93m"
BRIGHT_CYAN = "\x1b[96m"

SEVERITY_STYLE = {
    "critical": (MAGENTA, BOLD),
    "high": (BRIGHT_RED, BOLD),
    "medium": (YELLOW, BOLD),
    "low": (GREEN, BOLD),
    "info": (CYAN,),
}

SEVERITY_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED",
    "low": "LOW",
    "info": "INFO",
}


def _enable_windows_vt() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


class Terminal:
    """Small wrapper that degrades safely when output is redirected."""

    def __init__(self, stream: TextIO | None = None, color: bool | None = None):
        self.stream = stream or sys.stdout
        self.is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        if color is None:
            color = self.is_tty and os.environ.get("NO_COLOR") is None
            if os.environ.get("FORCE_COLOR"):
                color = True
        self.color = bool(color)
        if self.color:
            _enable_windows_vt()

    def paint(self, text: str, *codes: str) -> str:
        if not self.color or not codes:
            return text
        return "".join(codes) + text + RESET

    def severity(self, severity: str, text: str | None = None) -> str:
        label = SEVERITY_LABEL.get(severity, severity.upper())
        return self.paint(text if text is not None else label, *SEVERITY_STYLE.get(severity, (WHITE,)))

    def link(self, url: str, text: str | None = None) -> str:
        label = text or url
        if not self.is_tty:
            return label if text else url
        # OSC 8 hyperlink; falls back cleanly to the visible label in unsupported terms.
        return f"\x1b]8;;{url}\x1b\\{label}\x1b]8;;\x1b\\"

    def write(self, text: str = "") -> None:
        try:
            self.stream.write(text + "\n")
            self.stream.flush()
        except UnicodeEncodeError:
            self.stream.write(text.encode("ascii", "replace").decode("ascii") + "\n")
            self.stream.flush()

    def rule(self, width: int = 76, char: str = "─") -> str:
        return self.paint(char * width, GREY)

    def clear_line(self) -> None:
        if self.is_tty:
            try:
                self.stream.write("\r\x1b[2K")
                self.stream.flush()
            except Exception:
                pass

    def progress(self, text: str) -> None:
        if self.is_tty:
            self.clear_line()
            self.stream.write(self.paint(text, GREY))
            self.stream.flush()

    def finish_progress(self) -> None:
        if self.is_tty:
            self.stream.write("\n")
            self.stream.flush()


__all__ = [
    "Terminal",
    "SEVERITY_STYLE",
    "SEVERITY_LABEL",
    "RESET",
    "BOLD",
    "DIM",
    "UNDERLINE",
    "RED",
    "GREEN",
    "YELLOW",
    "BLUE",
    "MAGENTA",
    "CYAN",
    "WHITE",
    "GREY",
    "BRIGHT_RED",
    "BRIGHT_GREEN",
    "BRIGHT_YELLOW",
    "BRIGHT_CYAN",
]

#!/usr/bin/env python3
"""AEGIS launcher.

Educational and authorized security testing only.
https://github.com/pinkythegawd/aegis-scanner
"""

from __future__ import annotations

import sys


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main() -> int:
    _configure_stdio()
    try:
        from aegis_scan.cli import main as cli_main
    except ImportError as exc:
        print(f"error: could not import AEGIS package ({exc})")
        print("Run this launcher from the project root: python aegis.py --help")
        return 1
    try:
        return cli_main()
    except KeyboardInterrupt:
        print("\ninterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

"""Project identity and shared constants."""

VERSION = "1.0.0"
TOOL_NAME = "AEGIS"
FULL_NAME = "Automated Exposure & Guard Inspection Scanner"
AUTHOR = "pinkythegawd (MikePinku)"
GITHUB_HANDLE = "pinkythegawd"
REPO_URL = "https://github.com/pinkythegawd/aegis-scanner"
DOCS_URL = f"{REPO_URL}#readme"
ISSUES_URL = f"{REPO_URL}/issues"

SUPPORT_LINE = f"this project is open source ! please support at : {REPO_URL}"
WELCOME_SUBTITLE = "WEB VULNERABILITY SCANNER"
AUTHORIZATION_NOTICE = (
    "Authorized security testing and education only. Never scan systems you do not own "
    "or have written permission to test."
)

DEFAULT_USER_AGENT = f"AEGIS/{VERSION} (+{REPO_URL})"
DEFAULT_TIMEOUT = 8.0
DEFAULT_THREADS = 16
DEFAULT_MAX_PAGES = 40
DEFAULT_MAX_PARAMS = 40
DEFAULT_DEPTH = 2
MAX_RESPONSE_BYTES = 3 * 1024 * 1024
MAX_REDIRECTS = 5

__all__ = [
    "VERSION",
    "TOOL_NAME",
    "FULL_NAME",
    "AUTHOR",
    "GITHUB_HANDLE",
    "REPO_URL",
    "DOCS_URL",
    "ISSUES_URL",
    "SUPPORT_LINE",
    "WELCOME_SUBTITLE",
    "AUTHORIZATION_NOTICE",
    "DEFAULT_USER_AGENT",
    "DEFAULT_TIMEOUT",
    "DEFAULT_THREADS",
    "DEFAULT_MAX_PAGES",
    "DEFAULT_MAX_PARAMS",
    "DEFAULT_DEPTH",
    "MAX_RESPONSE_BYTES",
    "MAX_REDIRECTS",
]

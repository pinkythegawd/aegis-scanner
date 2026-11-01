# **AEGIS**

### Automated Exposure & Guard Inspection Scanner

```text
 █████╗  ███████╗  ██████╗  ██╗  ███████╗
██╔══██╗ ██╔════╝ ██╔════╝  ██║  ██╔════╝
███████║ █████╗   ██║  ███╗ ██║  ███████╗
██╔══██║ ██╔══╝   ██║   ██║ ██║  ╚════██║
██║  ██║ ███████╗ ╚██████╔╝ ██║  ███████║
╚═╝  ╚═╝ ╚══════╝  ╚═════╝  ╚═╝  ╚══════╝
```

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Checks](https://img.shields.io/badge/check%20library-146-cyan)
![License](https://img.shields.io/badge/license-MIT-blue)

> this project is open source ! please support at : https://github.com/pinkythegawd/aegis-scanner

**AEGIS** is a proof-first web application vulnerability scanner built for **educational and security
research purposes**. It crawls an authorized target, inspects its transport, headers, cookies, and
exposure surface, then actively proves injection findings with unique runtime markers and
confirmation requests — instead of printing generic "may be vulnerable" output.

It detects **SQL injection, cross-site scripting, OS command injection, and XXE**, plus **142
additional checks** (146 total) across headers, cookies, CORS, TLS, content analysis, forms, HTTP
methods, and sensitive-file exposure. Everything runs on the Python standard library — there is
nothing to install with `pip`.

---

## Table of contents

- [Key features](#key-features)
- [CLI experience](#cli-experience)
- [Installation (Windows)](#installation-windows)
- [Usage](#usage)
- [The payload engine](#the-payload-engine)
- [Check library](#check-library)
- [Reports and exports](#reports-and-exports)
- [Bundled lab](#bundled-lab)
- [Limitations](#limitations)
- [Legal and ethical use](#legal-and-ethical-use)
- [Logo options](#logo-options)
- [Credits](#credits)

---

## Key features

- **146 checks in 9 categories** — 142 beyond the four core injection classes.
- **Core detections:** error/boolean/time-based SQL injection, reflected XSS, OS command injection,
  and XXE — each proven, not guessed.
- **Proprietary payloads, record time.** A scan of a typical application completes in **10–40 seconds**
  on a modern Windows machine, because payloads are targeted at proof rather than at breadth. The
  full 146-check library ran against the bundled lab in about 30 seconds with 16 threads.
- **Proof-first detection** — random tokens, server-computed arithmetic markers, boolean
  differentials, file-content signatures, and second-request confirmation.
- **Multithreaded** crawling, page analysis, exposure probing, and active parameter probes (up to
  64 workers).
- **Zero dependencies.** No `requests`, no `BeautifulSoup`, no virtual environment, no build step.
- **Windows-first CLI** — ANSI colors with automatic virtual-terminal enablement, OSC 8 clickable
  links, and an ASCII identity banner.
- **Safe by default** — GET parameters only, read-only payloads, no destructive verbs, time-based
  probes off, form injection off, same-site crawling only.
- **Authorization gate** for non-loopback targets, plus an intentionally vulnerable localhost lab.
- **Exports** to `.txt` and `.json` with a stable, documented schema.

---

## CLI experience

AEGIS treats the terminal as part of the product.

**Welcome screen.** Running `py aegis.py` with no target prints the ASCII logo, the project support
line, the version, the authorization notice, and a clickable documentation link.

**Scan launch.** When a scan starts, the banner is redrawn with the target, the docs link, and a
one-line scope reminder, so every screenshot is self-documenting.

**Clickable links.** Every URL is rendered as an OSC 8 hyperlink on Windows Terminal, Windows
Console with VT enabled, and modern PowerShell hosts. When the terminal does not support OSC 8, the
plain HTTPS URL is printed instead — never a broken escape sequence.

**Completion footer.** After the report, AEGIS prints the docs, issues, and support links again, plus
the scan ID and tool version, so a pasted report is traceable.

```text
────────────────────────────────────────────────────────────────────────────
  this project is open source ! please support at : https://github.com/pinkythegawd/aegis-scanner
  created by MikePinku  ·  pinkythegawd  ·  https://github.com/pinkythegawd/aegis-scanner
  v1.0.0  ·  WEB VULNERABILITY SCANNER
────────────────────────────────────────────────────────────────────────────
  Authorized security testing and education only.
  Docs & payload catalogue: https://github.com/pinkythegawd/aegis-scanner#readme
```

Severity is color-coded in the terminal:

| Severity | Color | Meaning |
| --- | --- | --- |
| Critical | Magenta | Direct compromise path, confirmed by proof |
| High | Bright red | Serious weakness with a realistic attack path |
| Medium | Yellow | Exploitable under common conditions |
| Low | Green | Hardening gap with limited direct impact |
| Info | Cyan | Context and attack-surface notes |

> **Pro Tip** — Windows Terminal gives the best result. In legacy consoles, colors still work because
> AEGIS enables virtual-terminal processing itself, but hyperlinks degrade to plain URLs.

---

## Installation (Windows)

### 1. Install Python 3.10 or newer

```powershell
winget install --id Python.Python.3.12 -e
```

Or download the installer from [python.org](https://www.python.org/downloads/windows/) and tick
**Add python.exe to PATH**.

Verify:

```powershell
py -3 --version
```

### 2. Install Git (if needed)

```powershell
winget install --id Git.Git -e
```

### 3. Clone the repository

```powershell
git clone https://github.com/pinkythegawd/aegis-scanner.git
Set-Location .\aegis-scanner
```

### 4. Verify the install

```powershell
py .\aegis.py --version
py .\aegis.py checks
```

There is **no `pip install` step**. AEGIS uses only the standard library.

> **Pro Tip** — Running a script by path (`py .\aegis.py`) does not require changing the PowerShell
> execution policy. You only need `Set-ExecutionPolicy` for `.ps1` scripts, not for Python files.

### 5. Optional: run from anywhere

```powershell
# Add a session alias
Set-Alias aegis "py C:\tools\aegis-scanner\aegis.py"
```

---

## Usage

### Quick start

```powershell
# 1. Show the welcome screen and logo
py .\aegis.py

# 2. Scan a target you own or are authorized to test
py .\aegis.py https://authorized-target.example -y

# 3. Deeper pass: expanded payloads, time-based SQLi, form fields
py .\aegis.py https://authorized-target.example -y --deep --time-based --test-forms

# 4. Save both report formats
py .\aegis.py https://authorized-target.example -y -o reports\scan -f both

# 5. Practice against the bundled vulnerable lab
py .\lab\vulnerable_server.py
py .\aegis.py http://127.0.0.1:8899 -y --deep --time-based --test-forms

# 6. Browse the check library
py .\aegis.py checks
py .\aegis.py checks injection
```

### What the output looks like

```text
SCAN METADATA
  Scan ID       : 0e471d20ab
  Target        : https://authorized-target.example
  Duration      : 12.84s
  Requests      : 146 (0 errors)
  Pages crawled : 24
  Parameters    : 7
  Checks        : 146/146 executed

SUMMARY
  CRITICAL : 1
  HIGH     : 2
  MEDIUM   : 3
  LOW      : 5
  INFO     : 4
  TOTAL    : 15

FINDINGS

[1] CRITICAL  AEG-SQLI-001  SQL injection — error-based
    URL        : https://authorized-target.example/item?id=1
    Method     : GET
    Parameter  : id
    Confidence : high
    CWE        : CWE-89
    Source     : active
    Evidence   : Database error signature appeared after payload injection and reproduced
                 on a confirmation request.
    Remediation: Use parameterized queries / prepared statements.

[2] HIGH      AEG-XSS-001   Reflected cross-site scripting
    URL        : https://authorized-target.example/search?q=test
    ...
```

### Common options

| Option | Description |
| --- | --- |
| `target` | Target URL. Bare hosts default to `https://`. |
| `-t, --threads N` | Worker threads, 1–64 (default 16). |
| `--timeout SECONDS` | Per-request timeout (default 8). |
| `--delay SECONDS` | Global minimum delay between requests (default 0). |
| `--max-pages N` | Crawl page cap (default 40). |
| `--depth N` | Crawl depth, 0–5 (default 2). |
| `--max-params N` | Injection parameter cap (default 40). |
| `--deep` | Expanded payload set (more requests, more coverage). |
| `--time-based` | Enable delay-based SQL injection probes. |
| `--test-forms` | Actively inject non-password form fields; may change state. |
| `-H 'Name: value'` | Extra request header; repeatable. |
| `--cookie 'a=b; c=d'` | Cookie header for authenticated scans. |
| `-o, --output PATH` | Export path or base name. |
| `-f, --format FMT` | `auto`, `json`, `txt`, or `both`. |
| `-y, --authorized` | Confirm written authorization for non-loopback targets. |
| `--no-color`, `--no-banner` | Plain output for logs and CI. |
| `-k, --insecure` | Disable TLS verification (lab use only). |

> **Pro Tip** — Keep `--delay 0.3` or higher on production systems. It caps the scan near three
> requests per second and keeps a 64-thread run from looking like a denial of service.

> **Pro Tip** — `--test-forms` sends real POST requests. Use a throwaway account and a maintenance
> window, never a staff account on a live registration flow.

> **Pro Tip** — In CI, run with `--no-color --no-banner -f json` so the report is machine-readable and
> the log stays clean.

### Authorization behavior

Loopback targets (`localhost`, `127.0.0.0/8`, `::1`) are allowed without a prompt so the bundled lab
works out of the box. Every other target requires `--authorized` or an interactive exact-phrase
confirmation. In a non-interactive session without the flag, AEGIS aborts before sending a single
request.

---

## The payload engine

Most scanners parse a response for strings that *might* indicate a vulnerability. That produces
noise: a page that prints the word "error", a 404 that echoes a path, or a WAF block page can all
look like findings.

AEGIS payloads are built to **prove** execution. Each family carries a property that cannot appear
by accident, and every hit is re-requested before it reaches the report.

| Dimension | Typical signature check | AEGIS proof |
| --- | --- | --- |
| SQL injection | Sends `'` and looks for "SQL syntax" anywhere | Error signature must be absent from the control baseline **and** reproduce on a second request; boolean pairs compared with a similarity threshold; optional `SLEEP` timing measured against control latency |
| Reflected XSS | Searches the body for `<script>` | Random token must appear **unencoded** inside live markup (`<svg`, `<script`, `<img`), then reproduce on a second request |
| Command injection | Looks for `uid=` or `root:` | Shell arithmetic that the **server computes** to a value the client never sent, reproduced twice |
| XXE | Injects a DOCTYPE and hopes | Entity resolves to Linux/Windows file-content signatures absent from the baseline |
| SSTI | Sends `{{7*7}}` and looks for `49` | Template expression evaluated to a **random product** generated per scan |
| LFI | Sends `../../etc/passwd` | Recognizable local-file signature absent from the control response |
| Open redirect | Flags any 3xx | External `Location` containing a **fresh token**, confirmed with a second token |
| CRLF injection | Sends `%0d%0a` | Injected header name/value observed in the response, confirmed with a second request |
| NoSQL / LDAP | Greps for error text | Driver/parser error signature absent from the control, re-requested |

This is why the scan is fast: **fewer requests, each one decisive.** The default pass is read-only
and GET-only; deeper families are opt-in.

| Level | Flag | What it adds | When to use |
| --- | --- | --- | --- |
| Safe (default) | — | Core proofs on GET parameters, headers, exposures | Any authorized scan |
| Expanded | `--deep` | Larger payload sets, more encodings and suffixes | Staging or a quiet window |
| Timing | `--time-based` | `SLEEP`-style SQLi confirmation | When error/boolean proofs are inconclusive |
| Stateful | `--test-forms` | POST/GET form-field injection | Throwaway account, controlled window |

Payload families include error/boolean/time SQLi, MySQL/PostgreSQL/MSSQL/Oracle signatures,
reflected XSS contexts, shell metacharacter chains, SSTI syntax for Jinja/Twig/Freemarker, traversal
encodings, CRLF header injection, open-redirect parameters, NoSQL operators, LDAP filters, and XML
entity sets for Linux and Windows targets.

> **Pro Tip** — `--deep` does not make findings more severe; it makes coverage broader. If a default
> run is clean on a parameter you care about, `--deep` is the next step before concluding anything.

> **Pro Tip** — Time-based SQLi is the slowest check family by design. Run it only after the
> error-based and boolean proofs are clean, and only with `--delay` set.

---

## Check library

146 checks across 9 categories:

| Category | Checks | Examples |
| --- | ---: | --- |
| Exposures | 89 | `.git/`, `.env`, SSH keys, cloud credentials, database dumps, backups, config files, logs, Actuator, Swagger/OpenAPI, Jenkins, Tomcat, phpMyAdmin, WordPress endpoints |
| Headers | 14 | HSTS, CSP, clickjacking, nosniff, Referrer-Policy, Permissions-Policy, COOP/COEP, version disclosure |
| Injection | 12 | SQLi (error, boolean, time), XSS, command injection, XXE, SSTI, LFI, open redirect, CRLF, NoSQL, LDAP |
| Content | 11 | Mixed content, source maps, generator versions, secrets in comments, verbose errors, DOM XSS patterns, missing SRI, reverse tabnabbing |
| Transport | 7 | HTTPS availability, HTTP→HTTPS redirect, deprecated TLS, weak ciphers, expiry, trust, hostname match |
| Cookies | 5 | Secure, HttpOnly, SameSite, parent-domain scope, cookie prefixes |
| CORS | 3 | Wildcard, reflected origin, `null` origin |
| Forms | 3 | Password over GET, autocomplete, missing anti-CSRF token |
| HTTP Methods | 2 | Dangerous verbs advertised, TRACE enabled |

### Core detections

| Vulnerability | Check ID | Severity | Proof signal |
| --- | --- | --- | --- |
| SQL injection — error-based | `AEG-SQLI-001` | CRITICAL | New database error signature vs control |
| SQL injection — boolean | `AEG-SQLI-002` | HIGH | True/false response differential |
| SQL injection — time-based | `AEG-SQLI-003` | HIGH | Delay vs control latency |
| Reflected XSS | `AEG-XSS-001` | HIGH | Unencoded token in live markup |
| OS command injection | `AEG-CMDI-001` | CRITICAL | Server-computed arithmetic marker |
| XXE | `AEG-XXE-001` | CRITICAL | Local file content signature |
| Server-side template injection | `AEG-SSTI-001` | HIGH | Evaluated random product |
| Local file inclusion | `AEG-LFI-001` | HIGH | Local file signature |
| NoSQL injection | `AEG-NOSQL-001` | HIGH | Driver error signature |
| LDAP injection | `AEG-LDAP-001` | MEDIUM | Parser error signature |
| Open redirect | `AEG-REDIR-001` | MEDIUM | External `Location` with fresh token |
| CRLF injection | `AEG-CRLF-001` | MEDIUM | Injected header observed twice |

Run `py .\aegis.py checks` for the complete ID, severity, scope, and category catalogue.

### False-positive controls

- Control baseline captured before any payload is sent.
- Confirmation request for every injection hit.
- Soft-404 suppression for exposure checks.
- Redirect-path validation: evidence must come from the requested path, not a redirect to `/`.
- Error-signature subtraction against the baseline.
- Minimum similarity differential for boolean SQLi.
- Finding dedupe keyed by check, endpoint, parameter, and method.

---

## Reports and exports

```powershell
py .\aegis.py https://authorized-target.example -y -o report.json
py .\aegis.py https://authorized-target.example -y -o report.txt
py .\aegis.py https://authorized-target.example -y -o reports\scan -f both
```

With no `-o` and an explicit format, files land in `reports\` with a timestamp and the target
hostname. Exports are UTF-8 and parent directories are created automatically. The JSON schema is
stable:

```json
{
  "report": {
    "tool": "AEGIS",
    "version": "1.0.0",
    "author": "pinkythegawd (MikePinku)",
    "github": "https://github.com/pinkythegawd/aegis-scanner",
    "scan_id": "0e471d20ab",
    "generated_at": "2026-11-01T23:07:09Z"
  },
  "target": { "url": "...", "host": "...", "port": 443, "scheme": "https" },
  "config": { "threads": 16, "deep_payloads": false, "time_based": false, "test_forms": false },
  "summary": { "total": 15, "by_severity": { "critical": 1, "high": 2, "medium": 3, "low": 5, "info": 4 } },
  "findings": [
    {
      "check_id": "AEG-SQLI-001",
      "title": "SQL injection — error-based",
      "severity": "critical",
      "cwe": "CWE-89",
      "confidence": "high",
      "method": "GET",
      "url": "https://.../item?id=1",
      "parameter": "id",
      "evidence": "Database error signature reproduced on a confirmation request.",
      "remediation": "Use parameterized queries / prepared statements."
    }
  ],
  "checks_executed": 146,
  "checks_failed": [],
  "notes": []
}
```

---

## Bundled lab

`lab\vulnerable_server.py` is an intentionally insecure server bound to **127.0.0.1:8899**. It
simulates every detection class: SQL/NoSQL/LDAP errors, boolean and time-based SQLi, reflected XSS,
command injection, SSTI, LFI, XXE, CRLF, open redirects, host-header injection, misconfigured
headers/CORS/cookies, forms, directory listings, GraphQL introspection, and a broad set of exposed
paths.

```powershell
py .\lab\vulnerable_server.py
# in a second terminal
py .\aegis.py http://127.0.0.1:8899 -y --deep --time-based --test-forms -o reports\lab
```

The lab contains no real credentials and is deliberately unsafe. Never expose it to a network.

---

## Limitations

- AEGIS is an automated black-box scanner. Validate findings manually before remediation or
  disclosure; absence of findings does not prove a target is secure.
- Authenticated coverage depends on the cookies or headers you supply, and only reaches linked pages
  within the crawl budget and same-host scope.
- JavaScript-rendered content, WebSocket-only APIs, and JSON request bodies are not exercised.
- Header and exposure checks are high-signal but policy-oriented; treat severity as a starting point.
- Time-based probing adds latency and is intentionally opt-in.

---

## Legal and ethical use

AEGIS is provided for **education and authorized security research only**. Use it on systems you own
or have explicit written permission to test. Unauthorized scanning may violate computer-misuse laws
and a target's terms of service. You are responsible for every request you send.

> **Pro Tip** — Keep written authorization on file before a scan, and record the scan ID from the
> report footer. It makes remediation and disclosure conversations much easier.

---

## Logo options

Option A is the active banner in `aegis_scan\banner.py`. Swap in B or C by replacing the `LOGO`
tuple in that file and the code block above.

**Option A — block identity (current)**

```text
 █████╗  ███████╗  ██████╗  ██╗  ███████╗
██╔══██╗ ██╔════╝ ██╔════╝  ██║  ██╔════╝
███████║ █████╗   ██║  ███╗ ██║  ███████╗
██╔══██║ ██╔══╝   ██║   ██║ ██║  ╚════██║
██║  ██║ ███████╗ ╚██████╔╝ ██║  ███████║
╚═╝  ╚═╝ ╚══════╝  ╚═════╝  ╚═╝  ╚══════╝
```

**Option B — shield**

```text
        ▄▄▄▄▄▄▄▄▄
     ▄█▀         ▀█▄
   ▄█▀    ▲ ▲    ▀█▄
  ██     ◄ ● ►     ██
  ██      ▼       ██
   ▀█▄           ▄█▀
     ▀█▄       ▄█▀
       ▀█▄   ▄█▀
         ▀█▄█▀
          ▀▀▀
```

**Option C — boxed wordmark**

```text
┌───────────────────────────────────────────┐
│  A E G I S                                │
│  automated exposure & guard inspection    │
└───────────────────────────────────────────┘
```

---

## Credits

Created and maintained by **pinkythegawd (MikePinku)**.

- GitHub: [github.com/pinkythegawd](https://github.com/pinkythegawd)
- Repository: [github.com/pinkythegawd/aegis-scanner](https://github.com/pinkythegawd/aegis-scanner)
- Issues: [github.com/pinkythegawd/aegis-scanner/issues](https://github.com/pinkythegawd/aegis-scanner/issues)
- Support: [github.com/pinkythegawd/aegis-scanner](https://github.com/pinkythegawd/aegis-scanner)

> this project is open source ! please support at : https://github.com/pinkythegawd/aegis-scanner

Released under the MIT License. Built for learning, for research, and for defenders who want proof.

Made by **MikePinku**.

#!/usr/bin/env python3
"""AEGIS local lab — intentionally vulnerable, localhost only.

This server exists so the scanner can be tested safely. It is NOT production
code. Bind stays on 127.0.0.1 and contains no real credentials.
"""

from __future__ import annotations

import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

HOST = "127.0.0.1"
DEFAULT_PORT = 8899

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
FAKE_WININI = "[fonts]\n[extensions]\nfor 16-bit app support\n[files]\n"
DEBUG_TRACE = (
    "Traceback (most recent call last):\n"
    '  File "/opt/lab/app.py", line 42, in handler\n'
    "    return eval(user_value)\n"
    "NameError: name 'aegis_probe' is not defined"
)
SECRET_COMMENT = '<!-- legacy admin password = "LabOnly-NotReal-123" -->'
FAKE_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "FAKEFAKEFAKEFAKE-not-a-real-key-FAKEFAKEFAKEFAKE\n"
    "-----END RSA PRIVATE KEY-----\n"
)


def page(title: str, body: str, host: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <meta name="generator" content="LocalLab 1.0.0">
  <link rel="canonical" href="http://{host}/">
  <script src="https://cdn.example.org/aegis-lib.js"></script>
  {SECRET_COMMENT}
</head>
<body>
  <h1>{title}</h1>
  {body}
  <hr>
  <p>Contact: security@lab.local</p>
  <p><a href="https://example.org/" target="_blank">external reference</a></p>
  <script>
    const apiKey = "AKIAABCDEFGHIJKLMNOP";
    const output = document.getElementById("out");
    if (output) {{ output.innerHTML = location.hash; }}
    //# sourceMappingURL=app.js.map
  </script>
</body>
</html>"""


HOME_BODY = f"""
<p>Intentionally vulnerable lab. <a href="/search?q=hello">Search</a> ·
   <a href="/item?id=1">Item</a> · <a href="/page2">Page 2</a> ·
   <a href="/debug">Debug</a> · <a href="/redirect?next=/home">Redirect</a></p>
<form action="/login" method="get">
  <input type="password" name="password">
  <button type="submit">GET login</button>
</form>
<form action="/login" method="post">
  <input type="text" name="username" placeholder="username">
  <input type="password" name="password" autocomplete="on" placeholder="password">
  <button type="submit">POST login</button>
</form>
<form action="/comment" method="post">
  <textarea name="comment" placeholder="comment"></textarea>
  <button type="submit">Post comment</button>
</form>
<div id="out"></div>
"""


def computed_markers(value: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"AGCMD([A-Z0-9]{4,})\$\(\((\d+)\*(\d+)\)\)", value):
        found.append(f"AGCMD{match.group(1)}{int(match.group(2)) * int(match.group(3))}")
    for match in re.finditer(r"AGCMD([A-Z0-9]{4,})%COMSPEC:~-3%", value, re.I):
        found.append(f"AGCMD{match.group(1)}exe")
    for match in re.finditer(r"set /a (\d+)\*(\d+)", value):
        found.append(str(int(match.group(1)) * int(match.group(2))))
    template_patterns = (
        r"\{\{(\d+)\*(\d+)\}\}",
        r"\$\{(\d+)\*(\d+)\}",
        r"<%=\s*(\d+)\*(\d+)\s*%>",
        r"#\{(\d+)\*(\d+)\}",
        r"\*\{(\d+)\*(\d+)\}",
        r"@\((\d+)\*(\d+)\)",
    )
    for pattern in template_patterns:
        for match in re.finditer(pattern, value):
            found.append(str(int(match.group(1)) * int(match.group(2))))
    return found


def sql_view(value: str) -> tuple[str, str]:
    lowered = value.lower()
    has_and = " and " in lowered
    false_condition = re.search(r"(?i)(?:'|\")?1(?:'|\")?\s*=\s*(?:'|\")?2(?:'|\")?", value)
    true_condition = re.search(r"(?i)(?:'|\")?1(?:'|\")?\s*=\s*(?:'|\")?1(?:'|\")?", value)
    if has_and and false_condition:
        return "result", "No results found."
    if has_and and true_condition:
        return "result", (
            '<div class="result">Alpha service</div>'
            '<div class="result">Bravo service</div>'
            '<div class="result">Charlie service</div>'
            '<div class="result">Delta service</div>'
        )
    if "'" in value or '"' in value:
        return (
            "error",
            "You have an error in your SQL syntax; check the manual that corresponds to "
            "your MySQL server version for the right syntax to use near the input.",
        )
    return (
        "result",
        '<div class="result">Alpha service</div>'
        '<div class="result">Bravo service</div>'
        '<div class="result">Charlie service</div>'
        '<div class="result">Delta service</div>',
    )


def vulnerable_page(value: str, host: str, title: str = "Search results") -> str:
    mode, rows = sql_view(value)
    extra: list[str] = []
    if "etc/passwd" in value.lower() or "....//" in value:
        extra.append(f"<pre>{FAKE_PASSWD}</pre>")
    if "win.ini" in value.lower():
        extra.append(f"<pre>{FAKE_WININI}</pre>")
    if "$ne" in value or "$gt" in value:
        extra.append("<pre>MongoError: unknown operator: $ne</pre>")
    if ")(uid=" in value or "objectclass" in value.lower():
        extra.append("<pre>javax.naming.directory.InvalidSearchFilterException: LDAP error</pre>")
    if "sleep(3)" in value.lower():
        time.sleep(3)
    extra.extend(computed_markers(value))
    body = (
        f'<p>You searched for: <span id="q">{value}</span></p>'
        f'<div class="{mode}">{rows}</div>'
        + "".join(f"<div>{item}</div>" for item in extra)
    )
    return page(title, body, host)


class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabHTTP/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------ helpers
    def log_message(self, fmt: str, *args) -> None:
        print(f"  [{self.command}] {self.path} -> {args[1] if len(args) > 1 else ''}")

    def _read_body(self) -> str:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(min(length, 1_000_000)) if length else b""
        charset = "utf-8"
        content_type = (self.headers.get("Content-Type") or "").lower()
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return raw.decode(charset, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")

    def _host(self) -> str:
        return self.headers.get("Host", f"{HOST}:{self.server.server_port}")

    def _send(
        self,
        status: int,
        body: str | bytes,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        data = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Set-Cookie", "sessionid=lab-session-value; Path=/")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Powered-By", "LocalLab/1.0")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _not_found(self) -> None:
        self._send(404, page("Not Found", "<p>Nothing here.</p>", self._host()))

    def _query_value(self) -> str:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        for key in ("q", "id", "comment", "search"):
            if key in query:
                return query[key][0]
        return ""

    # -------------------------------------------------------------------- verbs
    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        host = self._host()
        extra_headers: dict[str, str] = {}

        # Simulated CRLF response splitting when the payload reaches a header.
        for values in query.values():
            for value in values:
                match = re.search(r"\r\n(Aegis-Probe-[A-Za-z0-9]+): hit", value)
                if match:
                    extra_headers[match.group(1)] = "hit"

        if path in ("/", "/home", "/index.html"):
            self._send(200, page("AEGIS Local Lab", HOME_BODY, host), extra_headers=extra_headers)
            return
        if path == "/search":
            self._send(200, vulnerable_page(self._query_value(), host), extra_headers=extra_headers)
            return
        if path == "/item":
            value = query.get("id", ["1"])[0]
            self._send(200, vulnerable_page(value, host, "Item"), extra_headers=extra_headers)
            return
        if path == "/page2":
            self._send(200, page("Page 2", "<p>Second page.</p>", host), extra_headers=extra_headers)
            return
        if path == "/debug":
            self._send(200, page("Debug", f"<pre>{DEBUG_TRACE}</pre>", host), extra_headers=extra_headers)
            return
        if path == "/redirect":
            destination = query.get("next", ["/home"])[0]
            if destination.lower().startswith(("http://", "https://")):
                self.send_response(302)
                self.send_header("Location", destination)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(
                200,
                page("Redirect", f'<p>Continue to <a href="{destination}">{destination}</a></p>', host),
                extra_headers=extra_headers,
            )
            return
        if path == "/login":
            body = (
                '<form action="/login" method="post">'
                '<input type="password" name="password"><button>Login</button></form>'
            )
            self._send(200, page("Login", body, host), extra_headers=extra_headers)
            return
        if path == "/api":
            if self.headers.get("Origin"):
                extra_headers.update(
                    {
                        "Access-Control-Allow-Origin": self.headers["Origin"],
                        "Access-Control-Allow-Credentials": "true",
                    }
                )
            self._send(200, json.dumps({"ok": True}), "application/json", extra_headers=extra_headers)
            return

        sensitive = self._sensitive(path)
        if sensitive is not None:
            body, content_type = sensitive
            self._send(200, body, content_type, extra_headers=extra_headers)
            return
        if path == "/uploads/":
            self._send(
                200,
                "<html><head><title>Index of /uploads</title></head><body>"
                "<h1>Index of /uploads</h1><a href='report.pdf'>report.pdf</a></body></html>",
                extra_headers=extra_headers,
            )
            return
        self._not_found()

    def do_POST(self) -> None:
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        body = self._read_body()
        content_type = (self.headers.get("Content-Type") or "").lower()
        host = self._host()

        if path in ("/", "/xml") and ("file:///etc/passwd" in body or "file:///C:/Windows/win.ini" in body):
            payload = FAKE_PASSWD if "etc/passwd" in body else FAKE_WININI
            self._send(200, payload, "application/xml")
            return
        if path == "/graphql":
            response = json.dumps(
                {"data": {"__schema": {"queryType": {"name": "Query"}}}}
            ).encode()
            self._send(200, response, "application/json")
            return
        if path == "/comment":
            fields = parse_qs(body, keep_blank_values=True)
            value = fields.get("comment", [""])[0]
            self._send(200, vulnerable_page(value, host, "Comment preview"))
            return
        if path == "/login":
            fields = parse_qs(body, keep_blank_values=True)
            username = fields.get("username", ["guest"])[0]
            self._send(200, page("Login result", f"<p>Welcome {username}</p>", host))
            return
        self._send(404, page("Not Found", "<p>No POST handler.</p>", host))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self) -> None:
        data = f"TRACE {self.path} {self.request_version}\r\n".encode()
        for name, value in self.headers.items():
            data += f"{name}: {value}\r\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_HEAD(self) -> None:
        self.do_GET()

    # ---------------------------------------------------------------- exposures
    def _sensitive(self, path: str) -> tuple[str | bytes, str] | None:
        text_html = "text/html; charset=utf-8"
        if path == "/.env":
            return (
                "APP_KEY=base64:NOTAREALSECRETNOTAREALSECRET\n"
                "DB_PASSWORD=not-a-real-password\n"
                "AWS_SECRET_ACCESS_KEY=FAKEFAKEFAKEFAKE\n",
                "text/plain; charset=utf-8",
            )
        if path == "/.env.production":
            return ("APP_ENV=production\nSECRET_KEY=FAKEKEY\n", "text/plain; charset=utf-8")
        if path == "/.git/HEAD":
            return ("ref: refs/heads/main\n", "text/plain; charset=utf-8")
        if path == "/.git/config":
            return ("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.invalid/repo\n", "text/plain")
        if path == "/.git/logs/HEAD":
            return ("0" * 40 + " " + "a" * 40 + " lab <lab@local> 1700000000 +0000\tcommit: init\n", "text/plain")
        if path == "/.git/index":
            return (b"DIRC\x00\x00\x00\x02" + b"\x00" * 64, "application/octet-stream")
        if path == "/id_rsa":
            return (FAKE_PRIVATE_KEY, "text/plain")
        if path == "/backup.sql":
            return (
                "-- MySQL dump\nCREATE TABLE users (id INT, name VARCHAR(64));\nINSERT INTO users VALUES (1,'lab');\n",
                "text/plain",
            )
        if path == "/config.json":
            return ('{"database":"lab","apiKey":"FAKE-API-KEY","password":"FAKE"}', "application/json")
        if path == "/error.log":
            return ("PHP Warning:  Undefined variable in /var/www/lab.php on line 4\n", "text/plain")
        if path == "/access.log":
            return ('127.0.0.1 - - [01/Nov/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 100\n', "text/plain")
        if path == "/phpinfo.php":
            return ("<title>phpinfo()</title><h1>PHP Version 8.3</h1>", text_html)
        if path == "/server-status":
            return ("<html><title>Apache Server Status</title>requests currently being processed: 2</html>", text_html)
        if path == "/server-info":
            return ("<html>Apache Server Information - Server Settings</html>", text_html)
        if path == "/trace.axd":
            return ("<html><title>Application Trace</title>Trace Information</html>", text_html)
        if path == "/actuator/env":
            return ('{"activeProfiles":["prod"],"propertySources":[{"name":"lab"}]}', "application/json")
        if path == "/actuator/health":
            return ('{"status":"UP"}', "application/json")
        if path == "/swagger-ui.html":
            return ("<html><title>Swagger UI</title></html>", text_html)
        if path == "/openapi.json":
            return ('{"openapi":"3.0.0","paths":{"/api":{"get":{}}}}', "application/json")
        if path == "/h2-console":
            return ("<html><title>H2 Console</title>Login</html>", text_html)
        if path == "/manager/html":
            return ("<html>Tomcat Web Application Manager</html>", text_html)
        if path == "/jenkins/script":
            return ("<html><title>Script Console</title>Jenkins</html>", text_html)
        if path == "/jenkins/":
            return ("<html>Jenkins Dashboard</html>", text_html)
        if path == "/phpmyadmin/":
            return ("<html>phpMyAdmin login</html>", text_html)
        if path == "/admin/":
            return ('<html><title>Admin login</title><input type="password" name="p"></html>', text_html)
        if path == "/metrics":
            return ("# HELP lab_requests_total\n# TYPE lab_requests_total counter\n", "text/plain")
        if path == "/debug/pprof/":
            return ("<html>Types of profiles available: profile goroutine</html>", text_html)
        if path == "/wp-json/wp/v2/users":
            return ('[{"id":1,"name":"admin","slug":"admin"}]', "application/json")
        if path == "/xmlrpc.php":
            return ("XML-RPC server accepts POST requests only.", "text/plain")
        if path == "/readme.html":
            return ("<html>WordPress Version 6.4</html>", text_html)
        if path == "/wp-content/debug.log":
            return ("PHP Warning:  Undefined array key in /var/www/wp-content/plugins/x.php\n", "text/plain")
        if path == "/crossdomain.xml":
            return ('<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>', "application/xml")
        if path == "/robots.txt":
            return ("User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /internal-api/\n", "text/plain")
        if path == "/backup/":
            return ("<html><title>Index of /backup</title><a href='db.sql'>db.sql</a></html>", text_html)
        return None


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="AEGIS intentionally vulnerable local lab")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    server = ThreadingHTTPServer((HOST, args.port), LabHandler)
    server.daemon_threads = True
    print("=" * 68)
    print(" AEGIS local vulnerable lab — INTENTIONALLY INSECURE")
    print(f" URL: http://{HOST}:{args.port}/")
    print(" Bind: localhost only. No real credentials are present.")
    print(" Use only for testing AEGIS. Press Ctrl+C to stop.")
    print("=" * 68)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping lab.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

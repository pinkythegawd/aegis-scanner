"""Thread-safe stdlib HTTP client, cookie handling, and TLS inspection."""

from __future__ import annotations

import gzip
import http.client
import os
import re
import socket
import ssl
import tempfile
import threading
import time
import zlib
from email.message import Message
from http.cookies import SimpleCookie
from typing import Any, Iterable
from urllib.parse import quote, urljoin, urlencode, urlsplit, urlunsplit

from .constants import DEFAULT_USER_AGENT, MAX_REDIRECTS, MAX_RESPONSE_BYTES
from .models import Response, ScanConfig

_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([\w\-]+)", re.I)
_META_CHARSET_RE = re.compile(rb"<meta[^>]+charset\s*=\s*[\"']?([\w\-]+)", re.I)
_PATH_SAFE = "/%:@!$&'()*+,;=-._~"
_QUERY_SAFE = "=&%:@!$'()*+,;/?-._~[]"


def _parse_custom_headers(values: Iterable[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values or []:
        if ":" not in raw:
            raise ValueError(f"invalid header (expected 'Name: value'): {raw!r}")
        name, value = raw.split(":", 1)
        name = name.strip()
        if not name or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name):
            raise ValueError(f"invalid header name: {raw!r}")
        if re.search(r"[\r\n]", value):
            raise ValueError(f"invalid header value: {raw!r}")
        headers[name] = value.strip()
    return headers


class HttpClient:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.timeout = max(1.0, float(config.timeout))
        self.delay = max(0.0, float(config.delay))
        self._insecure = bool(config.insecure)
        self._ssl_context = self._make_context(self._insecure)
        self._default_headers = _parse_custom_headers(config.headers)
        self._user_cookie = (config.cookie or "").strip()
        self._user_agent = config.user_agent or DEFAULT_USER_AGENT
        self._cookies: dict[str, dict[str, str]] = {}
        self._cookie_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._next_slot = 0.0
        self._requests = 0
        self._errors = 0
        self._bytes = 0
        self.last_cert_error = ""
        self.scope_host = ""

    # ------------------------------------------------------------------ state
    @property
    def insecure(self) -> bool:
        return self._insecure

    def enable_insecure(self) -> None:
        self._insecure = True
        self._ssl_context = self._make_context(True)

    def _make_context(self, insecure: bool) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    @property
    def base_headers(self) -> dict[str, str]:
        return dict(self._default_headers)

    def stats(self) -> dict[str, int]:
        with self._stats_lock:
            return {"requests": self._requests, "errors": self._errors, "bytes": self._bytes}

    def reset_stats(self) -> None:
        with self._stats_lock:
            self._requests = 0
            self._errors = 0
            self._bytes = 0

    # ------------------------------------------------------------------ public
    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data: Any = None, **kwargs: Any) -> Response:
        return self.request("POST", url, data=data, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def trace(self, url: str, **kwargs: Any) -> Response:
        return self.request("TRACE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        return self.request("HEAD", url, **kwargs)

    def request(
        self,
        method: str,
        url: str,
        data: Any = None,
        headers: dict[str, str] | None = None,
        follow: bool = True,
        timeout: float | None = None,
    ) -> Response:
        method = (method or "GET").upper()
        current_url = url
        current_method = method
        current_data = data
        history: list[str] = []
        started = time.perf_counter()
        final = Response(url=current_url, method=method)

        for hop in range(MAX_REDIRECTS + 1):
            response = self._send_once(
                current_method,
                current_url,
                current_data,
                headers=headers,
                follow_redirects=follow,
                timeout=timeout,
            )
            response.history = history + [current_url] if history else [current_url]
            final = response
            if not follow or response.error or response.status not in (301, 302, 303, 307, 308):
                break
            location = response.header("location")
            if not location:
                break
            target_url = urljoin(current_url, location.strip())
            if not self._in_scope(target_url):
                break
            if hop >= MAX_REDIRECTS:
                break
            history.append(current_url)
            if response.status in (301, 302, 303) and current_method not in {"HEAD"}:
                current_method = "GET"
                current_data = None
            if response.status == 303:
                current_data = None
            current_url = urljoin(current_url, location.strip())

        final.history = history or [url]
        final.elapsed = time.perf_counter() - started
        return final

    # ---------------------------------------------------------------- internals
    def _in_scope(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        host = parts.hostname.lower()
        scope = (self.scope_host or host).lower()
        bare_scope = scope[4:] if scope.startswith("www.") else scope
        bare_host = host[4:] if host.startswith("www.") else host
        return bare_host == bare_scope

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        with self._rate_lock:
            now = time.monotonic()
            wait = self._next_slot - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next_slot = max(now, self._next_slot) + self.delay

    def _count(self, *, error: bool = False, size: int = 0) -> None:
        with self._stats_lock:
            self._requests += 1
            if error:
                self._errors += 1
            self._bytes += size

    def _send_once(
        self,
        method: str,
        url: str,
        data: Any = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        timeout: float | None = None,
    ) -> Response:
        self._throttle()
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            self._count(error=True)
            return Response(url=url, method=method, error="invalid or unsupported URL")

        host = parts.hostname
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_host = host
        port = parts.port or (443 if scheme == "https" else 80)
        path = quote(parts.path or "/", safe=_PATH_SAFE)
        if parts.query:
            path += "?" + quote(parts.query, safe=_QUERY_SAFE)
        target_path = path or "/"

        send_headers = self._build_headers(ascii_host, headers)
        body_bytes: bytes | None
        if isinstance(data, dict):
            body_bytes = urlencode(data, doseq=True).encode("utf-8")
            if not any(key.lower() == "content-type" for key in send_headers):
                send_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
        elif data is None:
            body_bytes = None
        else:
            body_bytes = bytes(data)

        conn: http.client.HTTPConnection | None = None
        started = time.perf_counter()
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    ascii_host, port, timeout=timeout or self.timeout, context=self._ssl_context
                )
            else:
                conn = http.client.HTTPConnection(ascii_host, port, timeout=timeout or self.timeout)
            conn.request(method, target_path, body=body_bytes, headers=send_headers)
            raw = conn.getresponse()
            body = raw.read(MAX_RESPONSE_BYTES + 1)
            truncated = len(body) > MAX_RESPONSE_BYTES
            if truncated:
                body = body[:MAX_RESPONSE_BYTES]
            body = _decompress(body, raw.headers)
            headers_list = [(name, value) for name, value in raw.getheaders()]
            headers_map: dict[str, str] = {}
            for name, value in headers_list:
                key = name.lower()
                if key in headers_map and key != "set-cookie":
                    headers_map[key] += ", " + value
                else:
                    headers_map[key] = value
            text = _decode(body, headers_map.get("content-type", ""))
            response = Response(
                url=url,
                status=raw.status,
                reason=raw.reason or "",
                headers=headers_map,
                headers_list=headers_list,
                body=body,
                text=text,
                elapsed=time.perf_counter() - started,
                method=method,
            )
            self._store_cookies(response)
            self._count(size=len(body))
            return response
        except ssl.SSLCertVerificationError as exc:
            self.last_cert_error = str(exc)
            self._count(error=True)
            return Response(
                url=url,
                method=method,
                error=f"TLS certificate verification failed: {exc}",
                elapsed=time.perf_counter() - started,
            )
        except socket.timeout:
            self._count(error=True)
            return Response(
                url=url,
                method=method,
                error=f"timeout after {timeout or self.timeout:g}s",
                elapsed=time.perf_counter() - started,
            )
        except (ConnectionError, OSError, http.client.HTTPException, ValueError) as exc:
            self._count(error=True)
            return Response(
                url=url,
                method=method,
                error=f"{type(exc).__name__}: {exc}",
                elapsed=time.perf_counter() - started,
            )
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _build_headers(self, host: str, extra: dict[str, str] | None) -> dict[str, str]:
        headers: dict[str, str] = {
            "User-Agent": self._user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        for name, value in self._default_headers.items():
            headers[_replace_header(headers, name) or name] = value
        if extra:
            for name, value in extra.items():
                existing = _replace_header(headers, name)
                if existing is not None:
                    headers[existing] = value
                else:
                    headers[name] = value
        if _replace_header(headers, "cookie") is None:
            cookie = self._cookie_header(host)
            if cookie:
                headers["Cookie"] = cookie
        return headers

    def _cookie_header(self, host: str) -> str:
        pairs: dict[str, str] = {}
        for chunk in self._user_cookie.split(";"):
            if "=" in chunk:
                name, value = chunk.split("=", 1)
                pairs[name.strip()] = value.strip()
        with self._cookie_lock:
            snapshot = {domain: dict(values) for domain, values in self._cookies.items()}
        for domain, values in snapshot.items():
            if host == domain or host.endswith("." + domain):
                pairs.update(values)
        return "; ".join(f"{name}={value}" for name, value in pairs.items())

    def _store_cookies(self, response: Response) -> None:
        host = (urlsplit(response.url).hostname or "").lower()
        for raw in response.header_all("set-cookie"):
            jar = SimpleCookie()
            try:
                jar.load(raw)
            except Exception:
                continue
            with self._cookie_lock:
                for name, morsel in jar.items():
                    max_age = morsel["max-age"]
                    if max_age == "0" or (not morsel.value and "expires" in raw.lower()):
                        self._cookies.get(host, {}).pop(name, None)
                        continue
                    domain = (morsel["domain"] or host).lstrip(".").lower()
                    if not domain or not (host == domain or host.endswith("." + domain)):
                        continue
                    self._cookies.setdefault(domain, {})[name] = morsel.value


def _replace_header(headers: dict[str, str], wanted: str) -> str | None:
    lowered = wanted.lower()
    for name in headers:
        if name.lower() == lowered:
            return name
    return None


def _decompress(body: bytes, headers: Message | dict[str, str]) -> bytes:
    if isinstance(headers, Message):
        encoding = (headers.get("Content-Encoding") or "").lower()
    else:
        encoding = ""
        for name, value in headers.items():
            if name.lower() == "content-encoding":
                encoding = (value or "").lower()
                break
    try:
        if "gzip" in encoding:
            return gzip.decompress(body)
        if "deflate" in encoding:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        return body
    return body


def _decode(body: bytes, content_type: str) -> str:
    charset = ""
    match = _CHARSET_RE.search(content_type or "")
    if match:
        charset = match.group(1)
    if not charset:
        meta = _META_CHARSET_RE.search(body[:4096])
        if meta:
            charset = meta.group(1).decode("ascii", "ignore")
    for candidate in (charset, "utf-8", "cp1252", "latin-1"):
        if not candidate:
            continue
        try:
            return body.decode(candidate, errors="replace")
        except (LookupError, UnicodeError):
            continue
    return body.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- TLS helpers
def inspect_tls(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    result: dict[str, Any] = {
        "supported": False,
        "verified": False,
        "version": "",
        "cipher": "",
        "untrusted": False,
        "self_signed": False,
        "hostname_matches": None,
        "not_after": "",
        "days_left": None,
        "subject": "",
        "issuer": "",
        "sans": [],
        "weak_protocols": [],
        "weak_cipher": "",
        "error": "",
    }

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                result.update(
                    supported=True,
                    verified=True,
                    hostname_matches=True,
                    version=tls.version() or "",
                    cipher=(tls.cipher()[0] if tls.cipher() else ""),
                    **extract_cert_info(tls.getpeercert()),
                )
    except ssl.SSLCertVerificationError as exc:
        result["error"] = str(exc)
        result["untrusted"] = True
        _inspect_unverified(host, port, timeout, result)
    except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    if result["version"] in ("TLSv1", "TLSv1.1"):
        if result["version"] not in result["weak_protocols"]:
            result["weak_protocols"].append(result["version"])
    cipher = (result.get("cipher") or "").upper()
    if any(token in cipher for token in ("RC4", "3DES", "DES-CBC3", "NULL", "_DES_")):
        result["weak_cipher"] = result["cipher"]

    for version_name, version in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        if _protocol_accepted(host, port, timeout, version):
            result["weak_protocols"].append(version_name)
            result["weak_protocols"] = sorted(set(result["weak_protocols"]))
    return result


def _inspect_unverified(host: str, port: int, timeout: float, result: dict[str, Any]) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                result.update(
                    supported=True,
                    verified=False,
                    version=tls.version() or "",
                    cipher=(tls.cipher()[0] if tls.cipher() else ""),
                )
                der = tls.getpeercert(binary_form=True)
                cert = decode_der_cert(der) if der else {}
                if cert:
                    result.update(extract_cert_info(cert))
                    result["hostname_matches"] = hostname_matches(host, cert)
                    subject = _flatten_name(cert.get("subject", ()))
                    issuer = _flatten_name(cert.get("issuer", ()))
                    result["self_signed"] = bool(subject) and subject == issuer
    except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"


def _protocol_accepted(host: str, port: int, timeout: float, version: Any) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((host, port), timeout=min(timeout, 5.0)) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def decode_der_cert(der: bytes) -> dict:
    path = ""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="ascii") as handle:
            handle.write(pem)
            path = handle.name
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def extract_cert_info(cert: dict) -> dict[str, Any]:
    if not cert:
        return {}
    not_after = cert.get("notAfter", "")
    days_left = None
    if not_after:
        try:
            seconds = ssl.cert_time_to_seconds(not_after)
            days_left = int((seconds - time.time()) // 86400)
        except (ValueError, OverflowError):
            days_left = None
    sans = []
    for key, value in cert.get("subjectAltName", ()):
        if key.lower() in ("dns", "ip address"):
            sans.append(value)
    return {
        "not_after": not_after,
        "days_left": days_left,
        "subject": _flatten_name(cert.get("subject", ())),
        "issuer": _flatten_name(cert.get("issuer", ())),
        "sans": sans,
    }


def _flatten_name(name: Any) -> str:
    bits = []
    for rdn in name or ():
        for key, value in rdn:
            bits.append(f"{key}={value}")
    return ", ".join(bits)


def hostname_matches(host: str, cert: dict) -> bool:
    host = host.lower().rstrip(".")
    names = []
    for key, value in cert.get("subjectAltName", ()):
        if key.lower() == "dns":
            names.append(value.lower())
        elif key.lower() == "ip address" and value.lower() == host:
            return True
    if not names:
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key.lower() == "commonname":
                    names.append(value.lower())
    for pattern in names:
        if pattern == host:
            return True
        if pattern.startswith("*.") and "." in host:
            suffix = pattern[1:]
            if host.endswith(suffix) and host.count(".") == pattern.count("."):
                return True
    return False


def build_url_with_params(url: str, params: list[tuple[str, str]]) -> str:
    parts = urlsplit(url)
    query = urlencode(params, doseq=True, safe="")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


__all__ = [
    "HttpClient",
    "inspect_tls",
    "extract_cert_info",
    "hostname_matches",
    "decode_der_cert",
]

"""HTML extraction for crawl targets, forms, scripts, comments, and resources."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from .models import (
    AnchorRef,
    Form,
    FormField,
    ParsedPage,
    ResourceRef,
    ScriptRef,
)

_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "blob:", "about:")
_RESOURCE_TAGS = {"img": "src", "source": "src", "iframe": "src", "embed": "src", "video": "src"}


class _Extractor(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.base_url = page_url
        self.result = ParsedPage()
        self._form: Form | None = None
        self._script_src = ""
        self._script_integrity = ""
        self._in_script = False
        self._in_style = False
        self._in_title = False
        self._title_parts: list[str] = []
        self._inline_parts: list[str] = []

    # ----------------------------------------------------------------- helpers
    def _resolve(self, value: str) -> str:
        value = (value or "").strip()
        if not value or value.startswith("#"):
            return ""
        lowered = value.lower()
        if any(lowered.startswith(scheme) for scheme in _SKIP_SCHEMES):
            return ""
        try:
            resolved = urljoin(self.base_url, value)
        except ValueError:
            return ""
        return urldefrag(resolved)[0]

    def _attrs(self, attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {name.lower(): (value if value is not None else "") for name, value in attrs}

    # ---------------------------------------------------------------- handlers
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        data = self._attrs(attrs)

        if tag == "base" and data.get("href"):
            resolved = self._resolve(data["href"])
            if resolved:
                self.base_url = resolved
            return
        if tag == "title":
            self._in_title = True
            return
        if tag == "meta":
            name = data.get("name", "").lower()
            if name in {"generator", "application-name"}:
                content = data.get("content", "")
                if content:
                    self.result.meta[name] = content
                    if name == "generator":
                        self.result.generator = content
            return
        if tag == "a":
            href = self._resolve(data.get("href", ""))
            if href:
                self.result.links.append(href)
                self.result.anchors.append(
                    AnchorRef(href=href, target=data.get("target", ""), rel=data.get("rel", ""))
                )
            return
        if tag == "link":
            href = self._resolve(data.get("href", ""))
            if href:
                self.result.resources.append(ResourceRef(tag="link", url=href, attribute="href"))
                rel = data.get("rel", "").lower()
                if "stylesheet" in rel or href.lower().endswith(".css"):
                    self.result.resources[-1].tag = "stylesheet"
            return
        if tag == "script":
            src = self._resolve(data.get("src", ""))
            if src:
                script = ScriptRef(src=src, integrity=data.get("integrity", ""), crossorigin=data.get("crossorigin", ""))
                self.result.scripts.append(script)
                self.result.resources.append(ResourceRef(tag="script", url=src))
            else:
                self._in_script = True
                self._inline_parts = []
            return
        if tag in _RESOURCE_TAGS:
            src = self._resolve(data.get(_RESOURCE_TAGS[tag], ""))
            if src:
                self.result.resources.append(ResourceRef(tag=tag, url=src))
            return
        if tag == "style":
            self._in_style = True
            return
        if tag == "form":
            action = self._resolve(data.get("action", "")) or self.page_url
            method = (data.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                method = "GET"
            self._form = Form(
                page_url=self.page_url,
                action=action,
                method=method,
                enctype=(data.get("enctype") or "application/x-www-form-urlencoded").lower(),
                raw_action=data.get("action", ""),
            )
            return
        if tag == "input":
            name = data.get("name", "")
            if not name:
                return
            field = FormField(
                name=name,
                value=data.get("value", ""),
                type=(data.get("type") or "text").lower(),
                tag="input",
                attributes=data,
            )
            if self._form is not None:
                self._form.fields.append(field)
            return
        if tag in {"textarea", "select"}:
            name = data.get("name", "")
            if name and self._form is not None:
                field = FormField(
                    name=name,
                    value="",
                    type="textarea" if tag == "textarea" else "select",
                    tag=tag,
                    attributes=data,
                )
                self._form.fields.append(field)
            return
        if tag == "button" and self._form is not None:
            name = data.get("name", "")
            if name:
                self._form.fields.append(
                    FormField(
                        name=name,
                        value=data.get("value", ""),
                        type=(data.get("type") or "submit").lower(),
                        tag="button",
                        attributes=data,
                    )
                )
            return

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form" and self._form is not None:
            self.result.forms.append(self._form)
            self._form = None
        elif tag == "script":
            if self._in_script:
                text = "".join(self._inline_parts).strip()
                if text:
                    self.result.inline_scripts.append(text)
            self._in_script = False
            self._inline_parts = []
        elif tag == "style":
            self._in_style = False
        elif tag == "title":
            self._in_title = False
            self.result.title = " ".join("".join(self._title_parts).split())
            self._title_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        elif self._in_script:
            self._inline_parts.append(data)

    def handle_comment(self, data: str) -> None:
        cleaned = data.strip()
        if cleaned:
            self.result.comments.append(cleaned)

    def close(self) -> None:
        super().close()
        if self._form is not None:
            self.result.forms.append(self._form)
            self._form = None
        if self._in_title and self._title_parts:
            self.result.title = " ".join("".join(self._title_parts).split())


def parse_html(text: str, page_url: str) -> ParsedPage:
    parser = _Extractor(page_url)
    try:
        parser.feed(text or "")
        parser.close()
    except Exception:
        # Broken markup should never abort a scan; return what was parsed.
        try:
            parser.close()
        except Exception:
            pass
    result = parser.result
    # Deduplicate links while preserving crawl order.
    seen: set[str] = set()
    unique: list[str] = []
    for link in result.links:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    result.links = unique
    return result


def same_site_origin(url: str, origin: str) -> bool:
    try:
        left = urlsplit(url)
        right = urlsplit(origin)
    except ValueError:
        return False
    if left.scheme not in ("http", "https") or right.scheme not in ("http", "https"):
        return False
    lh = (left.hostname or "").lower()
    rh = (right.hostname or "").lower()
    if lh.startswith("www."):
        lh = lh[4:]
    if rh.startswith("www."):
        rh = rh[4:]
    return lh == rh


__all__ = ["parse_html", "same_site_origin"]

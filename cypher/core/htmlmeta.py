"""Minimal Open Graph / meta tag extractor (stdlib regex, no dependencies)."""

from __future__ import annotations

import re

_META_RE = re.compile(r"<meta[^>]+>", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_URL_IN_TEXT = re.compile(r"https?://[^\s)\]<>\"']+")
_HANDLE_IN_TEXT = re.compile(r"(?<![\w@])@([A-Za-z0-9_.]{3,30})")


def links_in(text: str) -> tuple[list[str], list[str]]:
    """Return (urls, @handles) found in free text such as a bio."""
    urls = _URL_IN_TEXT.findall(text or "")
    handles = _HANDLE_IN_TEXT.findall(text or "")
    return urls, handles


def og_tags(html: str) -> dict[str, str]:
    """Return a dict of og:<prop> -> content, plus 'title' from <title>."""
    tags: dict[str, str] = {}
    for m in _META_RE.finditer(html or ""):
        tag = m.group(0)
        prop = re.search(r'(?:property|name)=["\']og:([^"\']+)', tag, re.IGNORECASE)
        content = re.search(r'content=["\']([^"\']*)', tag, re.IGNORECASE)
        if prop and content:
            tags[prop.group(1).lower()] = content.group(1)
    if "title" not in tags:
        t = _TITLE_RE.search(html or "")
        if t:
            tags["title"] = " ".join(t.group(1).split())
    return tags

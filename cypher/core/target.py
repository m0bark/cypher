"""Target model and type detection.

A Target is the atom of an investigation: a normalized value plus its detected
type. Modules declare which target types they apply to.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    URL = "url"
    USERNAME = "username"
    PHONE = "phone"
    ORG = "org"
    UNKNOWN = "unknown"


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_USERNAME_RE = re.compile(r"^@?[A-Za-z0-9_][A-Za-z0-9_.-]{1,38}$")
# Phone: optional +, then 7-15 digits, allowing spaces/dashes/dots/parens as separators.
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().\-]{6,20}$")


def _phone_digits(s: str) -> str:
    return re.sub(r"[^0-9]", "", s)


@dataclass(frozen=True)
class Target:
    """An immutable investigation target."""

    raw: str
    type: TargetType
    value: str
    parent: str | None = None
    meta: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.type.value}:{self.value}"


def detect_type(raw: str) -> TargetType:
    """Classify a raw string. Order matters: most specific patterns first."""
    s = raw.strip()
    if not s:
        return TargetType.UNKNOWN
    if _URL_RE.match(s):
        return TargetType.URL
    if _EMAIL_RE.match(s):
        return TargetType.EMAIL
    try:
        ipaddress.ip_address(s)
        return TargetType.IP
    except ValueError:
        pass
    # Phone before domain/username: mostly-digits with an optional leading +.
    if _PHONE_RE.match(s) and 7 <= len(_phone_digits(s)) <= 15:
        return TargetType.PHONE
    if "." in s and _DOMAIN_RE.match(s):
        return TargetType.DOMAIN
    if _USERNAME_RE.match(s):
        return TargetType.USERNAME
    return TargetType.UNKNOWN


def parse_target(raw: str) -> Target:
    """Build a normalized Target from a raw string."""
    s = raw.strip()
    ttype = detect_type(s)

    if ttype is TargetType.URL:
        host = urlparse(s).netloc.split("@")[-1].split(":")[0].lower()
        return Target(raw=s, type=TargetType.URL, value=s.lower(), parent=host or None)

    if ttype is TargetType.EMAIL:
        domain = s.split("@", 1)[1].lower()
        return Target(
            raw=s, type=TargetType.EMAIL, value=s.lower(), parent=domain
        )

    if ttype is TargetType.DOMAIN:
        return Target(raw=s, type=TargetType.DOMAIN, value=s.lower().rstrip("."))

    if ttype is TargetType.IP:
        return Target(raw=s, type=TargetType.IP, value=s)

    if ttype is TargetType.PHONE:
        digits = _phone_digits(s)
        value = ("+" + digits) if s.lstrip().startswith("+") else digits
        return Target(raw=s, type=TargetType.PHONE, value=value)

    if ttype is TargetType.USERNAME:
        return Target(
            raw=s, type=TargetType.USERNAME, value=s.lstrip("@").lower()
        )

    return Target(raw=s, type=TargetType.UNKNOWN, value=s)

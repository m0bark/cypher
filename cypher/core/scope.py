"""Authorization and scope guard.

Cypher is for authorized use: infrastructure and accounts you own or are
permitted to assess, and defensive self-checks. This module surfaces an explicit
authorization gate and flags targets that read as private individuals so the
operator has to consciously confirm before proceeding.

It is a speed bump for conscience and paperwork, not a security control.
"""

from __future__ import annotations

from dataclasses import dataclass

from .target import Target, TargetType

CONSUMER_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "ymail.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "gmx.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
}

AUTHORIZATION_NOTICE = (
    "Authorized / defensive use only — your own assets and accounts, or targets "
    "you're permitted to assess."
)


@dataclass
class ScopeDecision:
    allowed: bool
    requires_confirmation: bool
    reason: str


def looks_personal(target: Target) -> bool:
    """Heuristic: does this target read as a private individual rather than
    infrastructure or an organization?"""
    if target.type is TargetType.USERNAME:
        return True
    if target.type is TargetType.EMAIL:
        domain = (target.parent or "").lower()
        return domain in CONSUMER_EMAIL_DOMAINS
    return False


def assess(target: Target) -> ScopeDecision:
    """Decide whether a target may proceed and whether it needs a second look."""
    if target.type is TargetType.UNKNOWN:
        return ScopeDecision(
            allowed=False,
            requires_confirmation=False,
            reason="Target type could not be determined.",
        )
    if looks_personal(target):
        return ScopeDecision(
            allowed=True,
            requires_confirmation=True,
            reason="Personal account — continue only if it's yours or you're authorized.",
        )
    return ScopeDecision(
        allowed=True,
        requires_confirmation=False,
        reason="Target reads as infrastructure or an organization.",
    )

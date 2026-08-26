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
    "Cypher collects only open-source, publicly available information, but that\n"
    "does not make every use of it acceptable. Use it against assets you own or\n"
    "are explicitly authorized to assess (a pentest scope, your own domains and\n"
    "accounts, a client engagement), or to check your own / your org's exposure.\n"
    "Do not use it to profile, locate, or build a dossier on a private individual\n"
    "who has not consented. That is stalking, and this tool will not help with it."
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
            reason=(
                "This target reads as a private individual (personal account or "
                "consumer email). Only continue if this is you, or someone who has "
                "consented, or a subject you are legally authorized to investigate."
            ),
        )
    return ScopeDecision(
        allowed=True,
        requires_confirmation=False,
        reason="Target reads as infrastructure or an organization.",
    )

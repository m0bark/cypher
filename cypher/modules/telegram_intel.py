"""Telegram public profile/channel preview via t.me (Open Graph, no login)."""

from __future__ import annotations

from ..core.context import Context
from ..core.htmlmeta import og_tags
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType, parse_target


class TelegramIntel(BaseModule):
    name = "telegram"
    description = (
        "Public Telegram preview for a handle via t.me: display name, bio/"
        "description, avatar (profile picture) and subscriber count for channels. "
        "Public Open Graph data, no login."
    )
    applies_to = (TargetType.USERNAME,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        url = f"https://t.me/{target.value}"
        try:
            resp = ctx.http.get(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"t.me request failed: {exc}")

        text = resp.text or ""
        og = og_tags(text)
        if "tgme_page_title" not in text and not og.get("title"):
            return ModuleResult(
                self.name, target.value, ok=True,
                findings=[Finding("Telegram", "No public Telegram profile/channel.", Severity.INFO)],
            )

        name = og.get("title", target.value)
        bio = og.get("description", "")
        pfp = og.get("image", "")
        findings = [
            Finding("Telegram name", name, Severity.LOW,
                    {"image": pfp, "bio": bio, "url": url, "platform": "Telegram"})
        ]
        if bio:
            findings.append(Finding("Telegram bio/description", bio, Severity.INFO))
        return ModuleResult(
            self.name, target.value, ok=True, findings=findings,
            new_targets=[parse_target(url)],
        )

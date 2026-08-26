"""Instagram public profile preview via Open Graph tags (no login).

Instagram aggressively gates its data behind login and rate limits, so this is
best-effort: when the public profile page still exposes Open Graph tags it
returns the display name, the follower/bio blurb and the avatar. If Instagram
serves a login wall it reports that plainly rather than guessing.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.htmlmeta import og_tags
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType, parse_target


class InstagramIntel(BaseModule):
    name = "instagram"
    description = (
        "Best-effort public Instagram preview for a handle: display name, "
        "follower/bio blurb and avatar via Open Graph. Instagram often gates "
        "this behind login; results may be partial."
    )
    applies_to = (TargetType.USERNAME,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        url = f"https://www.instagram.com/{target.value}/"
        try:
            resp = ctx.http.get(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"instagram request failed: {exc}")

        og = og_tags(resp.text or "")
        title = og.get("title", "")
        desc = og.get("description", "")
        pfp = og.get("image", "")

        if not title and not desc:
            return ModuleResult(
                self.name, target.value, ok=True,
                findings=[Finding("Instagram", "No public preview (login wall or not found).",
                                  Severity.INFO)],
            )

        findings = [
            Finding("Instagram profile", title or target.value, Severity.LOW,
                    {"image": pfp, "bio": desc, "url": url, "platform": "Instagram"})
        ]
        if desc:
            findings.append(Finding("Instagram bio/stats", desc, Severity.INFO))
        return ModuleResult(
            self.name, target.value, ok=True, findings=findings,
            new_targets=[parse_target(url)],
        )

"""Built-in username footprint check across common platforms.

A self-contained mini-enumerator: for a username, request each platform's public
profile URL and decide existence from the status code (or a per-site marker).
Best used to audit your own handle's exposure. For broad coverage (400+ sites)
install sherlock/maigret — this module works out of the box everywhere.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType, parse_target

# Each site: url template, and optional detection marker.
#   "absent":  text that appears ONLY on a not-found page (exists = 200 and absent not present)
#   "present": text that must appear on a real profile (exists = 200 and present in body)
#   neither:   exists = HTTP 200
SITES: list[dict] = [
    {"name": "GitHub", "url": "https://github.com/{}"},
    {"name": "GitLab", "url": "https://gitlab.com/{}"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}"},
    {"name": "Medium", "url": "https://medium.com/@{}"},
    {"name": "Dev.to", "url": "https://dev.to/{}"},
    {"name": "Replit", "url": "https://replit.com/@{}"},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{}"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}"},
    {"name": "about.me", "url": "https://about.me/{}"},
    {"name": "Keybase", "url": "https://keybase.io/{}"},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{}"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "absent": "could not be found"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "absent": "No such user."},
    {"name": "Telegram", "url": "https://t.me/{}", "present": "tgme_page_title"},
]


class UsernameSites(BaseModule):
    name = "username_sites"
    description = (
        "Check a username against common platforms (GitHub, GitLab, YouTube, "
        "Steam, Telegram, Keybase, ...) by requesting public profile URLs. "
        "Self-contained; ideal for auditing your own handle's exposure."
    )
    applies_to = (TargetType.USERNAME,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        found: list[tuple[str, str]] = []
        checked = 0
        for site in SITES:
            url = site["url"].format(target.value)
            try:
                resp = ctx.http.get(url, timeout=8)
            except Exception:
                continue
            checked += 1
            if self._exists(site, resp):
                found.append((site["name"], url))

        if checked == 0:
            return ModuleResult.failure(self.name, target.value, "No platforms reachable.")

        if not found:
            return ModuleResult(
                self.name, target.value, ok=True,
                findings=[Finding("Username footprint",
                                  f"Handle not found on any of {checked} checked platforms.",
                                  Severity.INFO)],
            )

        new_targets = [parse_target(u) for _, u in found]
        findings = [
            Finding(
                f"Found on {len(found)} platforms",
                ", ".join(f"{n} ({u})" for n, u in found),
                Severity.LOW,
                {"profiles": {n: u for n, u in found}, "checked": checked},
            )
        ]
        return ModuleResult(
            self.name, target.value, ok=True, findings=findings, new_targets=new_targets
        )

    @staticmethod
    def _exists(site: dict, resp) -> bool:
        if resp.status_code != 200:
            return False
        text = resp.text or ""
        if "present" in site:
            return site["present"] in text
        if "absent" in site:
            return site["absent"] not in text
        return True

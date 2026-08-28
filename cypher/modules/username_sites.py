"""Built-in username footprint check with control-string verification.

For each platform we request the target handle AND a known-garbage control handle.
A hit only counts when the two responses differ in a way that proves existence
(the target resolves where the control 404s, or the pages differ substantially).
Soft-404 platforms — which 200 for anything — are reported as UNVERIFIED, not as
hits. This kills the false positives that plain status-code checks produce.

For the widest reliable coverage install sherlock/maigret; this works everywhere.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType, parse_target

CONTROL = "zqx9no7user000zz"
LEN_DELTA = 600

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
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "absent": "could not be found"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "absent": "No such user."},
    {"name": "Telegram", "url": "https://t.me/{}", "present": "tgme_page_title"},
]


class UsernameSites(BaseModule):
    name = "username_sites"
    description = (
        "Check a username across common platforms with control-string verification: "
        "each hit is confirmed against a known-garbage handle so soft-404 platforms "
        "(which 200 for anything) are flagged unverified instead of counted. Kills "
        "false positives."
    )
    applies_to = (TargetType.USERNAME,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        found: list[tuple[str, str]] = []
        unverified: list[str] = []
        checked = 0
        for site in SITES:
            url = site["url"].format(target.value)
            try:
                resp = ctx.http.get(url, timeout=8)
            except Exception:
                continue
            checked += 1
            verdict = self._verify(site, resp, ctx)
            if verdict == "found":
                found.append((site["name"], url))
            elif verdict == "maybe":
                unverified.append(site["name"])

        if checked == 0:
            return ModuleResult.failure(self.name, target.value, "No platforms reachable.")

        findings: list[Finding] = []
        if found:
            findings.append(
                Finding(
                    f"Confirmed on {len(found)} platforms",
                    ", ".join(f"{n} ({u})" for n, u in found),
                    Severity.LOW,
                    {"profiles": {n: u for n, u in found}},
                )
            )
        else:
            findings.append(Finding("Username footprint",
                                    f"No confirmed accounts across {checked} platforms.",
                                    Severity.INFO))
        if unverified:
            findings.append(
                Finding(f"{len(unverified)} unverifiable (soft-404)",
                        ", ".join(unverified) + " — these 200 for any handle; treat as unknown.",
                        Severity.INFO, {"unverified": unverified})
            )
        new_targets = [parse_target(u) for _, u in found]
        return ModuleResult(
            self.name, target.value, ok=True, findings=findings, new_targets=new_targets
        )

    def _verify(self, site: dict, resp, ctx: Context) -> str:
        """Return 'found', 'no', or 'maybe' (unverifiable soft-404)."""
        text = resp.text or ""
        if "present" in site:
            return "found" if (resp.status_code == 200 and site["present"] in text) else "no"
        if "absent" in site:
            return "found" if (resp.status_code == 200 and site["absent"] not in text) else "no"

        if resp.status_code != 200:
            return "no"
        try:
            ctrl = ctx.http.get(site["url"].format(CONTROL), timeout=8)
        except Exception:
            return "maybe"
        if ctrl.status_code >= 400:
            return "found"
        if abs(len(text) - len(ctrl.text or "")) > LEN_DELTA:
            return "found"
        return "maybe"

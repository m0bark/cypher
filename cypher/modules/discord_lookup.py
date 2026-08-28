"""Discord user lookup by numeric ID (snowflake) via the official Discord API.

Discord exposes no public username lookup, so this works only on a user ID you
already have. It returns the public profile the API gives: display/global name,
username, and avatar. Requires DISCORD_BOT_TOKEN (a bot token). Skips cleanly
when the target isn't a snowflake or no token is configured.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


def _is_snowflake(value: str) -> bool:
    return value.isdigit() and 17 <= len(value) <= 20


# public_flags bitfield -> badge name
BADGES = {
    1 << 0: "Discord Staff", 1 << 1: "Partner", 1 << 2: "HypeSquad Events",
    1 << 3: "Bug Hunter (lvl 1)", 1 << 6: "HypeSquad Bravery",
    1 << 7: "HypeSquad Brilliance", 1 << 8: "HypeSquad Balance",
    1 << 9: "Early Supporter", 1 << 14: "Bug Hunter (lvl 2)",
    1 << 16: "Verified Bot", 1 << 17: "Early Verified Bot Dev",
    1 << 18: "Certified Moderator", 1 << 22: "Active Developer",
}
PREMIUM = {1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}


class DiscordLookup(BaseModule):
    name = "discord_id"
    description = (
        "Look up a Discord user by their numeric ID (snowflake) via the official "
        "API: display name, username, avatar. Requires DISCORD_BOT_TOKEN. Discord "
        "has no username lookup, so this needs the ID, not a handle."
    )
    applies_to = (TargetType.USERNAME,)
    requires_key = "DISCORD_BOT_TOKEN"

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        if not _is_snowflake(target.value):
            return ModuleResult.skip(
                self.name, target.value,
                "Not a Discord ID — needs the 17-20 digit user ID (snowflake), not a handle.",
            )
        token = ctx.key("DISCORD_BOT_TOKEN")
        if not token:
            return ModuleResult.skip(
                self.name, target.value,
                "Set DISCORD_BOT_TOKEN (a bot token) to enable Discord ID lookups.",
            )

        url = f"https://discord.com/api/v10/users/{target.value}"
        try:
            resp = ctx.http.get(url, headers={"Authorization": f"Bot {token}"})
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"Discord API failed: {exc}")

        if resp.status_code == 404:
            return ModuleResult(self.name, target.value, ok=True,
                                findings=[Finding("Discord", "No user with that ID.", Severity.INFO)])
        if resp.status_code != 200:
            return ModuleResult.failure(
                self.name, target.value, f"Discord API returned HTTP {resp.status_code}."
            )

        data = resp.json()
        findings: list[Finding] = []
        uname = data.get("username")
        gname = data.get("global_name")
        if uname:
            findings.append(Finding("Discord username", f"@{uname}", Severity.LOW))
        if gname:
            findings.append(Finding("Display name", gname, Severity.INFO))
        avatar = data.get("avatar")
        if avatar:
            ext = "gif" if str(avatar).startswith("a_") else "png"
            img = f"https://cdn.discordapp.com/avatars/{target.value}/{avatar}.{ext}?size=256"
            findings.append(Finding("Discord avatar", img, Severity.LOW,
                                    {"image": img, "bio": gname or uname or "",
                                     "url": img, "platform": "Discord"}))
        banner = data.get("banner")
        if banner:
            bext = "gif" if str(banner).startswith("a_") else "png"
            burl = f"https://cdn.discordapp.com/banners/{target.value}/{banner}.{bext}?size=600"
            findings.append(Finding("Banner", burl, Severity.INFO, {"url": burl}))
        flags = data.get("public_flags", 0) or 0
        badges = [name for bit, name in BADGES.items() if flags & bit]
        if badges:
            findings.append(Finding("Badges", ", ".join(badges), Severity.INFO, {"badges": badges}))
        prem = data.get("premium_type")
        if prem:
            findings.append(Finding("Nitro", PREMIUM.get(prem, f"type {prem}"), Severity.INFO))
        if data.get("bot"):
            findings.append(Finding("Account type", "Bot account", Severity.INFO))
        if data.get("id"):
            findings.append(Finding("User ID", str(data["id"]), Severity.INFO))
        if not findings:
            findings.append(Finding("Discord", "User found, no public fields exposed.", Severity.INFO))
        return ModuleResult(self.name, target.value, ok=True, findings=findings, raw=data)

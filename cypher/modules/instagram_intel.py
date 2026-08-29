"""Instagram public profile intel for a handle (no login).

Uses Instagram's public web-profile endpoint (the same one the website calls with
its public web app id) to pull the real profile picture, display name, bio,
follower/following/post counts, and verified/private flags for public accounts.
Falls back to Open Graph tags if that endpoint is unavailable. Public data only.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.htmlmeta import links_in, og_tags
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType, parse_target

_IG_APP_ID = "936619743392459"
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class InstagramIntel(BaseModule):
    name = "instagram"
    description = (
        "Public Instagram profile for a handle: real profile picture, display "
        "name, bio, follower/following/post counts and verified/private flags "
        "via Instagram's public web-profile API (Open Graph fallback)."
    )
    applies_to = (TargetType.USERNAME,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        url = f"https://www.instagram.com/{target.value}/"
        user = self._web_profile(target.value, ctx)
        if user:
            return self._from_api(target, url, user)
        return self._from_og(target, url, ctx)

    def _web_profile(self, handle: str, ctx: Context) -> dict | None:
        api = f"https://i.instagram.com/api/v1/users/web_profile_info/?username={handle}"
        headers = {"x-ig-app-id": _IG_APP_ID, "User-Agent": _BROWSER_UA, "Accept": "*/*"}
        try:
            resp = ctx.http.get(api, headers=headers)
            if resp.status_code != 200:
                return None
            user = (resp.json().get("data") or {}).get("user")
            return user or None
        except Exception:
            return None

    def _from_api(self, target: Target, url: str, u: dict) -> ModuleResult:
        pfp = u.get("profile_pic_url_hd") or u.get("profile_pic_url") or ""
        name = u.get("full_name") or target.value
        bio = u.get("biography") or ""
        followers = (u.get("edge_followed_by") or {}).get("count")
        following = (u.get("edge_follow") or {}).get("count")
        posts = (u.get("edge_owner_to_timeline_media") or {}).get("count")
        ext = u.get("external_url") or ""

        findings = [
            Finding("Instagram profile", name, Severity.LOW,
                    {"image": pfp, "bio": bio, "url": url, "platform": "Instagram"})
        ]
        flags = []
        if u.get("is_private"):
            flags.append("private")
        if u.get("is_verified"):
            flags.append("verified")
        stats = []
        if followers is not None:
            stats.append(f"{followers:,} followers")
        if following is not None:
            stats.append(f"{following:,} following")
        if posts is not None:
            stats.append(f"{posts:,} posts")
        if stats or flags:
            detail = " · ".join(stats + flags)
            findings.append(Finding("Instagram stats", detail, Severity.INFO))
        if bio:
            findings.append(Finding("Instagram bio", bio, Severity.INFO))
        if u.get("id"):
            findings.append(Finding("Instagram user ID", str(u["id"]), Severity.INFO))

        new_targets = [parse_target(url)]
        pivots: list[str] = []
        if ext:
            findings.append(Finding("External link (pivot)", ext, Severity.LOW, {"url": ext}))
            new_targets.append(parse_target(ext))
            pivots.append(ext)
        urls, handles = links_in(bio)
        for item in urls:
            new_targets.append(parse_target(item))
            pivots.append(item)
        for h in handles:
            new_targets.append(parse_target(h))
            pivots.append(f"@{h}")
        if pivots:
            findings.append(Finding("Links in bio (pivots)", ", ".join(pivots), Severity.LOW,
                                    {"pivots": pivots}))
        return ModuleResult(self.name, target.value, ok=True, findings=findings,
                            new_targets=new_targets)

    def _from_og(self, target: Target, url: str, ctx: Context) -> ModuleResult:
        try:
            resp = ctx.http.get(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"instagram request failed: {exc}")

        og = og_tags(resp.text or "")
        title, desc, pfp = og.get("title", ""), og.get("description", ""), og.get("image", "")
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
        new_targets = [parse_target(url)]
        urls, handles = links_in(desc)
        pivots = urls + [f"@{h}" for h in handles]
        for item in urls:
            new_targets.append(parse_target(item))
        for h in handles:
            new_targets.append(parse_target(h))
        if pivots:
            findings.append(Finding("Links in bio (pivots)", ", ".join(pivots), Severity.LOW,
                                    {"pivots": pivots}))
        return ModuleResult(self.name, target.value, ok=True, findings=findings,
                            new_targets=new_targets)

"""Public GitHub profile and repository recon for a username or org."""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


class GithubRecon(BaseModule):
    name = "github_recon"
    description = (
        "Public GitHub profile and repositories for a username/org: bio, company, "
        "location, public repo count, top languages. An optional GITHUB_TOKEN "
        "raises the API rate limit. Public data only."
    )
    applies_to = (TargetType.USERNAME, TargetType.ORG)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        headers = {"Accept": "application/vnd.github+json"}
        token = ctx.key("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            profile = ctx.http.get_json(
                f"https://api.github.com/users/{target.value}", headers=headers
            )
        except Exception as exc:
            return ModuleResult.failure(
                self.name, target.value, f"GitHub profile lookup failed: {exc}"
            )

        findings: list[Finding] = []
        for field in ("name", "company", "location", "blog", "bio", "public_repos", "followers"):
            if profile.get(field):
                findings.append(Finding(field.replace("_", " ").title(),
                                        str(profile[field]), Severity.INFO))

        langs: dict[str, int] = {}
        try:
            repos = ctx.http.get_json(
                f"https://api.github.com/users/{target.value}/repos?per_page=100&sort=updated",
                headers=headers,
            )
            for repo in repos:
                lang = repo.get("language")
                if lang:
                    langs[lang] = langs.get(lang, 0) + 1
        except Exception:
            repos = []

        if langs:
            top = sorted(langs.items(), key=lambda kv: kv[1], reverse=True)[:5]
            findings.append(
                Finding("Top languages", ", ".join(f"{k} ({v})" for k, v in top),
                        Severity.INFO, {"languages": dict(top)})
            )

        if not findings:
            return ModuleResult.failure(self.name, target.value, "No public GitHub data found.")

        return ModuleResult(
            module=self.name, target=target.value, ok=True, findings=findings,
            raw={"profile": profile, "repo_count": len(repos)},
        )

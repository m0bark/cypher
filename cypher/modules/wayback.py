"""Historical URL discovery via the Internet Archive Wayback CDX API (passive)."""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType

CDX_LIMIT = 200


class Wayback(BaseModule):
    name = "wayback"
    description = (
        "List historical URLs the Internet Archive has captured for a domain "
        "(old endpoints, forgotten paths, exposed files). Passive: queries "
        "archive.org, not the target."
    )
    applies_to = (TargetType.DOMAIN,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        url = (
            "http://web.archive.org/cdx/search/cdx"
            f"?url={target.value}/*&output=json&fl=original&collapse=urlkey&limit={CDX_LIMIT}"
        )
        try:
            rows = ctx.http.get_json(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"Wayback query failed: {exc}")

        urls = [r[0] for r in rows[1:]] if isinstance(rows, list) and len(rows) > 1 else []
        if not urls:
            return ModuleResult(
                self.name, target.value, ok=True,
                findings=[Finding("Archived URLs", "No captures found.", Severity.INFO)],
            )

        interesting = [u for u in urls if any(
            tok in u.lower() for tok in (".env", ".sql", ".bak", "admin", "backup", "config", ".git")
        )]
        findings = [
            Finding(f"{len(urls)} archived URLs", ", ".join(urls[:10]) + " ...",
                    Severity.INFO, {"urls": urls})
        ]
        if interesting:
            findings.append(
                Finding(
                    "Potentially sensitive archived paths",
                    ", ".join(interesting[:10]),
                    Severity.MEDIUM,
                    {"urls": interesting},
                )
            )
        return ModuleResult(
            module=self.name, target=target.value, ok=True, findings=findings, raw=urls
        )

"""Passive subdomain discovery via crt.sh certificate transparency logs."""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType, parse_target


class CrtShSubdomains(BaseModule):
    name = "crtsh_subdomains"
    description = (
        "Enumerate subdomains from public certificate transparency logs (crt.sh). "
        "Passive: queries a public log, never the target itself. Expands the attack "
        "surface by revealing hosts named on issued TLS certificates."
    )
    applies_to = (TargetType.DOMAIN,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        url = f"https://crt.sh/?q=%25.{target.value}&output=json"
        try:
            resp = ctx.http.get(url)
            resp.raise_for_status()
            rows = resp.json()
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"crt.sh query failed: {exc}")

        names: set[str] = set()
        for row in rows:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(target.value) and name != target.value:
                    names.add(name)

        if not names:
            return ModuleResult(
                self.name, target.value, ok=True,
                findings=[Finding("Subdomains", "No subdomains found in CT logs.", Severity.INFO)],
            )

        ordered = sorted(names)
        new_targets = [parse_target(n) for n in ordered]
        preview = ", ".join(ordered[:15]) + (" ..." if len(ordered) > 15 else "")
        return ModuleResult(
            module=self.name,
            target=target.value,
            ok=True,
            findings=[
                Finding(
                    f"{len(ordered)} subdomains",
                    preview,
                    Severity.LOW,
                    {"subdomains": ordered},
                )
            ],
            new_targets=new_targets,
            raw=ordered,
        )

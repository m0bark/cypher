"""Breach exposure via Have I Been Pwned (requires HIBP_API_KEY).

This is a real adapter, gated on configuration: with no key it returns a clear,
honest 'skipped — set HIBP_API_KEY to enable' result rather than failing. HIBP
is a paid API; the key is never hardcoded.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


class BreachCheck(BaseModule):
    name = "breach_check"
    description = (
        "Check an email against known data breaches via Have I Been Pwned. "
        "Requires HIBP_API_KEY. Best used defensively on your own addresses."
    )
    applies_to = (TargetType.EMAIL,)
    requires_key = "HIBP_API_KEY"

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        key = ctx.key("HIBP_API_KEY")
        if not key:
            return ModuleResult.skip(
                self.name, target.value,
                "Set HIBP_API_KEY to enable breach lookups (haveibeenpwned.com/API/Key).",
            )

        url = (
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{target.value}?truncateResponse=false"
        )
        headers = {"hibp-api-key": key, "user-agent": ctx.settings.user_agent}
        try:
            resp = ctx.http.get(url, headers=headers)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"HIBP request failed: {exc}")

        if resp.status_code == 404:
            return ModuleResult(
                self.name, target.value, ok=True,
                findings=[Finding("Breaches", "No known breaches for this address.",
                                  Severity.INFO)],
            )
        if resp.status_code != 200:
            return ModuleResult.failure(
                self.name, target.value, f"HIBP returned HTTP {resp.status_code}."
            )

        breaches = resp.json()
        names = [b.get("Name", "?") for b in breaches]
        findings = [
            Finding(
                f"Found in {len(breaches)} breaches",
                ", ".join(names),
                Severity.HIGH,
                {"breaches": names},
            )
        ]
        return ModuleResult(
            self.name, target.value, ok=True, findings=findings, raw=breaches
        )

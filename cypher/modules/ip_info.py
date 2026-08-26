"""IP geolocation and network ownership via ipinfo.io (free tier; optional token)."""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType

FIELDS = ("ip", "hostname", "city", "region", "country", "org", "asn", "timezone")


class IpInfo(BaseModule):
    name = "ip_info"
    description = (
        "Geolocation and network ownership for an IP (city/region/country, "
        "hosting org, ASN) via ipinfo.io. An optional IPINFO_TOKEN raises limits."
    )
    applies_to = (TargetType.IP,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        token = ctx.key("IPINFO_TOKEN")
        url = f"https://ipinfo.io/{target.value}/json"
        if token:
            url += f"?token={token}"
        try:
            data = ctx.http.get_json(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"ipinfo lookup failed: {exc}")

        findings: list[Finding] = []
        for field in FIELDS:
            if data.get(field):
                findings.append(Finding(field.title(), str(data[field]), Severity.INFO))

        if not findings:
            return ModuleResult.failure(self.name, target.value, "No geolocation data returned.")

        return ModuleResult(
            module=self.name, target=target.value, ok=True, findings=findings, raw=data
        )

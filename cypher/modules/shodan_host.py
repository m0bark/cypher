"""Host intelligence via Shodan (requires SHODAN_API_KEY).

Shodan indexes internet-exposed services. Gated on configuration: with no key it
returns a clean 'skipped — set SHODAN_API_KEY' result.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


class ShodanHost(BaseModule):
    name = "shodan_host"
    description = (
        "Internet-exposure intelligence for an IP via Shodan: open ports, "
        "detected services/products, hostnames, org, and known CVEs. "
        "Requires SHODAN_API_KEY."
    )
    applies_to = (TargetType.IP,)
    requires_key = "SHODAN_API_KEY"

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        key = ctx.key("SHODAN_API_KEY")
        if not key:
            return ModuleResult.skip(
                self.name, target.value,
                "Set SHODAN_API_KEY to enable (account.shodan.io).",
            )

        url = f"https://api.shodan.io/shodan/host/{target.value}?key={key}"
        try:
            data = ctx.http.get_json(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"Shodan lookup failed: {exc}")

        findings: list[Finding] = []
        ports = data.get("ports", [])
        if ports:
            findings.append(Finding("Open ports", ", ".join(map(str, ports)),
                                    Severity.MEDIUM, {"ports": ports}))
        for field in ("org", "isp", "os", "asn"):
            if data.get(field):
                findings.append(Finding(field.upper(), str(data[field]), Severity.INFO))
        hostnames = data.get("hostnames", [])
        if hostnames:
            findings.append(Finding("Hostnames", ", ".join(hostnames), Severity.INFO))

        products = sorted({s.get("product") for s in data.get("data", []) if s.get("product")})
        if products:
            findings.append(Finding("Detected products", ", ".join(products), Severity.LOW,
                                    {"products": products}))

        vulns = sorted(data.get("vulns", []))
        if vulns:
            findings.append(Finding(f"{len(vulns)} known CVEs", ", ".join(vulns[:20]),
                                    Severity.HIGH, {"vulns": vulns}))

        if not findings:
            findings.append(Finding("Shodan", "Host found but no notable data.", Severity.INFO))
        return ModuleResult(self.name, target.value, ok=True, findings=findings, raw=data)

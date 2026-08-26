"""ASN / network-block context for an IP via the free BGPView API (passive)."""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


class BgpView(BaseModule):
    name = "bgpview"
    description = (
        "Network-block context for an IP via BGPView: announcing ASN, prefix, "
        "RIR, and reverse DNS. Passive and key-free."
    )
    applies_to = (TargetType.IP,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        try:
            data = ctx.http.get_json(f"https://api.bgpview.io/ip/{target.value}")
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"BGPView lookup failed: {exc}")

        info = data.get("data", {})
        findings: list[Finding] = []
        if info.get("ptr_record"):
            findings.append(Finding("Reverse DNS (PTR)", str(info["ptr_record"]), Severity.INFO))

        for pfx in info.get("prefixes", [])[:3]:
            asn = pfx.get("asn", {})
            detail = (
                f"AS{asn.get('asn')} {asn.get('name', '')} "
                f"— prefix {pfx.get('prefix')} ({pfx.get('name', '')})"
            )
            findings.append(Finding("Announcing network", detail.strip(), Severity.INFO,
                                    {"asn": asn.get("asn"), "prefix": pfx.get("prefix")}))

        rir = info.get("rir_allocation", {}).get("rir_name")
        if rir:
            findings.append(Finding("RIR", str(rir), Severity.INFO))

        if not findings:
            findings.append(Finding("BGPView", "No routing data for this IP.", Severity.INFO))
        return ModuleResult(self.name, target.value, ok=True, findings=findings, raw=info)

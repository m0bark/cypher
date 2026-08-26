"""Registration data (WHOIS successor: RDAP) for domains and IPs via rdap.org.

RDAP is a modern JSON replacement for WHOIS. rdap.org bootstraps to the correct
authoritative registry, so no per-TLD configuration is needed.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


class RdapWhois(BaseModule):
    name = "rdap_whois"
    description = (
        "Registration data for a domain or IP (registrar, creation/expiry dates, "
        "name servers, abuse contacts, network owner/ASN) via RDAP."
    )
    applies_to = (TargetType.DOMAIN, TargetType.IP)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        kind = "domain" if target.type is TargetType.DOMAIN else "ip"
        url = f"https://rdap.org/{kind}/{target.value}"
        try:
            data = ctx.http.get_json(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"RDAP lookup failed: {exc}")

        findings: list[Finding] = []
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        if events:
            detail = "; ".join(f"{k}: {v}" for k, v in events.items() if k)
            findings.append(Finding("Registration events", detail, Severity.INFO, events))

        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
        if nameservers:
            findings.append(
                Finding("Name servers", ", ".join(nameservers), Severity.INFO,
                        {"nameservers": nameservers})
            )

        for entity in data.get("entities", []):
            roles = ", ".join(entity.get("roles", []))
            handle = entity.get("handle", "")
            if roles:
                findings.append(
                    Finding(f"Entity ({roles})", handle or "(no handle)", Severity.INFO)
                )

        if data.get("name"):
            findings.append(Finding("Network / object name", str(data["name"]), Severity.INFO))

        if not findings:
            findings.append(Finding("RDAP record", "Record retrieved but sparse.", Severity.INFO))

        return ModuleResult(
            module=self.name, target=target.value, ok=True, findings=findings, raw=data
        )

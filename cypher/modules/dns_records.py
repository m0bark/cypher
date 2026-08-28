"""DNS record enumeration via dnspython."""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType, parse_target

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")


class DnsRecords(BaseModule):
    name = "dns_records"
    description = (
        "Resolve DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) for a domain. "
        "Surfaces mail servers, name servers, SPF/DMARC hints and discovered IPs."
    )
    applies_to = (TargetType.DOMAIN,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        try:
            import dns.resolver
        except ImportError:
            return ModuleResult.failure(
                self.name, target.value, "dnspython not installed (pip install dnspython)"
            )

        findings: list[Finding] = []
        new_targets: list[Target] = []
        raw: dict[str, list[str]] = {}
        resolver = dns.resolver.Resolver()
        resolver.lifetime = ctx.settings.timeout

        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(target.value, rtype)
            except Exception:
                continue
            values = [r.to_text() for r in answers]
            raw[rtype] = values
            findings.append(
                Finding(
                    title=f"{rtype} records",
                    detail=", ".join(values),
                    severity=Severity.INFO,
                    data={"type": rtype, "values": values},
                )
            )
            if rtype in ("A", "AAAA"):
                for ip in values:
                    new_targets.append(parse_target(ip))
            if rtype == "MX":
                for v in values:
                    host = v.split()[-1].rstrip(".")
                    if host:
                        new_targets.append(parse_target(host))

        if not raw:
            return ModuleResult.failure(
                self.name, target.value, "No DNS records resolved."
            )

        self._flag_email_auth(raw, findings)
        return ModuleResult(
            module=self.name,
            target=target.value,
            ok=True,
            findings=findings,
            new_targets=new_targets,
            raw=raw,
        )

    @staticmethod
    def _flag_email_auth(raw: dict, findings: list[Finding]) -> None:
        txt = " ".join(raw.get("TXT", [])).lower()
        if "v=spf1" not in txt:
            findings.append(
                Finding(
                    "No SPF record",
                    "No 'v=spf1' TXT record found; domain is more spoofable.",
                    Severity.LOW,
                )
            )

"""Passive web-exposure lookup via the free urlscan.io search API.

urlscan.io runs and archives scans of URLs submitted by the community. Searching
by domain reveals historically observed hosts, IPs and page snapshots without
ever contacting the target.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


class UrlscanSearch(BaseModule):
    name = "urlscan"
    description = (
        "Search urlscan.io for prior scans of a domain: observed hostnames, IPs "
        "and page snapshots. Passive: queries urlscan.io, never the target."
    )
    applies_to = (TargetType.DOMAIN,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{target.value}&size=100"
        try:
            data = ctx.http.get_json(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"urlscan query failed: {exc}")

        results = data.get("results", [])
        if not results:
            return ModuleResult(
                self.name, target.value, ok=True,
                findings=[Finding("urlscan", "No prior scans found.", Severity.INFO)],
            )

        ips = sorted({r.get("page", {}).get("ip") for r in results if r.get("page", {}).get("ip")})
        servers = sorted({r.get("page", {}).get("server") for r in results
                          if r.get("page", {}).get("server")})
        pages = [r.get("page", {}).get("url") for r in results if r.get("page", {}).get("url")]

        findings = [Finding(f"{data.get('total', len(results))} archived scans",
                            f"{len(pages)} pages, {len(ips)} unique IPs", Severity.INFO)]
        if ips:
            findings.append(Finding("Observed IPs", ", ".join(ips[:20]), Severity.LOW,
                                    {"ips": ips}))
        if servers:
            findings.append(Finding("Observed servers", ", ".join(servers[:10]), Severity.INFO))
        return ModuleResult(self.name, target.value, ok=True, findings=findings, raw=results[:20])

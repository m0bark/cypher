"""HTTP(S) fingerprinting: status, server, security headers, page title.

This module contacts the target's own web server (contacts_target=True), so it
is skipped in passive-only runs.
"""

from __future__ import annotations

import re

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (forces HTTPS)",
    "content-security-policy": "CSP (mitigates XSS)",
    "x-frame-options": "clickjacking protection",
    "x-content-type-options": "MIME-sniffing protection",
    "referrer-policy": "referrer leakage control",
}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class HttpFingerprint(BaseModule):
    name = "http_fingerprint"
    description = (
        "Fetch the target over HTTPS and report status, server banner, page title "
        "and which security headers are present or missing. Directly contacts the "
        "target's web server."
    )
    applies_to = (TargetType.DOMAIN, TargetType.URL, TargetType.IP)
    contacts_target = True

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        url = target.value if target.type is TargetType.URL else f"https://{target.value}"
        try:
            resp = ctx.http.get(url)
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"HTTP request failed: {exc}")

        findings: list[Finding] = [
            Finding("HTTP status", f"{resp.status_code} for {url}", Severity.INFO)
        ]
        headers = {k.lower(): v for k, v in resp.headers.items()}

        if headers.get("server"):
            findings.append(Finding("Server header", headers["server"], Severity.INFO))
        if headers.get("x-powered-by"):
            findings.append(
                Finding("X-Powered-By", headers["x-powered-by"], Severity.LOW,
                        {"note": "reveals backend technology"})
            )

        title_match = _TITLE_RE.search(resp.text or "")
        if title_match:
            title = " ".join(title_match.group(1).split())[:200]
            findings.append(Finding("Page title", title, Severity.INFO))

        missing = [desc for h, desc in SECURITY_HEADERS.items() if h not in headers]
        if missing:
            findings.append(
                Finding(
                    f"{len(missing)} security headers missing",
                    "; ".join(missing),
                    Severity.MEDIUM,
                    {"missing": missing},
                )
            )

        return ModuleResult(
            module=self.name,
            target=target.value,
            ok=True,
            findings=findings,
            raw={"status": resp.status_code, "headers": headers},
        )

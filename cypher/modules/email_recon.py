"""Passive email recon: mail-server presence and Gravatar existence.

Deliberately conservative: it confirms the domain can receive mail and whether a
public Gravatar exists for the address. It does not attempt SMTP probing or any
verification that would contact third parties on the person's behalf.
"""

from __future__ import annotations

import hashlib

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType, parse_target


class EmailRecon(BaseModule):
    name = "email_recon"
    description = (
        "Passive checks for an email address: whether its domain has MX records "
        "(can receive mail) and whether a public Gravatar profile exists. Emits "
        "the email's domain as a follow-on target."
    )
    applies_to = (TargetType.EMAIL,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        domain = target.parent or target.value.split("@", 1)[-1]
        findings: list[Finding] = []
        new_targets = [parse_target(domain)]

        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.lifetime = ctx.settings.timeout
            mx = [r.to_text() for r in resolver.resolve(domain, "MX")]
            findings.append(Finding("Mail servers (MX)", ", ".join(mx), Severity.INFO,
                                    {"mx": mx}))
        except Exception:
            findings.append(
                Finding("Mail servers (MX)", "None found — domain may not receive mail.",
                        Severity.LOW)
            )

        digest = hashlib.md5(target.value.strip().lower().encode()).hexdigest()
        gravatar = f"https://www.gravatar.com/avatar/{digest}?d=404"
        try:
            resp = ctx.http.get(gravatar)
            if resp.status_code == 200:
                findings.append(
                    Finding("Gravatar exists", f"https://www.gravatar.com/{digest}",
                            Severity.LOW, {"hash": digest})
                )
            else:
                findings.append(Finding("Gravatar", "No public Gravatar for this address.",
                                        Severity.INFO))
        except Exception:
            pass

        return ModuleResult(
            module=self.name, target=target.value, ok=True,
            findings=findings, new_targets=new_targets,
        )

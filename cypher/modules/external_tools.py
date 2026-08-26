"""Adapters for external CLI OSINT tools (the Kali toolchain).

Each ToolSpec becomes a discoverable module. If the binary is not on PATH the
module returns a clean 'skipped — install X' result. Commands are executed
without a shell and with a hard timeout; the target value is passed as an argv
element, never interpolated into a shell string.

Active/intrusive tools (e.g. nmap) set contacts_target=True and are skipped in
passive-only runs and gated behind the authorization prompt like everything else.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType

EXTERNAL_TOOL_TIMEOUT = 300  # seconds; hard cap per tool
MAX_PREVIEW_LINES = 25


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    description: str
    applies_to: tuple[TargetType, ...]
    build_args: Callable[[str], list[str]]
    contacts_target: bool = False
    install_hint: str = ""


SPECS: list[ToolSpec] = [
    ToolSpec(
        "theharvester", "theHarvester",
        "Harvest emails, subdomains and hosts for a domain from public sources "
        "(search engines, crt.sh, etc.) using theHarvester.",
        (TargetType.DOMAIN,),
        lambda d: ["-d", d, "-b", "crtsh,duckduckgo,hackertarget", "-l", "200"],
        install_hint="apt install theharvester  (or pipx install theHarvester)",
    ),
    ToolSpec(
        "amass", "amass",
        "Passive subdomain enumeration for a domain via OWASP Amass.",
        (TargetType.DOMAIN,),
        lambda d: ["enum", "-passive", "-d", d, "-timeout", "3"],
        install_hint="apt install amass  (or snap install amass)",
    ),
    ToolSpec(
        "subfinder", "subfinder",
        "Fast passive subdomain discovery for a domain via ProjectDiscovery subfinder.",
        (TargetType.DOMAIN,),
        lambda d: ["-silent", "-d", d],
        install_hint="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    ToolSpec(
        "whois", "whois",
        "Classic WHOIS registration lookup for a domain or IP.",
        (TargetType.DOMAIN, TargetType.IP),
        lambda t: [t],
        install_hint="apt install whois",
    ),
    ToolSpec(
        "nmap", "nmap",
        "Fast TCP port/service scan of a host (top ports). ACTIVE: directly "
        "probes the target and requires authorization.",
        (TargetType.DOMAIN, TargetType.IP),
        lambda t: ["-T4", "-F", "-Pn", t],
        contacts_target=True,
        install_hint="apt install nmap",
    ),
    ToolSpec(
        "holehe", "holehe",
        "Check which online services have an account registered to an email "
        "(password-reset oracle) via holehe. Best used on your own address.",
        (TargetType.EMAIL,),
        lambda e: ["--only-used", e],
        install_hint="pipx install holehe",
    ),
    ToolSpec(
        "sherlock", "sherlock",
        "Hunt a username across social networks via sherlock.",
        (TargetType.USERNAME,),
        lambda u: ["--print-found", "--timeout", "10", u],
        install_hint="pipx install sherlock-project",
    ),
]


class ExternalToolModule(BaseModule):
    """Base for external-binary adapters. Concrete specs are generated below."""

    spec: ToolSpec | None = None

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        assert self.spec is not None
        binary_path = shutil.which(self.spec.binary)
        if not binary_path:
            return ModuleResult.skip(
                self.name, target.value,
                f"'{self.spec.binary}' not on PATH. Install: {self.spec.install_hint}",
            )

        argv = [binary_path, *self.spec.build_args(target.value)]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=EXTERNAL_TOOL_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ModuleResult.failure(
                self.name, target.value,
                f"{self.spec.binary} timed out after {EXTERNAL_TOOL_TIMEOUT}s.",
            )
        except Exception as exc:
            return ModuleResult.failure(self.name, target.value, f"exec failed: {exc}")

        output = (proc.stdout or "").strip()
        if not output and proc.returncode != 0:
            err = (proc.stderr or "").strip()[:400]
            return ModuleResult.failure(
                self.name, target.value,
                f"{self.spec.binary} exited {proc.returncode}: {err or 'no output'}",
            )

        return self._parse(target, output, proc.returncode)

    def _parse(self, target: Target, output: str, returncode: int) -> ModuleResult:
        assert self.spec is not None
        lines = [ln for ln in output.splitlines() if ln.strip()]
        hits = [ln for ln in lines if "http" in ln.lower() or ln.strip().startswith("[+]")]
        preview = "\n".join(lines[:MAX_PREVIEW_LINES])
        if len(lines) > MAX_PREVIEW_LINES:
            preview += f"\n... (+{len(lines) - MAX_PREVIEW_LINES} more lines)"

        severity = Severity.LOW if hits else Severity.INFO
        findings = [
            Finding(
                f"{self.spec.binary}: {len(lines)} lines",
                preview or "(no output)",
                severity,
                {"hits": hits[:50], "returncode": returncode},
            )
        ]
        return ModuleResult(
            module=self.name, target=target.value, ok=True, findings=findings, raw=output
        )


def _make_module(spec: ToolSpec) -> type[ExternalToolModule]:
    return type(
        f"ExternalTool_{spec.name}",
        (ExternalToolModule,),
        {
            "name": spec.name,
            "description": spec.description,
            "applies_to": spec.applies_to,
            "contacts_target": spec.contacts_target,
            "spec": spec,
        },
    )


# Generate one discoverable module class per spec.
for _spec in SPECS:
    globals()[f"ExternalTool_{_spec.name}"] = _make_module(_spec)

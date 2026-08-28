"""Adapters for external CLI OSINT tools (the Kali toolchain).

Each ToolSpec becomes a discoverable module. If the binary is not on PATH the
module returns a clean 'skipped — install X' result. Commands are executed
without a shell and with a hard timeout; the target value is passed as an argv
element, never interpolated into a shell string.

Active/intrusive tools (nmap, nikto, nuclei, gobuster, ...) set
contacts_target=True: they directly probe the target, are skipped in
passive-only runs, and are gated behind the authorization prompt.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType

EXTERNAL_TOOL_TIMEOUT = 300
MAX_PREVIEW_LINES = 25
DIRB_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_NOISE_MARKERS = ("donation", "megadose", "@palenath", "1FHDM49", "twitter :", "github :")


def _url(target: str) -> str:
    """Ensure a value is an http(s) URL for tools that require one."""
    return target if target.startswith(("http://", "https://")) else f"https://{target}"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    description: str
    applies_to: tuple[TargetType, ...]
    build_args: Callable[[str], list[str]]
    contacts_target: bool = False
    install_hint: str = ""
    verify_hits: bool = False


CONTROL_HANDLE = "zqx9no7user000zz"


D = (TargetType.DOMAIN,)
DU = (TargetType.DOMAIN, TargetType.URL)
DUI = (TargetType.DOMAIN, TargetType.URL, TargetType.IP)
DI = (TargetType.DOMAIN, TargetType.IP)
IP = (TargetType.IP,)
EMAIL = (TargetType.EMAIL,)
USER = (TargetType.USERNAME,)

SPECS: list[ToolSpec] = [
    ToolSpec("theharvester", "theHarvester",
             "Harvest emails, subdomains and hosts for a domain from public "
             "sources (search engines, crt.sh) via theHarvester.",
             D, lambda d: ["-d", d, "-b", "crtsh,duckduckgo,hackertarget", "-l", "200"],
             install_hint="apt install theharvester"),
    ToolSpec("amass", "amass",
             "Passive subdomain enumeration for a domain via OWASP Amass.",
             D, lambda d: ["enum", "-passive", "-d", d, "-timeout", "3"],
             install_hint="apt install amass"),
    ToolSpec("subfinder", "subfinder",
             "Fast passive subdomain discovery via ProjectDiscovery subfinder.",
             D, lambda d: ["-silent", "-d", d],
             install_hint="apt install subfinder"),
    ToolSpec("assetfinder", "assetfinder",
             "Find domains and subdomains related to a domain (assetfinder).",
             D, lambda d: ["--subs-only", d],
             install_hint="apt install assetfinder  (or go install github.com/tomnomnom/assetfinder@latest)"),
    ToolSpec("findomain", "findomain",
             "Cross-source subdomain enumeration via Findomain.",
             D, lambda d: ["-t", d, "-q"],
             install_hint="apt install findomain"),
    ToolSpec("sublist3r", "sublist3r",
             "Subdomain enumeration from search engines via Sublist3r.",
             D, lambda d: ["-d", d],
             install_hint="apt install sublist3r"),
    ToolSpec("dnsrecon", "dnsrecon",
             "DNS enumeration: records, SRV, zone-transfer attempts (dnsrecon).",
             D, lambda d: ["-d", d],
             install_hint="apt install dnsrecon"),
    ToolSpec("dnsenum", "dnsenum",
             "DNS info, zone transfers and host enumeration via dnsenum.",
             D, lambda d: ["--noreverse", d],
             install_hint="apt install dnsenum"),
    ToolSpec("fierce", "fierce",
             "DNS reconnaissance and subdomain scanning via fierce.",
             D, lambda d: ["--domain", d],
             install_hint="apt install fierce"),
    ToolSpec("dnstwist", "dnstwist",
             "Detect typosquatting / phishing look-alike domains via dnstwist.",
             D, lambda d: ["--format", "cli", "--registered", d],
             install_hint="apt install dnstwist"),
    ToolSpec("gau", "gau",
             "Fetch known URLs for a domain from Wayback, OTX and urlscan (getallurls).",
             D, lambda d: [d],
             install_hint="go install github.com/lc/gau/v2/cmd/gau@latest"),
    ToolSpec("waybackurls", "waybackurls",
             "Pull historical URLs for a domain from the Wayback Machine.",
             D, lambda d: [d],
             install_hint="go install github.com/tomnomnom/waybackurls@latest"),
    ToolSpec("whois", "whois",
             "Classic WHOIS registration lookup for a domain or IP.",
             DI, lambda t: [t],
             install_hint="apt install whois"),

    ToolSpec("whatweb", "whatweb",
             "Fingerprint web technologies, CMS, servers and plugins (WhatWeb).",
             DU, lambda t: ["--color=never", _url(t)], contacts_target=True,
             install_hint="apt install whatweb"),
    ToolSpec("wafw00f", "wafw00f",
             "Detect and identify Web Application Firewalls (wafw00f).",
             DU, lambda t: [_url(t)], contacts_target=True,
             install_hint="apt install wafw00f"),
    ToolSpec("httpx", "httpx-toolkit",
             "Probe a host: status, title, tech, redirects (ProjectDiscovery httpx).",
             DU, lambda t: ["-u", _url(t), "-silent", "-title", "-status-code",
                            "-tech-detect", "-no-color"], contacts_target=True,
             install_hint="apt install httpx-toolkit"),
    ToolSpec("katana", "katana",
             "Crawl a site and enumerate endpoints/links (ProjectDiscovery katana).",
             DU, lambda t: ["-u", _url(t), "-silent", "-no-color"], contacts_target=True,
             install_hint="apt install katana  (or go install ...katana)"),
    ToolSpec("nuclei", "nuclei",
             "Template-based vulnerability and misconfig scanner (nuclei). ACTIVE.",
             DU, lambda t: ["-u", _url(t), "-silent", "-no-color"], contacts_target=True,
             install_hint="apt install nuclei"),
    ToolSpec("nikto", "nikto",
             "Web server vulnerability scanner (nikto). ACTIVE and noisy.",
             DUI, lambda t: ["-host", _url(t), "-maxtime", "120s", "-nointeractive"],
             contacts_target=True, install_hint="apt install nikto"),
    ToolSpec("gobuster", "gobuster",
             "Brute-force web content/directories with a wordlist (gobuster). ACTIVE.",
             DU, lambda t: ["dir", "-u", _url(t), "-w", DIRB_WORDLIST, "-q", "-z"],
             contacts_target=True, install_hint="apt install gobuster dirb"),
    ToolSpec("wpscan", "wpscan",
             "WordPress security scanner: users, plugins, versions (wpscan). ACTIVE.",
             DU, lambda t: ["--url", _url(t), "--no-banner", "--random-user-agent"],
             contacts_target=True, install_hint="apt install wpscan"),
    ToolSpec("sslscan", "sslscan",
             "Enumerate TLS versions, ciphers and certificate details (sslscan).",
             DI, lambda t: [t], contacts_target=True,
             install_hint="apt install sslscan"),

    ToolSpec("nmap", "nmap",
             "Fast TCP port/service scan of a host (top ports). ACTIVE.",
             DI, lambda t: ["-T4", "-F", "-Pn", t], contacts_target=True,
             install_hint="apt install nmap"),
    ToolSpec("naabu", "naabu",
             "Fast port scanner (ProjectDiscovery naabu). ACTIVE.",
             DI, lambda t: ["-host", t, "-silent", "-no-color"], contacts_target=True,
             install_hint="apt install naabu"),
    ToolSpec("rustscan", "rustscan",
             "Ultra-fast port scanner (rustscan). ACTIVE.",
             DI, lambda t: ["-a", t, "-g", "--no-banner"], contacts_target=True,
             install_hint="apt install rustscan  (or cargo install rustscan)"),

    ToolSpec("holehe", "holehe",
             "Find which services have an account for an email (holehe).",
             EMAIL, lambda e: ["--only-used", e],
             install_hint="pipx install holehe"),
    ToolSpec("h8mail", "h8mail",
             "Hunt an email across breach datasets and leaks (h8mail).",
             EMAIL, lambda e: ["-t", e],
             install_hint="pipx install h8mail"),
    ToolSpec("mosint", "mosint",
             "Automated email OSINT: breaches, social, related data (mosint).",
             EMAIL, lambda e: [e],
             install_hint="go install github.com/alpkeskin/mosint/v3/cmd/mosint@latest"),
    ToolSpec("socialscan", "socialscan",
             "Check email/username availability across platforms (socialscan).",
             (TargetType.EMAIL, TargetType.USERNAME), lambda t: [t],
             install_hint="pipx install socialscan"),

    ToolSpec("sherlock", "sherlock",
             "Hunt a username across ~400 social networks (sherlock). Each hit is "
             "control-verified to strip its soft-404 false positives.",
             USER, lambda u: ["--print-found", "--timeout", "10", u],
             install_hint="pipx install sherlock-project", verify_hits=True),
    ToolSpec("maigret", "maigret",
             "Deep username search across 2500+ sites (maigret), with each hit "
             "control-verified to strip false positives.",
             USER, lambda u: [u, "--timeout", "10", "--no-color"],
             install_hint="pipx install maigret", verify_hits=True),
]


_HIT_URL_RE = re.compile(r"https?://[^\s)\]]+")


def _hit_url(line: str) -> str | None:
    m = _HIT_URL_RE.search(line)
    return m.group(0).rstrip(".,") if m else None


def _verify_hit(url: str, uname: str, ctx: Context) -> bool:
    """True if the profile plausibly exists: the handle resolves where a known
    garbage control handle 404s. Kills soft-404 platforms that 200 for anything."""
    ctrl = url.replace(uname, CONTROL_HANDLE, 1)
    if ctrl == url:
        return True
    try:
        r1 = ctx.http.get(url, timeout=8)
        r2 = ctx.http.get(ctrl, timeout=8)
    except Exception:
        return True
    if r1.status_code >= 400:
        return False
    if r2.status_code >= 400:
        return True
    return abs(len(r1.text or "") - len(r2.text or "")) > 600


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
            with tempfile.TemporaryDirectory(prefix="cypher-tool-") as workdir:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=EXTERNAL_TOOL_TIMEOUT,
                    check=False,
                    cwd=workdir,
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

        return self._parse(target, output, proc.returncode, ctx)

    def _parse(self, target: Target, output: str, returncode: int, ctx: Context) -> ModuleResult:
        assert self.spec is not None
        output = _ANSI_RE.sub("", output)
        lines = [
            ln.strip()
            for ln in output.splitlines()
            if ln.strip() and not any(m in ln.lower() for m in _NOISE_MARKERS)
        ]

        plus = [
            ln for ln in lines
            if ln.startswith("[+]") and "[-]" not in ln and "[x]" not in ln
        ]
        hits = plus if plus else [ln for ln in lines if "http" in ln.lower()]
        tv = target.value.lower()
        hits = [ln for ln in hits if "http" not in ln.lower() or tv in ln.lower()]

        dropped = 0
        if self.spec and self.spec.verify_hits and hits:
            kept = []
            for ln in hits[:30]:
                u = _hit_url(ln)
                if u and not _verify_hit(u, tv, ctx):
                    dropped += 1
                else:
                    kept.append(ln)
            hits = kept

        if hits:
            detail = "; ".join(hits[:40])
            if len(hits) > 40:
                detail += f" ... (+{len(hits) - 40} more)"
            title = f"{self.spec.binary}: {len(hits)} hits"
            if self.spec.verify_hits:
                title += " (control-verified)"
            findings = [
                Finding(title, detail, Severity.LOW,
                        {"hits": hits[:60], "returncode": returncode})
            ]
            if dropped:
                findings.append(Finding(
                    f"{dropped} false positives filtered",
                    "control-check dropped soft-404 platforms that return 200 for any handle.",
                    Severity.INFO))
        else:
            preview = "\n".join(lines[:MAX_PREVIEW_LINES])
            if len(lines) > MAX_PREVIEW_LINES:
                preview += f"\n... (+{len(lines) - MAX_PREVIEW_LINES} more lines)"
            findings = [
                Finding(
                    f"{self.spec.binary}: {len(lines)} lines",
                    preview or "(no output)",
                    Severity.INFO,
                    {"returncode": returncode},
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


for _spec in SPECS:
    globals()[f"ExternalTool_{_spec.name}"] = _make_module(_spec)

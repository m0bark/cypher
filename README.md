# Cypher

**AI-orchestrated OSINT framework.** Pluggable modules self-register, an
orchestrator (optionally Claude) decides which modules to run against a target,
and the collected findings are synthesized into one report — Markdown + JSON.

Cypher is the brain; your installed tooling (including the Kali OSINT suite) are
the hands.

## Authorized use only

Cypher gathers only open-source, publicly available data — but that does not make
every use acceptable. Use it on:

- infrastructure and accounts **you own** or are **explicitly authorized** to assess (a pentest scope, a client engagement);
- your **own / your org's** exposure (defensive self-check).

**Do not** use it to profile, locate, or build a dossier on a private individual
who has not consented. Cypher flags person-like targets and makes you confirm
authorization before it proceeds. That gate is a conscience speed bump, not a
security control — the responsibility is yours.

## Install

```bash
cd D:\cypher
python -m venv .venv
.venv\Scripts\activate           # Windows;  source .venv/bin/activate on Linux
pip install -e ".[all]"          # core + AI + rich + dotenv + pytest
# minimal: pip install -e .      # core only (httpx, dnspython)
```

Copy `.env.example` to `.env` and fill in what you have (all optional). With
`ANTHROPIC_API_KEY` set, Claude plans and writes the report; without it, Cypher
uses a deterministic plan and a templated summary.

## Usage

```bash
cypher modules                       # list modules + status
cypher scan example.com              # full run (asks for authorization)
cypher scan example.com --passive    # skip modules that touch the target
cypher scan example.com --no-ai      # deterministic, no API calls
cypher scan 8.8.8.8 --modules rdap_whois,ip_info
cypher scan user@example.com --depth 2   # expand into discovered domains
cypher scan someuser                 # username -> github, sherlock, ...
```

Reports are written to `reports/<target>.md` and `.json`.

## Built-in modules (no external tools needed)

| Module | Target | What it does |
|---|---|---|
| `dns_records` | domain | A/AAAA/MX/NS/TXT/SOA/CNAME, SPF hint |
| `rdap_whois` | domain, ip | Registration data via RDAP |
| `crtsh_subdomains` | domain | Subdomains from certificate transparency (passive) |
| `http_fingerprint` | domain, url, ip | Status, server, security headers, title (active) |
| `ip_info` | ip | Geolocation + network owner/ASN |
| `wayback` | domain | Historical URLs from the Internet Archive |
| `github_recon` | username, org | Public GitHub profile + repos |
| `email_recon` | email | MX presence + Gravatar (passive) |
| `breach_check` | email | Have I Been Pwned (needs `HIBP_API_KEY`) |

## External tool adapters (Kali toolchain)

If these binaries are on `PATH`, Cypher drives them and folds their output into
the report; if not, that module cleanly reports "install X".

`theHarvester`, `amass`, `subfinder`, `whois`, `nmap` (active), `holehe`, `sherlock`.

## Architecture

```
target string ─▶ parse_target ─▶ scope gate ─▶ Orchestrator
                                                   │ plan  (Claude or deterministic)
                                                   ▼
                              registry ─▶ modules run ─▶ Context (findings)
                                                   │ synthesize (Claude or template)
                                                   ▼
                                        report/renderer ─▶ .md + .json
```

Add a module: drop a `BaseModule` subclass in `cypher/modules/`; the registry
discovers it and the AI planner can select it. Keep heavy imports inside `run()`.

## Tests

```bash
pytest            # target detection, registry discovery, scope guard (no network)
```

## License

MIT.

# Cypher

**OSINT scanner console.** Point it at a target — handle, email, domain, IP,
phone, wallet, or image — and it picks the right modules, runs them, follows the
leads (pivoting into discovered accounts), and lays the results out as a
dashboard: exposure grade, entity map, findings, and per-target notes. Pluggable
modules self-register; the Kali toolchain plugs in when present.

## Authorized use only

Cypher gathers only open-source, publicly available data — that does not make
every use acceptable. Use it on:

- infrastructure and accounts **you own** or are **explicitly authorized** to assess (a pentest scope, a client engagement);
- your **own / your org's** exposure (a defensive self-check).

**Do not** use it to profile, locate, or build a dossier on a private individual
who has not consented. Cypher flags person-like targets and makes you confirm
authorization before it proceeds. That gate is a conscience speed bump, not a
security control — the responsibility is yours.

## Quick start

**Windows** — double-click `run.bat`.
**Linux / Kali** — `./run.sh`.

The first launch builds a virtual environment, installs Cypher and the common
OSINT tools, then opens the console at `http://127.0.0.1:8765`. It binds to
localhost only.

## No accounts, no credits

The scanner needs no login and no API keys — just double-click and go. The written
briefing is a deterministic template by default; an optional AI briefing can run
on your Claude Code subscription (`CYPHER_LLM=cli`, free, no API credits) or the
paid API (`ANTHROPIC_API_KEY`). Everything else — scans, entity map, scorecard,
findings — works without any of that.

## What it does

- **Auto target typing** — domain, IP, email, URL, username, phone, name, image, or crypto address.
- **Follow-leads pivots** — deterministically expands into discovered accounts (no AI required).
- **Entity map** — live force-directed graph of what connects to what; drag nodes, click one to scan it.
- **Exposure scorecard** — a 0–100 grade with the factors behind it.
- **Verify list** — ambiguous profile hits become a yes / maybe / no checklist instead of false certainty.
- **Reverse-image** — pfp hits get one-click reverse search across Google, Yandex, Bing, TinEye and more.
- **Timeline** — dated findings (registrations, breaches) assembled into a chronology.
- **Notes** — a per-target scratchpad, saved locally and folded into the report.
- **Footprint diff** — a re-scan shows what appeared or vanished since last time.
- **HTML report** — one-click standalone report of any scan.

## CLI

The console is optional — everything is scriptable:

```bash
cypher modules                       # list modules + status
cypher scan example.com              # full run (asks for authorization)
cypher scan example.com --passive    # skip modules that touch the target
cypher scan 8.8.8.8 --modules rdap_whois,ip_info
cypher scan user@example.com --depth 2   # expand into discovered entities
```

Reports are written to `reports/<target>.md` and `.json`.

## Modules

Built-in (no external tools needed) cover DNS/RDAP/WHOIS, certificate-transparency
subdomains, HTTP fingerprinting, IP geolocation, Wayback history, GitHub recon,
email + breach checks (Have I Been Pwned), username enumeration, phone intel,
Telegram / Instagram / Discord lookups, Google dorks, reverse-image links, and
public blockchain lookup for BTC/ETH addresses.

External-tool adapters drive the Kali suite when the binaries are on `PATH`
(`theHarvester`, `amass`, `subfinder`, `nmap`, `sherlock`, `maigret`, `holehe`,
`nuclei`, and more); if a tool is missing, that module cleanly reports how to
install it.

## Architecture

```
target string ─▶ parse_target ─▶ scope gate ─▶ Orchestrator
                                                   │ plan  (Claude or deterministic)
                                                   ▼
                              registry ─▶ modules run ─▶ Context (findings)
                                                   │ synthesize (Claude or template)
                                                   ▼
                                report/renderer ─▶ .md + .json  ·  web console
```

Add a module: drop a `BaseModule` subclass in `cypher/modules/`; the registry
discovers it and the planner can select it. Keep heavy imports inside `run()`.

## Tests

```bash
pytest            # target detection, registry discovery, scope guard (no network)
```

## License

MIT.

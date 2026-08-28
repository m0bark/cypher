# Cypher

**AI-orchestrated OSINT console.** You talk to Cypher — an analyst persona — in a
chat-first web UI. It picks the right modules for a target, runs them, correlates
the findings, and briefs you back. Pluggable modules self-register; the Kali
toolchain plugs in when present. Cypher is the brain, your installed tooling is
the hands.

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

## AI on your Claude subscription (no API credits)

Cypher's chat and briefings run on your existing Claude Code subscription via the
`claude` CLI — no per-token API billing. The launcher writes `CYPHER_LLM=cli` to
`.env` for you; just have the CLI installed and logged in (`claude` once). Prefer
the paid API instead? Put `ANTHROPIC_API_KEY=...` in `.env`. With neither, scans,
the entity graph, the scorecard and the profile cards all still work — only the
written briefing falls back to a template.

## What it does

- **Chat-first** — describe a target in plain language; Cypher runs the scan itself and briefs you.
- **Auto target typing** — domain, IP, email, URL, username, phone, name, image, or crypto address.
- **Entity graph** — live force-directed map of what connects to what.
- **Exposure scorecard** — a 0–100 grade with the factors behind it.
- **Verify list** — ambiguous profile hits become a yes / maybe / no checklist instead of false certainty.
- **Timeline** — dated findings (registrations, breaches) assembled into a chronology.
- **Remove-me** — opt-out and account-deletion links for what a self-scan surfaced.
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

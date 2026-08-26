"""Write an investigation as an Obsidian-friendly Markdown note.

Produces a note with YAML frontmatter (target, type, date, tags) and
[[wikilinks]] to every discovered entity (subdomains, IPs, emails), so an
Obsidian vault builds a live graph of the investigation over time.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from ..ai.orchestrator import Investigation
from ..core.module import Severity
from .renderer import _slug

SUBFOLDER = "Cypher"
_SEV_EMOJI = {
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟠",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _discovered_entities(inv: Investigation) -> list[str]:
    seen: list[str] = []
    for res in inv.results:
        for nt in res.new_targets:
            if nt.value not in seen and nt.value != inv.target.value:
                seen.append(nt.value)
    return seen


def to_note(inv: Investigation) -> str:
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    tags = ["osint", "cypher", inv.target.type.value]
    lines = [
        "---",
        f"target: {inv.target.value}",
        f"type: {inv.target.type.value}",
        f"date: {date}",
        f"ai: {str(inv.ai_used).lower()}",
        f"tags: [{', '.join(tags)}]",
        "---",
        "",
        f"# {inv.target.value}",
        "",
        "## Summary",
        inv.summary or "_(no summary)_",
        "",
        "## Findings",
    ]

    for res in inv.results:
        if res.skipped or not res.findings:
            continue
        lines.append(f"### {res.module}")
        for f in res.findings:
            emoji = _SEV_EMOJI.get(f.severity, "⚪")
            lines.append(f"- {emoji} **{f.title}** — {f.detail}")
        lines.append("")

    entities = _discovered_entities(inv)
    if entities:
        lines.append("## Discovered entities")
        lines += [f"- [[{e}]]" for e in entities]
        lines.append("")

    return "\n".join(lines)


def write_note(inv: Investigation, vault_dir: str) -> str:
    """Write the note into <vault>/Cypher/<target>.md and return its path."""
    folder = os.path.join(os.path.expanduser(vault_dir), SUBFOLDER)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{_slug(inv.target.value)}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_note(inv))
    return path

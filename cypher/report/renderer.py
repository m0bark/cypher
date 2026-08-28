"""Render an Investigation to Markdown and JSON, and write to disk."""

from __future__ import annotations

import json
import os
from dataclasses import asdict

from ..ai.orchestrator import Investigation
from ..core.module import ModuleResult


def _slug(value: str) -> str:
    keep = "".join(c if c.isalnum() else "-" for c in value)
    return keep.strip("-").lower() or "target"


def to_markdown(inv: Investigation) -> str:
    lines = [
        f"# Cypher report — {inv.target.value}",
        "",
        f"- **Target type:** {inv.target.type.value}",
        f"- **AI orchestration:** {'on' if inv.ai_used else 'off (deterministic)'}",
        f"- **Modules planned:** {', '.join(inv.plan) or '(none)'}",
    ]
    if inv.expanded_targets:
        lines.append(f"- **Expanded into:** {', '.join(inv.expanded_targets)}")
    if inv.plan_reasoning:
        lines += ["", f"> _Plan rationale:_ {inv.plan_reasoning}"]

    lines += ["", "## Intelligence summary", "", inv.summary or "_(no summary)_", ""]

    lines += ["## Module results", ""]
    for res in inv.results:
        lines.append(f"### {res.module} — `{res.target}`")
        if res.skipped:
            lines.append(f"- _skipped: {res.findings[0].detail if res.findings else ''}_")
        elif not res.ok:
            lines.append(f"- **error:** {res.error}")
        elif not res.findings:
            lines.append("- _(no findings)_")
        else:
            for f in res.findings:
                lines.append(f"- **{f.title}** ({f.severity.value}): {f.detail}")
        lines.append("")
    return "\n".join(lines)


def _result_dict(res: ModuleResult) -> dict:
    d = asdict(res)
    d.pop("raw", None)
    return d


def to_json(inv: Investigation) -> str:
    doc = {
        "target": {"value": inv.target.value, "type": inv.target.type.value},
        "ai_used": inv.ai_used,
        "plan": inv.plan,
        "plan_reasoning": inv.plan_reasoning,
        "expanded_targets": inv.expanded_targets,
        "summary": inv.summary,
        "results": [_result_dict(r) for r in inv.results],
    }
    return json.dumps(doc, indent=2, default=str)


def write_report(inv: Investigation, out_dir: str) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    base = _slug(inv.target.value)
    md_path = os.path.join(out_dir, f"{base}.md")
    json_path = os.path.join(out_dir, f"{base}.json")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(inv))
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(to_json(inv))
    return {"markdown": md_path, "json": json_path}

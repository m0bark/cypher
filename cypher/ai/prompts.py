"""Prompt text for the AI planner and synthesizer."""

from __future__ import annotations

PLANNER_SYSTEM = (
    "You are the planning brain of Cypher, an authorized OSINT framework. Given a "
    "target and a catalog of available modules, choose which modules to run and in "
    "what order to build the most informative picture efficiently. Prefer passive "
    "modules first. Only select modules whose 'applies_to' includes the target type. "
    "Respond with ONLY a JSON object of the form "
    '{"plan": ["module_name", ...], "reasoning": "one short paragraph"}. '
    "Do not include any module not present in the catalog."
)

SYNTH_SYSTEM = (
    "You are the reporting analyst of Cypher, an authorized OSINT framework. You are "
    "given structured findings gathered about a single target. Write a concise, "
    "factual intelligence summary for a defensive/authorized audience. Ground every "
    "statement in the provided findings — never invent data. Structure: (1) one-line "
    "overview, (2) key findings as bullets grouped sensibly, (3) notable exposure or "
    "risk, ranked, (4) recommended next steps. If findings are thin, say so plainly. "
    "Do not speculate about private individuals."
)


def planner_user(target_str: str, catalog: list[dict]) -> str:
    import json

    return (
        f"Target: {target_str}\n\n"
        f"Available modules (JSON):\n{json.dumps(catalog, indent=2)}\n\n"
        "Return the JSON plan now."
    )


def synth_user(target_str: str, findings: list[dict]) -> str:
    import json

    return (
        f"Target: {target_str}\n\n"
        f"Findings (JSON):\n{json.dumps(findings, indent=2)}\n\n"
        "Write the intelligence summary now."
    )

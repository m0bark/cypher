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
    "You are the correlation analyst of Cypher, an authorized OSINT framework. You are "
    "given structured findings gathered about a single target — often the user's OWN "
    "footprint, for a defensive self-check. Your job is to CONNECT THE DOTS: read "
    "across every module and produce one coherent assessment, not a list.\n\n"
    "Do:\n"
    "- Cluster the discovered accounts/entities that plausibly belong together, and say "
    "WHY (shared handle, one profile linking to another, matching display name).\n"
    "- Call out explicit cross-references (profile A links to profile B).\n"
    "- Give each linkage a confidence level (low/medium/high) and say what would raise it.\n"
    "- If findings carry dates, assemble a short timeline.\n"
    "- Separate corroborated signal from weak/coincidental matches (common-word handle "
    "collisions, OCR artifacts, unrelated same-name accounts) into a discard pile.\n"
    "- State the aggregate picture, and — for a self-check — the concrete exposure and "
    "what to lock down or delete.\n\n"
    "Rules:\n"
    "- Ground EVERY statement in the provided findings. Never invent names, locations, "
    "employers, or links that are not present in the data.\n"
    "- A shared username is NOT proof of the same person; keep identity claims "
    "probabilistic and say so.\n"
    "- Do not infer sensitive attributes (real identity, home address, employer) beyond "
    "what the data explicitly states.\n\n"
    "Structure: (1) one-line overview, (2) linked clusters with confidence and the "
    "evidence for each link, (3) timeline if any dated findings exist, (4) discard pile "
    "(weak/coincidental), (5) aggregate exposure + concrete recommended actions."
)


def planner_user(target_str: str, catalog: list[dict]) -> str:
    import json

    return (
        f"Target: {target_str}\n\n"
        f"Available modules (JSON):\n{json.dumps(catalog, indent=2)}\n\n"
        "Return the JSON plan now."
    )


def synth_user(target_str: str, findings: list[dict], entities: dict | None = None) -> str:
    import json

    parts = [
        f"Target: {target_str}",
        "",
        f"Findings (JSON):\n{json.dumps(findings, indent=2)}",
    ]
    if entities:
        parts += [
            "",
            "Discovered entities and which modules surfaced each "
            f"(JSON):\n{json.dumps(entities, indent=2)}",
        ]
    parts += ["", "Connect the dots and write the correlation assessment now."]
    return "\n".join(parts)

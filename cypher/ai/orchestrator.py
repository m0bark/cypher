"""The orchestrator: plan -> execute -> synthesize.

With an ANTHROPIC_API_KEY, Claude plans the module run and writes the summary.
Without one, Cypher falls back to a deterministic plan (all applicable modules,
passive first) and a templated summary — so the tool is fully usable offline
from the AI, and the AI is a strict enhancement.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..core.context import Context
from ..core.module import ModuleResult, Severity
from ..core.registry import Registry
from ..core.target import Target, parse_target
from . import prompts

_SEVERITY_ORDER = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}


@dataclass
class Investigation:
    target: Target
    plan: list[str]
    plan_reasoning: str
    results: list[ModuleResult] = field(default_factory=list)
    summary: str = ""
    ai_used: bool = False
    expanded_targets: list[str] = field(default_factory=list)

    def entity_map(self) -> dict:
        """Discovered entities -> {type, modules that surfaced it}. Raw material
        for connecting the dots across modules."""
        ent: dict = {}
        for res in self.results:
            for nt in res.new_targets:
                if nt.value == self.target.value:
                    continue
                rec = ent.setdefault(nt.value, {"type": nt.type.value, "modules": []})
                if res.module not in rec["modules"]:
                    rec["modules"].append(res.module)
        return ent

    def findings_payload(self) -> list[dict]:
        payload = []
        for res in self.results:
            if res.skipped or not res.findings:
                continue
            payload.append(
                {
                    "module": res.module,
                    "target": res.target,
                    "findings": [
                        {
                            "title": f.title,
                            "detail": f.detail,
                            "severity": f.severity.value,
                        }
                        for f in res.findings
                    ],
                }
            )
        return payload


class Orchestrator:
    def __init__(self, ctx: Context, registry: Registry, use_ai: bool = True) -> None:
        self.ctx = ctx
        self.registry = registry
        self.use_ai = use_ai and ctx.settings.ai_enabled
        self._client = None

    def plan(self, target: Target, only: list[str] | None = None) -> tuple[list[str], str]:
        applicable = self.registry.applicable(target)
        if self.ctx.settings.passive_only:
            applicable = [m for m in applicable if not m.contacts_target]
        if only:
            wanted = set(only)
            applicable = [m for m in applicable if m.name in wanted]

        names = [m.name for m in applicable]
        if not names:
            return [], "No applicable modules for this target type."

        if self.use_ai:
            try:
                return self._ai_plan(target, applicable)
            except Exception as exc:
                return self._passive_first(applicable), f"(AI planner unavailable: {exc})"
        return self._passive_first(applicable), "Deterministic plan: all applicable modules, passive first."

    @staticmethod
    def _passive_first(applicable) -> list[str]:
        passive = [m.name for m in applicable if not m.contacts_target]
        active = [m.name for m in applicable if m.contacts_target]
        return passive + active

    def _ai_plan(self, target: Target, applicable) -> tuple[list[str], str]:
        catalog = [m.describe() for m in applicable]
        text = self._complete(
            prompts.PLANNER_SYSTEM, prompts.planner_user(str(target), catalog)
        )
        data = json.loads(_extract_json(text))
        valid = {m.name for m in applicable}
        plan = [n for n in data.get("plan", []) if n in valid]
        if not plan:
            plan = self._passive_first(applicable)
        return plan, data.get("reasoning", "")

    def investigate(
        self, target: Target, only: list[str] | None = None, depth: int = 1
    ) -> Investigation:
        plan, reasoning = self.plan(target, only=only)
        inv = Investigation(target=target, plan=plan, plan_reasoning=reasoning)
        inv.ai_used = self.use_ai

        self.ctx.seen.add(str(target))
        self._run_plan(target, plan, inv)

        if depth > 1:
            frontier = self._collect_new_targets(inv.results)
            for nt in frontier:
                if str(nt) in self.ctx.seen:
                    continue
                self.ctx.seen.add(str(nt))
                inv.expanded_targets.append(str(nt))
                sub_plan, _ = self.plan(nt, only=only)
                sub_plan = [
                    n for n in sub_plan
                    if not getattr(self.registry.get(n), "contacts_target", False)
                ]
                self._run_plan(nt, sub_plan, inv)

        return inv

    def _run_plan(self, target: Target, plan: list[str], inv: Investigation) -> None:
        for name in plan:
            module = self.registry.get(name)
            if module is None:
                continue
            try:
                result = module.run(target, self.ctx)
            except Exception as exc:
                result = ModuleResult.failure(name, target.value, f"module crashed: {exc}")
            self.ctx.record(result)
            inv.results.append(result)

    @staticmethod
    def _collect_new_targets(results: list[ModuleResult]) -> list[Target]:
        seen: set[str] = set()
        out: list[Target] = []
        for res in results:
            for nt in res.new_targets:
                if str(nt) not in seen:
                    seen.add(str(nt))
                    out.append(nt)
        return out

    def synthesize(self, inv: Investigation) -> str:
        payload = inv.findings_payload()
        entities = inv.entity_map()
        if self.use_ai and payload:
            try:
                from ..report.scorecard import score_exposure

                sc = score_exposure(inv)
                user = prompts.synth_user(str(inv.target), payload, entities)
                user += (
                    f"\n\n=== EXPOSURE SCORECARD ===\nScore {sc['score']}/100, grade "
                    f"{sc['grade']}. Factors: {'; '.join(sc['factors']) or 'none'}. "
                    "Open your briefing by stating this grade in one line, then justify it."
                )
                inv.summary = self._complete(prompts.SYNTH_SYSTEM, user)
                return inv.summary
            except Exception:
                pass
        inv.summary = _template_summary(inv, entities)
        return inv.summary

    def _complete(self, system: str, user: str) -> str:
        if self.ctx.settings.resolve_backend() == "cli":
            from . import claude_cli

            return claude_cli.complete(f"{system}\n\n{user}")
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self.ctx.settings.anthropic_api_key)
        resp = self._client.messages.create(
            model=self.ctx.settings.model,
            max_tokens=1500,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in resp.content if block.type == "text")


def _extract_json(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in AI response")
    return text[start : end + 1]


def _template_summary(inv: Investigation, entities: dict | None = None) -> str:
    findings = [
        (res.module, f)
        for res in inv.results
        if not res.skipped
        for f in res.findings
    ]
    findings.sort(key=lambda mf: _SEVERITY_ORDER.get(mf[1].severity, 3))
    lines = [f"Target: {inv.target.value}", ""]
    if not findings:
        lines.append("No findings were produced.")
        return "\n".join(lines)

    if entities:
        corroborated = {v: d for v, d in entities.items() if len(d["modules"]) > 1}
        if corroborated:
            lines.append("Corroborated (more than one source):")
            for value, d in sorted(corroborated.items(), key=lambda kv: -len(kv[1]["modules"])):
                lines.append(f"• {value} ({d['type']})")
            lines.append("")
        by_type: dict[str, list[str]] = {}
        for value, d in entities.items():
            by_type.setdefault(d["type"], []).append(value)
        lines.append(f"Footprint: {len(entities)} linked identities across "
                     f"{len(by_type)} types ({', '.join(sorted(by_type))}).")
        lines.append("")

    notable = [mf for mf in findings if mf[1].severity in (Severity.HIGH, Severity.MEDIUM)]
    if notable:
        lines.append("Notable exposure:")
        for module, f in notable[:12]:
            lines.append(f"• [{f.severity.value.upper()}] {f.title} — {f.detail}")
    else:
        lines.append("Nothing high-severity surfaced. See the findings panel for detail.")
    return "\n".join(lines)

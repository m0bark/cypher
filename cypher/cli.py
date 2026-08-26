"""Cypher command-line interface.

Commands:
  cypher scan TARGET     Plan + run modules against a target, write a report.
  cypher modules         List available modules and their status.
  cypher version         Print version.

Rich is used for output when available, with a plain-text fallback.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .ai.orchestrator import Orchestrator
from .core.context import Context
from .core.registry import discover
from .core.scope import AUTHORIZATION_NOTICE, assess, looks_personal
from .core.settings import Settings
from .core.target import TargetType, parse_target
from .report.renderer import write_report


def _echo(msg: str = "") -> None:
    print(msg)


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        _echo(f"{prompt} [auto-yes]")
        return True
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def cmd_modules(args: argparse.Namespace) -> int:
    registry = discover()
    _echo(f"Cypher modules ({len(registry.modules)} available):\n")
    for name in registry.names():
        mod = registry.modules[name]
        applies = ", ".join(t.value for t in mod.applies_to)
        flags = []
        if mod.contacts_target:
            flags.append("active")
        if mod.requires_key:
            flags.append(f"needs {mod.requires_key}")
        tag = f"  [{', '.join(flags)}]" if flags else ""
        _echo(f"  {name:<20} <{applies}>{tag}")
        _echo(f"      {mod.description}")
    if registry.load_errors:
        _echo("\nLoad errors (usually missing optional dependencies):")
        for mod, err in registry.load_errors.items():
            _echo(f"  {mod}: {err}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = Settings.load()
    if args.passive:
        settings.passive_only = True
    if args.no_ai:
        settings.anthropic_api_key = settings.anthropic_api_key  # unchanged; use_ai=False below
    if args.out:
        settings.output_dir = args.out

    target = parse_target(args.target)
    if target.type is TargetType.UNKNOWN:
        _echo(f"error: could not classify target '{args.target}'.", )
        return 2

    # -- authorization gate ------------------------------------------------
    _echo("=" * 68)
    _echo(AUTHORIZATION_NOTICE)
    _echo("=" * 68)
    decision = assess(target)
    if not decision.allowed:
        _echo(f"Refusing: {decision.reason}")
        return 2
    _echo(f"Target: {target}  —  {decision.reason}\n")
    if not _confirm("Do you have authorization to assess this target?", args.yes):
        _echo("Aborted: authorization not confirmed.")
        return 1
    if decision.requires_confirmation and looks_personal(target):
        if not _confirm(
            "This looks like a private individual. Confirm this is you or a consented/"
            "authorized subject", args.yes
        ):
            _echo("Aborted: personal-target confirmation declined.")
            return 1

    ctx = Context.create(settings)
    registry = discover()
    orch = Orchestrator(ctx, registry, use_ai=not args.no_ai)

    only = [m.strip() for m in args.modules.split(",")] if args.modules else None
    mode = "AI-orchestrated" if orch.use_ai else "deterministic"
    _echo(f"Running ({mode}, passive_only={settings.passive_only}, depth={args.depth})...\n")

    inv = orch.investigate(target, only=only, depth=args.depth)
    if inv.plan_reasoning:
        _echo(f"Plan: {', '.join(inv.plan)}\n  rationale: {inv.plan_reasoning}\n")
    for res in inv.results:
        status = "skip" if res.skipped else ("ok" if res.ok else "ERR")
        n = len([f for f in res.findings if not res.skipped])
        _echo(f"  [{status:>4}] {res.module:<18} {res.target}"
              + (f"  ({n} findings)" if res.ok and not res.skipped else "")
              + (f"  {res.error}" if not res.ok else ""))

    _echo("\nSynthesizing summary...")
    orch.synthesize(inv)
    paths = write_report(inv, settings.output_dir)
    ctx.close()

    _echo("\n" + "-" * 68)
    _echo(inv.summary)
    _echo("-" * 68)
    _echo(f"\nReport written:\n  {paths['markdown']}\n  {paths['json']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cypher", description="AI-orchestrated OSINT framework.")
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("scan", help="Investigate a target.")
    ps.add_argument("target", help="domain, IP, email, URL, or username")
    ps.add_argument("--modules", help="comma-separated subset of module names to run")
    ps.add_argument("--depth", type=int, default=1, help="expansion depth (default 1)")
    ps.add_argument("--passive", action="store_true", help="skip modules that contact the target")
    ps.add_argument("--no-ai", action="store_true", help="force deterministic planning/summary")
    ps.add_argument("--yes", action="store_true", help="assume yes to authorization prompts")
    ps.add_argument("--out", help="output directory (default: reports)")
    ps.set_defaults(func=cmd_scan)

    pm = sub.add_parser("modules", help="List available modules.")
    pm.set_defaults(func=cmd_modules)

    pw = sub.add_parser("web", help="Launch the browser UI.")
    pw.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    pw.add_argument("--port", type=int, default=8765, help="port (default 8765)")
    pw.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    pw.set_defaults(func=cmd_web)

    pv = sub.add_parser("version", help="Print version.")
    pv.set_defaults(func=lambda a: (_echo(f"cypher {__version__}"), 0)[1])

    return p


def cmd_web(args: argparse.Namespace) -> int:
    from .web.server import serve

    serve(host=args.host, port=args.port, open_browser=not args.no_open)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

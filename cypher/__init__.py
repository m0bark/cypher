"""Cypher — an AI-orchestrated OSINT framework.

A pluggable engine where open-source-intelligence modules self-register, an
orchestrator (optionally driven by Claude) decides which modules to run against
a target, and the collected findings are synthesized into a report.

Intended for authorized use only: assets you own or are permitted to assess,
and defensive self-checks. See cypher.core.scope and the README.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]

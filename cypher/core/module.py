"""Module contract: the base class every OSINT module implements.

Modules keep their heavy/optional imports inside run() so the registry can
discover them even when a given third-party dependency is not installed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from .target import Target, TargetType

if TYPE_CHECKING:
    from .context import Context


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    """A single observation produced by a module."""

    title: str
    detail: str
    severity: Severity = Severity.INFO
    data: dict = field(default_factory=dict)


@dataclass
class ModuleResult:
    """The outcome of running one module against one target."""

    module: str
    target: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    new_targets: list[Target] = field(default_factory=list)
    error: str | None = None
    skipped: bool = False
    raw: Any = None

    @classmethod
    def failure(cls, module: str, target: str, error: str) -> "ModuleResult":
        return cls(module=module, target=target, ok=False, error=error)

    @classmethod
    def skip(cls, module: str, target: str, reason: str) -> "ModuleResult":
        return cls(
            module=module,
            target=target,
            ok=True,
            skipped=True,
            findings=[Finding("Skipped", reason, Severity.INFO)],
        )


class BaseModule(ABC):
    """Base class for all modules.

    Subclasses set the class attributes and implement run(). ``contacts_target``
    marks modules that touch the target's own infrastructure directly; those are
    skipped when the run is configured passive-only.
    """

    name: str = "base"
    description: str = ""
    applies_to: tuple[TargetType, ...] = ()
    requires_key: str | None = None
    contacts_target: bool = False

    def applicable(self, target: Target) -> bool:
        return target.type in self.applies_to

    @abstractmethod
    def run(self, target: Target, ctx: "Context") -> ModuleResult:
        ...

    def describe(self) -> dict:
        """Machine-readable summary handed to the AI planner."""
        return {
            "name": self.name,
            "description": self.description,
            "applies_to": [t.value for t in self.applies_to],
            "requires_key": self.requires_key,
            "contacts_target": self.contacts_target,
        }

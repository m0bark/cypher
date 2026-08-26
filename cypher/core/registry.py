"""Module discovery. Imports every submodule of Cypher.modules and collects
BaseModule subclasses. Import failures for individual modules are recorded, not
fatal, so an optional-dependency gap never breaks the whole registry.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field

from .module import BaseModule
from .target import Target


@dataclass
class Registry:
    modules: dict[str, BaseModule] = field(default_factory=dict)
    load_errors: dict[str, str] = field(default_factory=dict)

    def applicable(self, target: Target) -> list[BaseModule]:
        return [m for m in self.modules.values() if m.applicable(target)]

    def get(self, name: str) -> BaseModule | None:
        return self.modules.get(name)

    def names(self) -> list[str]:
        return sorted(self.modules)


def _all_subclasses(cls: type) -> set[type]:
    subs = set(cls.__subclasses__())
    for sub in list(subs):
        subs |= _all_subclasses(sub)
    return subs


def discover() -> Registry:
    """Discover all modules under Cypher.modules."""
    from .. import modules as modules_pkg

    registry = Registry()
    for info in pkgutil.iter_modules(modules_pkg.__path__):
        full = f"cypher.modules.{info.name}"
        try:
            importlib.import_module(full)
        except Exception as exc:  # optional dep missing, etc.
            registry.load_errors[info.name] = f"{type(exc).__name__}: {exc}"

    for cls in _all_subclasses(BaseModule):
        try:
            instance = cls()
        except Exception as exc:
            registry.load_errors[cls.__name__] = f"{type(exc).__name__}: {exc}"
            continue
        if instance.name and instance.name != "base":
            registry.modules[instance.name] = instance
    return registry

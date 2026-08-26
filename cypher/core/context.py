"""Investigation context shared across modules during a run."""

from __future__ import annotations

from dataclasses import dataclass, field

from .http import HttpClient
from .module import ModuleResult
from .settings import Settings


@dataclass
class Context:
    settings: Settings
    http: HttpClient
    results: list[ModuleResult] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)

    @classmethod
    def create(cls, settings: Settings | None = None) -> "Context":
        settings = settings or Settings.load()
        return cls(settings=settings, http=HttpClient(settings))

    def record(self, result: ModuleResult) -> None:
        self.results.append(result)

    def key(self, name: str) -> str | None:
        return self.settings.env_key(name)

    def close(self) -> None:
        self.http.close()

"""Runtime settings, loaded from environment (and an optional .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_USER_AGENT = "cypher-osint/0.1 (+authorized-recon)"
DEFAULT_TIMEOUT = 15.0
DEFAULT_RATE_LIMIT = 1.0
DEFAULT_OUTPUT_DIR = "reports"


@dataclass
class Settings:
    """Configuration for an investigation run.

    Secrets come only from the environment; nothing is hardcoded. Every
    optional API key gates a single module and the tool works without it.
    """

    anthropic_api_key: str | None = None
    model: str = DEFAULT_MODEL
    hibp_api_key: str | None = None
    ipinfo_token: str | None = None
    github_token: str | None = None
    shodan_api_key: str | None = None
    user_agent: str = DEFAULT_USER_AGENT
    timeout: float = DEFAULT_TIMEOUT
    rate_limit_per_host: float = DEFAULT_RATE_LIMIT
    passive_only: bool = False
    output_dir: str = DEFAULT_OUTPUT_DIR
    obsidian_vault: str | None = None
    llm_backend: str = "auto"  # auto | api | cli | off

    def resolve_backend(self) -> str:
        """Which LLM backend to actually use: 'api' (paid key), 'cli' (Claude
        Code / subscription), or 'none'."""
        import shutil

        has_cli = shutil.which("claude") is not None
        if self.llm_backend == "off":
            return "none"
        if self.llm_backend == "cli":
            return "cli" if has_cli else "none"
        if self.llm_backend == "api":
            return "api" if self.anthropic_api_key else "none"
        # auto: prefer a paid API key, else fall back to the CLI subscription
        if self.anthropic_api_key:
            return "api"
        return "cli" if has_cli else "none"

    @property
    def ai_enabled(self) -> bool:
        return self.resolve_backend() != "none"

    @classmethod
    def load(cls) -> "Settings":
        _load_dotenv()

        def _float(name: str, default: float) -> float:
            raw = os.environ.get(name)
            if not raw:
                return default
            try:
                return float(raw)
            except ValueError:
                return default

        return cls(
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
            model=os.environ.get("CYPHER_MODEL", DEFAULT_MODEL),
            hibp_api_key=os.environ.get("HIBP_API_KEY"),
            ipinfo_token=os.environ.get("IPINFO_TOKEN"),
            github_token=os.environ.get("GITHUB_TOKEN"),
            shodan_api_key=os.environ.get("SHODAN_API_KEY"),
            user_agent=os.environ.get("CYPHER_USER_AGENT", DEFAULT_USER_AGENT),
            timeout=_float("CYPHER_TIMEOUT", DEFAULT_TIMEOUT),
            rate_limit_per_host=_float("CYPHER_RATE_LIMIT", DEFAULT_RATE_LIMIT),
            passive_only=os.environ.get("CYPHER_PASSIVE_ONLY", "").lower()
            in {"1", "true", "yes"},
            output_dir=os.environ.get("CYPHER_OUTPUT_DIR", DEFAULT_OUTPUT_DIR),
            obsidian_vault=os.environ.get("CYPHER_VAULT"),
            llm_backend=os.environ.get("CYPHER_LLM", "auto").lower(),
        )

    def env_key(self, name: str) -> str | None:
        """Look up an arbitrary env var (used by modules that require a key)."""
        mapping = {
            "HIBP_API_KEY": self.hibp_api_key,
            "IPINFO_TOKEN": self.ipinfo_token,
            "GITHUB_TOKEN": self.github_token,
            "SHODAN_API_KEY": self.shodan_api_key,
            "ANTHROPIC_API_KEY": self.anthropic_api_key,
        }
        return mapping.get(name) or os.environ.get(name)


def _load_dotenv() -> None:
    """Best-effort .env loading; a hard dependency is not required."""
    try:
        from dotenv import load_dotenv  # type: ignore
    except ImportError:
        return
    load_dotenv()

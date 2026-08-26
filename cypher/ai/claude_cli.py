"""LLM backend that shells out to the `claude` CLI (Claude Code).

This runs on the user's Claude subscription instead of the paid Anthropic API —
no API credits consumed. Requires the `claude` CLI installed and authenticated
on the machine running Cypher.
"""

from __future__ import annotations

import shutil
import subprocess

CLI_TIMEOUT = 180


def cli_available() -> bool:
    return shutil.which("claude") is not None


def complete(prompt: str, timeout: int = CLI_TIMEOUT) -> str:
    """Send a one-shot prompt to `claude -p` and return the text reply."""
    exe = shutil.which("claude")
    if not exe:
        raise RuntimeError("claude CLI not found on PATH")
    try:
        proc = subprocess.run(
            [exe, "-p", prompt],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"claude CLI timed out after {timeout}s") from exc

    out = (proc.stdout or "").strip()
    if proc.returncode != 0 and not out:
        err = (proc.stderr or "").strip()[:300]
        raise RuntimeError(err or f"claude CLI exited {proc.returncode}")
    return out

"""Footprint diff: compare this scan of a target against the last one.

Persists a small snapshot of discovered entities per target, so a re-scan can
report what is new and what disappeared since last time.
"""

from __future__ import annotations

import json
import os
import re


def _slug(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", target)[:120] or "target"


def _entities(inv) -> list[str]:
    ents: set[str] = set()
    for res in inv.results:
        if res.skipped:
            continue
        for nt in res.new_targets:
            if nt.value != inv.target.value:
                ents.add(f"{nt.type.value}:{nt.value}")
    return sorted(ents)


def diff_and_save(inv, out_dir: str) -> dict:
    snap_dir = os.path.join(out_dir, "snapshots")
    os.makedirs(snap_dir, exist_ok=True)
    path = os.path.join(snap_dir, _slug(inv.target.value) + ".json")

    current = _entities(inv)
    previous: list[str] = []
    first = True
    if os.path.exists(path):
        first = False
        try:
            with open(path, encoding="utf-8") as fh:
                previous = json.load(fh).get("entities", [])
        except Exception:
            previous = []

    prev_set, cur_set = set(previous), set(current)
    added = sorted(cur_set - prev_set)
    removed = sorted(prev_set - cur_set)

    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"target": inv.target.value, "entities": current}, fh, indent=2)
    except Exception:
        pass

    return {"first_scan": first, "added": added, "removed": removed,
            "total": len(current)}

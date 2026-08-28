"""Build a rough chronology from a scan's dated findings.

Scans every finding's text for dates (YYYY-MM-DD or bare year) and assembles a
sorted, de-duplicated timeline of what surfaced when. Best-effort — only as good
as the dates the modules actually return (registration dates, breach dates, etc.).
"""

from __future__ import annotations

import re

_DATE = re.compile(r"\b(\d{4})[-/](\d{1,2})[-/](\d{1,2})\b|\b(19|20)(\d{2})\b")


def build_timeline(inv) -> list[dict]:
    events: list[dict] = []
    for res in inv.results:
        if res.skipped or not res.ok:
            continue
        for f in res.findings:
            for m in _DATE.finditer(f.detail):
                if m.group(1):
                    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
                    if not (1970 <= y <= 2100 and 1 <= mo <= 12 and 1 <= d <= 31):
                        continue
                    date, sort = f"{y}-{mo:02d}-{d:02d}", f"{y:04d}{mo:02d}{d:02d}"
                else:
                    y = int(m.group(4) + m.group(5))
                    if not (1970 <= y <= 2100):
                        continue
                    date, sort = str(y), f"{y:04d}0000"
                events.append({"sort": sort, "date": date, "source": res.module,
                               "what": f.title})

    seen: set = set()
    out: list[dict] = []
    for e in sorted(events, key=lambda x: x["sort"]):
        key = (e["date"], e["source"], e["what"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"date": e["date"], "source": e["source"], "what": e["what"]})
    return out[:40]

"""Exposure scorecard — grade how exposed/findable an identity is from a scan.

Deterministic scoring over the investigation's findings: linked accounts, breach
presence, and exposed email/phone. Higher score = more exposed. Meant as a
self-check signal — 'how much does my footprint give away, and what do I fix
first' — not a judgement of anyone else.
"""

from __future__ import annotations

BREACH_MODULES = {"breach_check", "holehe", "h8mail", "mosint"}


def score_exposure(inv) -> dict:
    accounts: set[str] = set()
    breach = False
    has_email = inv.target.type.value == "email"
    has_phone = inv.target.type.value == "phone"

    for res in inv.results:
        if res.skipped or not res.ok:
            continue
        for nt in res.new_targets:
            t = nt.type.value
            if t in ("url", "username", "email"):
                accounts.add(nt.value.lower())
            if t == "email":
                has_email = True
            if t == "phone":
                has_phone = True
        if res.module in BREACH_MODULES:
            for f in res.findings:
                text = (f.title + " " + f.detail).lower()
                if any(w in text for w in ("hit", "breach", "leak", "found", "[+]", "pwned")):
                    breach = True

    score = 0
    factors: list[str] = []
    recs: list[str] = []

    n = len(accounts)
    if n:
        pts = min(45, n * 6)
        score += pts
        factors.append(f"{n} linked accounts/profiles (+{pts})")
        if n >= 4:
            recs.append("One identity spans many platforms — compartmentalize: don't reuse a "
                        "single handle everywhere; it's the join key that links it all.")
    if breach:
        score += 30
        factors.append("Appears in breach / leak data (+30)")
        recs.append("Your address shows up in breaches — rotate those passwords and turn on 2FA.")
    if has_email:
        score += 8
        factors.append("Email exposed (+8)")
    if has_phone:
        score += 8
        factors.append("Phone number exposed (+8)")

    score = min(100, score)
    grade = ("A" if score < 20 else "B" if score < 40 else "C"
             if score < 60 else "D" if score < 80 else "F")
    if not recs:
        recs.append("Low exposure — keep it that way; re-audit periodically.")

    return {"score": score, "grade": grade, "factors": factors, "recommendations": recs}

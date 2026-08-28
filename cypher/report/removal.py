"""Opt-out / account-removal links for what a scan surfaced.

Turns discovered accounts and the usual data-broker exposure into a concrete
'here's where to delete / opt out' action list — the defensive payoff of a
self-check: not just where you're exposed, but how to reduce it.
"""

from __future__ import annotations

PLATFORM_REMOVAL = {
    "github.com": "https://github.com/settings/admin  (Delete account)",
    "gitlab.com": "https://gitlab.com/-/profile/account  (Delete account)",
    "instagram.com": "https://www.instagram.com/accounts/remove/request/permanent/",
    "t.me": "https://my.telegram.org/deactivate",
    "telegram": "https://my.telegram.org/deactivate",
    "youtube.com": "https://myaccount.google.com/deleteservices",
    "chess.com": "https://www.chess.com/settings  (Close account)",
    "reddit.com": "https://www.reddit.com/settings/  (Deactivate account)",
    "tiktok.com": "https://www.tiktok.com/setting  (Deactivate)",
    "pinterest.com": "https://www.pinterest.com/settings/  (Close account)",
    "medium.com": "https://medium.com/me/settings  (Delete account)",
    "steamcommunity.com": "https://help.steampowered.com  (Delete account request)",
    "twitch.tv": "https://www.twitch.tv/user/deactivate",
    "soundcloud.com": "https://soundcloud.com/settings/account  (Delete)",
    "vimeo.com": "https://vimeo.com/settings/account  (Delete)",
    "keybase.io": "https://keybase.io/account/delete_me",
    "replit.com": "https://replit.com/account  (Delete account)",
}

DATA_BROKERS = [
    ("Whitepages", "https://www.whitepages.com/suppression-requests"),
    ("Spokeo", "https://www.spokeo.com/optout"),
    ("BeenVerified", "https://www.beenverified.com/app/optout/search"),
    ("Intelius", "https://www.intelius.com/opt-out/"),
    ("TruePeopleSearch", "https://www.truepeoplesearch.com/removal"),
    ("FastPeopleSearch", "https://www.fastpeoplesearch.com/removal"),
    ("Radaris", "https://radaris.com/control/privacy"),
    ("MyLife", "https://www.mylife.com/ccpa/index.pubview"),
]


def removal_links(inv) -> dict:
    plats: set[str] = set()
    for res in inv.results:
        if res.skipped:
            continue
        blobs = [nt.value.lower() for nt in res.new_targets]
        for f in res.findings:
            blobs.append((f.data or {}).get("platform", "").lower())
            blobs.append(f.detail.lower())
        joined = " ".join(blobs)
        for key in PLATFORM_REMOVAL:
            if key in joined:
                plats.add(key)

    accounts = [{"platform": k, "url": PLATFORM_REMOVAL[k]} for k in sorted(plats)]
    brokers = [{"name": n, "url": u} for n, u in DATA_BROKERS]
    return {"accounts": accounts, "brokers": brokers}

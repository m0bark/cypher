"""Google-dork generator: build ready-to-run search queries for a target.

Turns a username, email, domain, phone, org or free-text NAME into a set of
search-engine dorks (exact-match, per-platform, documents, contact info, leaks).
It does not scrape results — it hands you clickable queries, so it works for any
target type and needs no keys. This is the 'more than username lookup' surface.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType

GOOGLE = "https://www.google.com/search?q="
SOCIAL = ["linkedin.com", "twitter.com", "instagram.com", "facebook.com", "github.com",
          "tiktok.com", "reddit.com", "youtube.com"]


def _dorks_for(target: Target) -> list[tuple[str, str]]:
    v = target.value
    q = f'"{v}"'
    dorks: list[tuple[str, str]] = []

    if target.type is TargetType.DOMAIN:
        dorks += [
            ("All indexed pages", f"site:{v}"),
            ("Subdomains", f"site:*.{v} -www"),
            ("Documents", f"site:{v} (filetype:pdf OR filetype:xlsx OR filetype:docx)"),
            ("Exposed secrets", f"site:{v} (intext:password OR intext:api_key OR intext:secret)"),
            ("Login / admin pages", f"site:{v} (inurl:login OR inurl:admin OR inurl:dashboard)"),
            ("Mentions elsewhere", f'"{v}" -site:{v}'),
        ]
        return dorks

    # username / email / name / org / phone
    dorks.append(("Exact match", q))
    for site in SOCIAL:
        dorks.append((f"On {site}", f"{q} site:{site}"))
    dorks += [
        ("Contact details", f"{q} (email OR mail OR phone OR contact OR whatsapp)"),
        ("In documents", f"{q} (filetype:pdf OR filetype:xlsx OR filetype:csv)"),
        ("Pastes / leaks", f"{q} (site:pastebin.com OR site:ghostbin.com OR site:throwbin.io)"),
        ("Forums / boards", f"{q} (site:reddit.com OR inurl:forum OR inurl:profile)"),
    ]
    if target.type is TargetType.EMAIL:
        dorks.append(("Breach mentions", f"{q} (breach OR leak OR dump OR combolist)"))
    return dorks


class GoogleDorks(BaseModule):
    name = "google_dorks"
    description = (
        "Generate ready-to-run Google search dorks for a target (username, email, "
        "domain, phone, org, or a free-text name): exact match, per-platform, "
        "documents, contact info, pastes/leaks. Produces clickable queries; no scraping."
    )
    applies_to = (TargetType.USERNAME, TargetType.EMAIL, TargetType.DOMAIN,
                  TargetType.ORG, TargetType.NAME, TargetType.PHONE)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        findings = []
        for label, query in _dorks_for(target):
            url = GOOGLE + quote_plus(query)
            findings.append(Finding(label, url, Severity.INFO, {"query": query, "url": url}))
        return ModuleResult(
            self.name, target.value, ok=True, findings=findings,
            raw={"count": len(findings)},
        )

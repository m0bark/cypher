"""Reverse image search — turn an image URL into reverse-search queries.

Given an image URL, produce clickable links to the public reverse-image engines
(Google Lens, Yandex, TinEye, Bing) that find where that image appears online —
reuse, impersonation, catfish checks. It generates links to public engines; it
does NOT scrape results and does NOT do facial recognition (identifying a person
from their face). It finds where an image appears, not who a face belongs to.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType

ENGINES = [
    ("Google Lens", "https://lens.google.com/uploadbyurl?url={}"),
    ("Google Images", "https://www.google.com/searchbyimage?image_url={}"),
    ("Yandex Images", "https://yandex.com/images/search?rpt=imageview&url={}"),
    ("Bing Visual", "https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{}"),
    ("TinEye", "https://tineye.com/search?url={}"),
    ("Karma Decay (Reddit)", "http://karmadecay.com/search?q={}"),
]


class ReverseImage(BaseModule):
    name = "reverse_image"
    description = (
        "Reverse image search for an image URL: generates links to Google Lens, "
        "Google Images, Yandex, Bing, TinEye and Karma Decay to find where the image "
        "is reused online (impersonation / catfish / same-pfp). Links only; no "
        "facial recognition."
    )
    applies_to = (TargetType.IMAGE,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        enc = quote_plus(target.value)
        findings = [
            Finding(name, url.format(enc), Severity.INFO, {"url": url.format(enc)})
            for name, url in ENGINES
        ]
        findings.append(
            Finding("Note", "These find where this image appears, not whose face it is.",
                    Severity.INFO)
        )
        return ModuleResult(self.name, target.value, ok=True, findings=findings)

"""Phone-number metadata via the offline `phonenumbers` library.

Reports only format-derived metadata: validity, country/region, carrier, line
type and timezone. It performs NO owner/reverse lookup — that would be people
tracing, which Cypher does not do. Best used to sanity-check your own number or
a number in an authorized investigation's scope.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


class PhoneInfo(BaseModule):
    name = "phone_info"
    description = (
        "Offline metadata for a phone number: validity, country/region, carrier, "
        "line type (mobile/fixed/VoIP) and timezone. No owner or reverse lookup."
    )
    applies_to = (TargetType.PHONE,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone
            from phonenumbers import NumberParseException
        except ImportError:
            return ModuleResult.failure(
                self.name, target.value, "phonenumbers not installed (pip install phonenumbers)"
            )

        raw = target.value if target.value.startswith("+") else "+" + target.value
        try:
            num = phonenumbers.parse(raw, None)
        except NumberParseException as exc:
            return ModuleResult.failure(self.name, target.value, f"could not parse: {exc}")

        valid = phonenumbers.is_valid_number(num)
        type_names = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "fixed line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed or mobile",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll-free",
        }
        line_type = type_names.get(phonenumbers.number_type(num), "unknown")

        findings = [
            Finding("Valid number", "yes" if valid else "no — fails format checks for its region",
                    Severity.INFO if valid else Severity.LOW),
            Finding("Country code", f"+{num.country_code}", Severity.INFO),
            Finding("E.164", phonenumbers.format_number(
                num, phonenumbers.PhoneNumberFormat.E164), Severity.INFO),
        ]
        region = geocoder.description_for_number(num, "en")
        if region:
            findings.append(Finding("Region", region, Severity.INFO))
        car = carrier.name_for_number(num, "en")
        if car:
            findings.append(Finding("Carrier", car, Severity.INFO))
        findings.append(Finding("Line type", line_type, Severity.INFO))
        tzs = timezone.time_zones_for_number(num)
        if tzs:
            findings.append(Finding("Timezone(s)", ", ".join(tzs), Severity.INFO))

        return ModuleResult(self.name, target.value, ok=True, findings=findings)

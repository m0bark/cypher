"""Target detection tests (no network, stdlib only)."""

from cypher.core.target import TargetType, detect_type, parse_target


def test_detects_domain():
    assert detect_type("example.com") is TargetType.DOMAIN
    assert parse_target("Example.COM").value == "example.com"


def test_detects_ipv4_and_ipv6():
    assert detect_type("8.8.8.8") is TargetType.IP
    assert detect_type("2001:4860:4860::8888") is TargetType.IP


def test_detects_email_and_extracts_domain():
    t = parse_target("Alice@Example.com")
    assert t.type is TargetType.EMAIL
    assert t.value == "alice@example.com"
    assert t.parent == "example.com"


def test_detects_url_and_extracts_host():
    t = parse_target("https://sub.example.com/path?q=1")
    assert t.type is TargetType.URL
    assert t.parent == "sub.example.com"


def test_detects_username():
    t = parse_target("@some_user")
    assert t.type is TargetType.USERNAME
    assert t.value == "some_user"


def test_empty_is_unknown():
    assert detect_type("   ") is TargetType.UNKNOWN


def test_domain_precedes_username_when_dotted():
    # A dotted token is a domain, not a username.
    assert detect_type("foo.bar") is TargetType.DOMAIN


def test_detects_phone_with_plus_and_separators():
    assert detect_type("+965 9988 7766") is TargetType.PHONE
    t = parse_target("+965 9988 7766")
    assert t.type is TargetType.PHONE
    assert t.value == "+96599887766"


def test_detects_bare_digit_phone():
    assert detect_type("6502530000") is TargetType.PHONE


def test_short_digits_not_phone():
    # Too short to be a phone number.
    assert detect_type("12345") is not TargetType.PHONE

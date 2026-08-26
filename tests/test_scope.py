"""Authorization / scope-guard tests."""

from cypher.core.scope import assess, looks_personal
from cypher.core.target import parse_target


def test_infra_domain_no_extra_confirmation():
    d = assess(parse_target("example.com"))
    assert d.allowed is True
    assert d.requires_confirmation is False


def test_consumer_email_flagged_personal():
    t = parse_target("someone@gmail.com")
    assert looks_personal(t) is True
    assert assess(t).requires_confirmation is True


def test_corporate_email_not_flagged_personal():
    t = parse_target("admin@example.com")
    assert looks_personal(t) is False


def test_username_flagged_personal():
    assert looks_personal(parse_target("@handle")) is True


def test_unknown_target_disallowed():
    d = assess(parse_target("!!!"))
    assert d.allowed is False

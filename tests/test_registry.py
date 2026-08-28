"""Registry discovery tests. Runs without third-party deps because modules keep
their heavy imports inside run()."""

from cypher.core.registry import discover
from cypher.core.target import TargetType, parse_target

EXPECTED_BUILTINS = {
    "dns_records",
    "rdap_whois",
    "crtsh_subdomains",
    "http_fingerprint",
    "ip_info",
    "wayback",
    "github_recon",
    "email_recon",
    "breach_check",
}

EXPECTED_EXTERNAL = {"theharvester", "amass", "subfinder", "whois", "nmap", "holehe", "sherlock"}


def test_discovers_all_builtin_modules():
    reg = discover()
    assert EXPECTED_BUILTINS <= set(reg.names())


def test_discovers_external_tool_adapters():
    reg = discover()
    assert EXPECTED_EXTERNAL <= set(reg.names())


def test_no_load_errors():
    reg = discover()
    assert reg.load_errors == {}, reg.load_errors


def test_base_class_not_registered():
    reg = discover()
    assert "base" not in reg.names()


def test_applicable_filters_by_type():
    reg = discover()
    domain = parse_target("example.com")
    names = {m.name for m in reg.applicable(domain)}
    assert "dns_records" in names
    assert "github_recon" not in names


def test_nmap_marked_active():
    reg = discover()
    assert reg.get("nmap").contacts_target is True
    assert reg.get("crtsh_subdomains").contacts_target is False

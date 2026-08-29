from cypher.ai.orchestrator import Investigation
from cypher.core.module import Finding, ModuleResult, Severity
from cypher.core.target import TargetType, parse_target
from cypher.report.footprint import diff_and_save
from cypher.report.scorecard import score_exposure
from cypher.report.timeline import build_timeline


def _investigation():
    target = parse_target("somehandle")
    gh = parse_target("github.com/somehandle")
    result = ModuleResult(
        module="github_recon",
        target="somehandle",
        ok=True,
        findings=[
            Finding("Account", "github.com/somehandle", Severity.LOW,
                    {"platform": "github.com", "url": "https://github.com/somehandle"}),
            Finding("Created", "joined 2015-06-01", Severity.INFO),
        ],
        new_targets=[gh],
    )
    return Investigation(target=target, plan=["github_recon"], plan_reasoning="",
                         results=[result])


def test_scorecard_returns_grade_and_score():
    sc = score_exposure(_investigation())
    assert 0 <= sc["score"] <= 100
    assert sc["grade"] in {"A", "B", "C", "D", "F"}


def test_timeline_extracts_dates():
    tl = build_timeline(_investigation())
    assert any(e["date"] == "2015-06-01" for e in tl)


def test_footprint_first_scan(tmp_path):
    fp = diff_and_save(_investigation(), str(tmp_path))
    assert fp["first_scan"] is True
    fp2 = diff_and_save(_investigation(), str(tmp_path))
    assert fp2["first_scan"] is False
    assert fp2["added"] == [] and fp2["removed"] == []


def test_crypto_target_detection():
    for addr in ("0x00000000219ab540356cBB839Cbe05303d7705Fa",
                 "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"):
        assert parse_target(addr).type is TargetType.CRYPTO

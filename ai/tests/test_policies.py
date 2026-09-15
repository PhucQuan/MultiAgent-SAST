"""Test tầng policy — eligibility gate và lưới an toàn chống suppress sai."""

from collections import Counter

import pytest

from ai import config as config_module
from ai.policies.eligibility import (
    check_eligibility,
    priority_score,
    select_for_llm,
)
from ai.policies.suppression import (
    apply_suppression_policy,
    build_suppression_record,
)
from ai.schemas.state import GraphState, ValidatorAssessment
from ai.schemas.verdict import TriageState
from conftest import make_finding, verdict


@pytest.fixture(autouse=True)
def _reset_settings():
    config_module.reset_settings()
    yield
    config_module.reset_settings()


# --- eligibility ---------------------------------------------------------
def test_low_severity_never_reaches_llm():
    finding = make_finding(severity="low")
    decision = check_eligibility(finding)
    assert decision.eligible is False
    assert "severity_below" in decision.reason


def test_disabled_mode_blocks_everything(monkeypatch):
    monkeypatch.setenv("AEGIS_AI_MODE", "disabled")
    config_module.reset_settings()
    decision = check_eligibility(make_finding(severity="critical"))
    assert decision.eligible is False
    assert decision.reason == "ai_mode_disabled"


def test_heuristic_mode_blocks_llm_but_is_not_disabled(monkeypatch):
    """`heuristic` vẫn chạy filter tất định nhưng không tốn một token nào."""
    monkeypatch.setenv("AEGIS_AI_MODE", "heuristic")
    config_module.reset_settings()
    assert config_module.get_settings().llm_enabled is False
    decision = check_eligibility(make_finding(severity="critical"))
    assert decision.eligible is False


def test_static_proof_of_safety_skips_llm():
    """Heuristic đã chứng minh an toàn thì gọi LLM là lãng phí thuần."""
    decision = check_eligibility(make_finding(), static_verdict_is_fp=True)
    assert decision.eligible is False
    assert decision.reason == "static_heuristic_proved_safe"


def test_thin_evidence_is_rejected():
    decision = check_eligibility(make_finding(evidence_quality=0.1))
    assert decision.eligible is False
    assert decision.reason == "insufficient_evidence_for_llm"


def test_per_file_budget_is_enforced():
    finding = make_finding()
    counter = Counter({finding.evidence.sink.file: 3})
    decision = check_eligibility(finding, per_file_counter=counter)
    assert decision.eligible is False
    assert decision.reason == "file_llm_budget_exhausted"


def test_scan_budget_is_enforced(monkeypatch):
    monkeypatch.setenv("AEGIS_MAX_LLM_FINDINGS_PER_SCAN", "2")
    config_module.reset_settings()
    decision = check_eligibility(make_finding(), scan_budget_used=2)
    assert decision.eligible is False
    assert decision.reason == "scan_llm_budget_exhausted"


def test_priority_prefers_critical_over_medium():
    critical = make_finding(severity="critical", finding_id="c")
    medium = make_finding(severity="medium", finding_id="m")
    assert priority_score(critical) > priority_score(medium)


def test_priority_is_deterministic():
    """Hai lần tính trên cùng một finding phải ra cùng một số.

    Điều kiện cần để benchmark tái lập: nếu thứ tự ưu tiên đổi giữa các lần
    chạy thì tập finding được AI xem cũng đổi, và số liệu không so sánh được.
    """
    finding = make_finding()
    assert priority_score(finding) == priority_score(finding)


def test_select_for_llm_respects_budget_in_priority_order(monkeypatch):
    monkeypatch.setenv("AEGIS_MAX_LLM_FINDINGS_PER_SCAN", "2")
    monkeypatch.setenv("AEGIS_MAX_LLM_FINDINGS_PER_FILE", "5")
    config_module.reset_settings()

    findings = [
        make_finding(severity="medium", finding_id="m1"),
        make_finding(severity="critical", finding_id="c1"),
        make_finding(severity="high", finding_id="h1"),
    ]
    selected, decisions = select_for_llm(findings)

    assert [f.finding_id for f in selected] == ["c1", "h1"]
    rejected = [d for d in decisions if not d.eligible]
    assert rejected[0].reason == "scan_llm_budget_exhausted"


# --- suppression ---------------------------------------------------------
def _state(severity="medium", **kwargs) -> GraphState:
    return GraphState(finding=make_finding(severity=severity), **kwargs)


def test_high_severity_is_never_auto_suppressed():
    state = _state(
        severity="high",
        auditor_verdict=verdict(exploitable=False),
        validator_assessment=ValidatorAssessment(proved_safe_pattern=True),
    )
    outcome = apply_suppression_policy(state, TriageState.SUPPRESSED)
    assert outcome.triage_state == TriageState.NEEDS_REVIEW
    assert outcome.safe_suppression is False
    assert "high_critical_no_auto_suppress" in outcome.events


def test_high_severity_suppress_allowed_only_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("AEGIS_HIGH_CRITICAL_AUTO_SUPPRESS", "true")
    config_module.reset_settings()
    state = _state(
        severity="high",
        auditor_verdict=verdict(exploitable=False),
        validator_assessment=ValidatorAssessment(
            proved_safe_pattern=True, constant_bound=True
        ),
    )
    outcome = apply_suppression_policy(state, TriageState.SUPPRESSED)
    assert outcome.triage_state == TriageState.SUPPRESSED


def test_suppression_requires_validator():
    state = _state(auditor_verdict=verdict(exploitable=False))
    outcome = apply_suppression_policy(state, TriageState.SUPPRESSED)
    assert outcome.triage_state == TriageState.NEEDS_REVIEW
    assert "suppression_without_validator" in outcome.events


def test_suppression_requires_static_proof_not_just_absence_of_evidence():
    """Validator chạy nhưng không chứng minh được gì thì vẫn không đủ.

    "Không tìm thấy dấu hiệu nguy hiểm" khác hẳn "chứng minh được an toàn".
    """
    state = _state(
        auditor_verdict=verdict(exploitable=False),
        validator_assessment=ValidatorAssessment(
            dataflow_confirmed=True, proved_safe_pattern=False
        ),
    )
    outcome = apply_suppression_policy(state, TriageState.SUPPRESSED)
    assert outcome.triage_state == TriageState.NEEDS_REVIEW
    assert "no_static_proof_of_safety" in outcome.events


def test_suppression_allowed_with_constant_bound_proof():
    state = _state(
        auditor_verdict=verdict(exploitable=False),
        validator_assessment=ValidatorAssessment(
            dataflow_confirmed=True,
            constant_bound=True,
            proved_safe_pattern=True,
            evidence_ids=["ev_001"],
        ),
    )
    outcome = apply_suppression_policy(state, TriageState.SUPPRESSED)
    assert outcome.triage_state == TriageState.SUPPRESSED
    assert outcome.safe_suppression is True


def test_fabricated_citation_blocks_suppression():
    fake = verdict(exploitable=False)
    fake.grounded_citations = ["khong_co_that.php:9999"]
    state = _state(
        auditor_verdict=fake,
        validator_assessment=ValidatorAssessment(
            proved_safe_pattern=True, evidence_ids=["ev_001"]
        ),
    )
    outcome = apply_suppression_policy(state, TriageState.SUPPRESSED)
    assert outcome.triage_state == TriageState.NEEDS_REVIEW
    assert "suppression_without_grounded_evidence" in outcome.events


def test_empty_citations_block_suppression():
    silent = verdict(exploitable=False)
    silent.grounded_citations = []
    state = _state(
        auditor_verdict=silent,
        validator_assessment=ValidatorAssessment(
            proved_safe_pattern=True, evidence_ids=["ev_001"]
        ),
    )
    outcome = apply_suppression_policy(state, TriageState.SUPPRESSED)
    assert outcome.triage_state == TriageState.NEEDS_REVIEW


def test_llm_failure_forces_fail_open():
    state = _state(
        llm_failed=True,
        auditor_verdict=verdict(exploitable=False),
        validator_assessment=ValidatorAssessment(proved_safe_pattern=True),
    )
    outcome = apply_suppression_policy(state, TriageState.SUPPRESSED)
    assert outcome.triage_state == TriageState.NEEDS_REVIEW
    assert "fail_open_enforced" in outcome.events


def test_policy_does_not_touch_confirmed_verdicts():
    """Policy chỉ chặn suppress; nó không được hạ cấp finding đã xác nhận."""
    state = _state(auditor_verdict=verdict(exploitable=True))
    outcome = apply_suppression_policy(state, TriageState.CONFIRMED)
    assert outcome.triage_state == TriageState.CONFIRMED
    assert outcome.changed is False


def test_suppression_record_expires_on_code_change():
    state = _state(
        commit_sha="a42e9df",
        validator_assessment=ValidatorAssessment(
            constant_bound=True, proved_safe_pattern=True, evidence_ids=["ev_001"]
        ),
    )
    record = build_suppression_record(state)
    assert record["expires_on_code_change"] is True
    assert record["created_for_commit"] == "a42e9df"
    assert record["evidence_ids"] == ["ev_001"]

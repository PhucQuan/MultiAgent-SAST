"""Test Task 8 — routing và end-to-end workflow."""

import pytest

from ai.graph.build import aegis_graph, run_triage
from ai.graph.routing import (
    route_after_auditor,
    route_after_hypothesis,
    route_after_planner,
    route_after_skeptic,
)
from ai.schemas.finding import Language
from ai.schemas.state import GraphState
from ai.schemas.verdict import TriageState
from conftest import judge_decision, make_finding, verdict


# --- routing --------------------------------------------------------------
def test_route_after_planner():
    decided = GraphState(finding=make_finding(), triage_state=TriageState.NEEDS_REVIEW)
    assert route_after_planner(decided) == "end"
    assert route_after_planner(GraphState(finding=make_finding())) == "hypothesis_builder"


def test_route_after_hypothesis():
    ok = GraphState(finding=make_finding())
    dead = GraphState(finding=make_finding(), llm_failed=True)
    assert route_after_hypothesis(ok) == "knowledge_loader"
    assert route_after_hypothesis(dead) == "judge"


def test_route_after_auditor_skips_skeptic_only_above_configured_threshold():
    """Ngưỡng lấy từ settings (mặc định 0.99), không phải hằng số 0.8 của guide.

    Đo thực tế trên NVIDIA NIM: confidence Auditor tự chấm là 0.95/0.98 gần như
    mọi lần, nên ngưỡng 0.8 khiến Skeptic không bao giờ chạy.
    """
    confident = GraphState(finding=make_finding(), auditor_verdict=verdict(confidence=0.99))
    typical = GraphState(finding=make_finding(), auditor_verdict=verdict(confidence=0.95))
    assert route_after_auditor(confident) == "judge"
    assert route_after_auditor(typical) == "skeptic"


def test_skip_skeptic_threshold_is_configurable(monkeypatch):
    from ai import config as config_module

    monkeypatch.setenv("AEGIS_SKIP_SKEPTIC_CONFIDENCE", "0.5")
    config_module.reset_settings()
    state = GraphState(finding=make_finding(), auditor_verdict=verdict(confidence=0.6))
    assert route_after_auditor(state) == "judge"


def test_route_after_auditor_fails_open():
    dead = GraphState(finding=make_finding(), llm_failed=True)
    assert route_after_auditor(dead) == "judge"


def test_route_after_skeptic_consensus_goes_to_judge():
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.75),
        skeptic_verdict=verdict(exploitable=True, confidence=0.8),
    )
    assert route_after_skeptic(state) == "judge"


def test_route_after_skeptic_disagreement_triggers_debate():
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.6),
        skeptic_verdict=verdict(exploitable=False, confidence=0.6),
    )
    assert route_after_skeptic(state) == "auditor_reround"


def test_route_after_skeptic_hard_stops_at_round_three():
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.6),
        skeptic_verdict=verdict(exploitable=False, confidence=0.6),
        debate_round=3,
    )
    assert route_after_skeptic(state) == "judge"


# --- end-to-end -----------------------------------------------------------
@pytest.mark.parametrize(
    "language,cwe",
    [
        (Language.PYTHON, "CWE-89"),
        (Language.PHP, "CWE-89"),
        (Language.JAVASCRIPT, "CWE-78"),
        (Language.JAVA, "CWE-22"),
    ],
)
def test_end_to_end_confirmed_path(fake_structured, hypothesis, language, cwe):
    fake_structured(
        {
            "StructuredHypothesis": hypothesis,
            "AgentVerdict": [
                verdict(confidence=0.9),   # auditor
                verdict(confidence=0.9),   # skeptic đồng thuận
            ],
            "JudgeDecision": [judge_decision(TriageState.CONFIRMED)],
        }
    )
    finding = make_finding(language=language, cwe=cwe, finding_id=f"e2e-{language.value}")
    final = run_triage(finding)

    assert final.triage_state == TriageState.CONFIRMED
    assert final.llm_failed is False
    assert final.debate_round == 0
    assert len(final.knowledge_cards) == 2
    assert final.judge_decision.reasoning


def test_end_to_end_uses_skeptic_when_auditor_unsure(fake_structured, hypothesis):
    fake = fake_structured(
        {
            "StructuredHypothesis": hypothesis,
            "AgentVerdict": [
                verdict(exploitable=True, confidence=0.75),   # auditor
                verdict(exploitable=True, confidence=0.8),    # skeptic đồng thuận
            ],
            "JudgeDecision": [judge_decision(TriageState.LIKELY)],
        }
    )
    final = run_triage(make_finding())

    assert final.skeptic_verdict is not None
    assert final.skeptic_mode == "neutral"
    assert final.triage_state == TriageState.LIKELY
    assert [c["schema"] for c in fake.calls].count("AgentVerdict") == 2


def test_end_to_end_planner_short_circuit_calls_no_llm(fake_structured):
    fake = fake_structured({"StructuredHypothesis": None})
    final = run_triage(make_finding(evidence_quality=0.1))

    assert final.triage_state == TriageState.NEEDS_REVIEW
    assert fake.calls == []
    assert final.judge_decision is None


def test_end_to_end_hypothesis_failure_reaches_judge_fail_open(fake_structured):
    fake_structured({"StructuredHypothesis": None, "JudgeDecision": None})
    final = run_triage(make_finding())

    assert final.llm_failed is True
    assert final.triage_state == TriageState.NEEDS_REVIEW
    assert final.judge_decision.policy_applied == ["fail_open"]
    assert final.knowledge_cards == []


def test_end_to_end_debate_hard_stops_at_three_rounds(fake_structured, hypothesis):
    disagreeing = []
    for _ in range(8):
        disagreeing.append(verdict(exploitable=True, confidence=0.6))   # auditor
        disagreeing.append(verdict(exploitable=False, confidence=0.6))  # skeptic
    fake_structured(
        {
            "StructuredHypothesis": hypothesis,
            "AgentVerdict": disagreeing,
            "JudgeDecision": [judge_decision(TriageState.NEEDS_REVIEW)],
        }
    )
    final = run_triage(make_finding())

    assert final.debate_round == 3
    assert final.triage_state == TriageState.NEEDS_REVIEW


def test_end_to_end_sensitive_cwe_never_suppressed(fake_structured, hypothesis):
    fake_structured(
        {
            "StructuredHypothesis": hypothesis,
            "AgentVerdict": [verdict(exploitable=False, confidence=0.9)],
            "JudgeDecision": [judge_decision(TriageState.SUPPRESSED)],
        }
    )
    final = run_triage(make_finding(cwe="CWE-798"))

    assert final.triage_state == TriageState.NEEDS_REVIEW
    assert "anti_over_suppression_enforced" in final.judge_decision.policy_applied


def test_graph_is_compiled_once():
    assert aegis_graph is not None
    assert "planner" in aegis_graph.get_graph().nodes
    assert "judge" in aegis_graph.get_graph().nodes

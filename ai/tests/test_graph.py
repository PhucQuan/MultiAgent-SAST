"""Test Task 8 — routing và end-to-end workflow."""

import pytest

from ai.graph.build import aegis_graph, run_triage
from ai.graph.routing import (
    route_after_auditor,
    route_after_eligibility,
    route_after_hypothesis,
    route_after_planner,
    route_after_skeptic,
    route_after_validator,
)
from ai.schemas.finding import Language
from ai.schemas.state import GraphState, ValidatorAssessment
from ai.schemas.verdict import TriageState
from conftest import judge_decision, make_finding, verdict


# --- routing --------------------------------------------------------------
def test_route_after_planner():
    decided = GraphState(finding=make_finding(), triage_state=TriageState.NEEDS_REVIEW)
    assert route_after_planner(decided) == "end"
    assert route_after_planner(GraphState(finding=make_finding())) == "hypothesis_builder"


def test_route_after_eligibility_short_circuits_rejected_finding():
    """Finding bị gate loại ra thẳng END, không đi qua node LLM nào."""
    rejected = GraphState(
        finding=make_finding(), triage_state=TriageState.NEEDS_REVIEW
    )
    assert route_after_eligibility(rejected) == "end"
    assert route_after_eligibility(GraphState(finding=make_finding())) == "evidence_inventory"


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
    # Bỏ Skeptic vẫn phải qua validator: không agent nào tự xác nhận chính mình.
    assert route_after_auditor(confident) == "validator"
    assert route_after_auditor(typical) == "skeptic"


def test_skip_skeptic_threshold_is_configurable(monkeypatch):
    from ai import config as config_module

    monkeypatch.setenv("AEGIS_SKIP_SKEPTIC_CONFIDENCE", "0.5")
    config_module.reset_settings()
    state = GraphState(finding=make_finding(), auditor_verdict=verdict(confidence=0.6))
    assert route_after_auditor(state) == "validator"


def test_route_after_auditor_fails_open():
    dead = GraphState(finding=make_finding(), llm_failed=True)
    assert route_after_auditor(dead) == "judge"


def test_route_after_skeptic_always_goes_to_validator():
    """Skeptic không được chốt thẳng: kết luận phải qua kiểm chứng tất định."""
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.75),
        skeptic_verdict=verdict(exploitable=True, confidence=0.8),
    )
    assert route_after_skeptic(state) == "validator"


def test_validator_routes_to_judge_on_consensus():
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.75),
        skeptic_verdict=verdict(exploitable=True, confidence=0.8),
        validator_assessment=ValidatorAssessment(dataflow_confirmed=True),
    )
    assert route_after_validator(state) == "judge"


def test_validator_reinvestigates_on_disagreement_when_progress_was_made():
    """Bất đồng + vòng trước có thu được artifact mới => đi tìm thêm bằng chứng."""
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.6),
        skeptic_verdict=verdict(exploitable=False, confidence=0.6),
        validator_assessment=ValidatorAssessment(dataflow_confirmed=True),
    )
    state.evidence.add(artifact_type="dataflow_path", producer="t", payload={"a": 1})
    state.model_metadata["evidence_count_at_round_start"] = 0
    assert route_after_validator(state) == "reinvestigate"


def test_validator_stops_looping_when_no_new_evidence():
    """Bất đồng nhưng vòng trước KHÔNG thu thêm được gì => chốt, không lặp.

    Đây là điểm khác cốt lõi so với vòng debate cũ: hỏi lại mô hình trên cùng
    một ngữ cảnh chỉ lặp lại cùng thiên kiến với chi phí gấp đôi.
    """
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.6),
        skeptic_verdict=verdict(exploitable=False, confidence=0.6),
        validator_assessment=ValidatorAssessment(dataflow_confirmed=True),
    )
    state.evidence.add(artifact_type="dataflow_path", producer="t", payload={"a": 1})
    state.model_metadata["evidence_count_at_round_start"] = 1
    assert route_after_validator(state) == "judge"


def test_validator_hard_stops_at_round_max():
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.6),
        skeptic_verdict=verdict(exploitable=False, confidence=0.6),
        validator_assessment=ValidatorAssessment(insufficient_evidence=True),
        debate_round=3,
    )
    assert route_after_validator(state) == "judge"


def test_validator_stops_when_tool_budget_exhausted(monkeypatch):
    from ai import config as config_module

    monkeypatch.setenv("AEGIS_TOOL_CALL_BUDGET", "2")
    config_module.reset_settings()
    state = GraphState(
        finding=make_finding(),
        auditor_verdict=verdict(exploitable=True, confidence=0.6),
        skeptic_verdict=verdict(exploitable=False, confidence=0.6),
        validator_assessment=ValidatorAssessment(insufficient_evidence=True),
        tool_calls_used=2,
    )
    assert route_after_validator(state) == "judge"
    config_module.reset_settings()


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


def _disagreeing_verdicts(rounds: int = 8) -> list:
    out = []
    for _ in range(rounds):
        out.append(verdict(exploitable=True, confidence=0.6))   # auditor
        out.append(verdict(exploitable=False, confidence=0.6))  # skeptic
    return out


def test_debate_stops_immediately_when_no_tool_can_add_evidence(
    fake_structured, hypothesis
):
    """Bất đồng nhưng không tool nào gắn backend => dừng ngay, không tranh luận.

    Vòng debate cũ sẽ chạy đủ ba vòng ở đây và tốn sáu lượt gọi LLM để nhận
    lại đúng hai ý kiến ban đầu. Vòng mới nhận ra không có bằng chứng nào có
    thể thu thêm nên chốt luôn ở needs-review.
    """
    fake_structured(
        {
            "StructuredHypothesis": hypothesis,
            "AgentVerdict": _disagreeing_verdicts(),
            "JudgeDecision": [judge_decision(TriageState.NEEDS_REVIEW)],
        }
    )
    final = run_triage(make_finding())

    assert final.debate_round == 1
    assert final.triage_state == TriageState.NEEDS_REVIEW


def test_debate_hard_stops_at_round_max_even_when_evidence_keeps_arriving(
    fake_structured, hypothesis, mock_code_tools, monkeypatch
):
    """Có bằng chứng mới mỗi vòng thì vẫn bị chặn cứng ở debate_round_max.

    Trần này là thứ giữ cho một finding khó không ngốn vô hạn quota: kể cả khi
    mỗi vòng đều tiến triển, graph vẫn phải dừng và giao cho người xem.
    """
    import ai.nodes.tool_executor as tool_executor
    import ai.nodes.validator as validator_mod
    import ai.nodes.investigation_planner as planner_mod

    monkeypatch.setenv("AEGIS_TOOL_CALL_BUDGET", "50")
    from ai import config as config_module

    config_module.reset_settings()

    counter = {"n": 0}

    def unique_dataflow(file, line):
        counter["n"] += 1
        return {"file": file, "line": line, "reaches_sink": True, "probe": counter["n"]}

    tools = mock_code_tools(
        get_dataflow_path=unique_dataflow,
        get_sanitizer_trace=lambda file, line: {"file": file, "line": line, "probe": counter["n"]},
        get_constant_propagation=lambda file, line, variable="": {"constant_bound": False, "probe": counter["n"]},
        get_control_flow_context=lambda file, line: {"guards": [], "probe": counter["n"]},
        get_backward_slice=lambda file, line, variable="": {"slice": [], "probe": counter["n"]},
    )
    for mod in (tool_executor, validator_mod, planner_mod):
        monkeypatch.setattr(mod, "code_tools", tools)

    fake_structured(
        {
            "StructuredHypothesis": hypothesis,
            "AgentVerdict": _disagreeing_verdicts(),
            "JudgeDecision": [judge_decision(TriageState.NEEDS_REVIEW)],
        }
    )
    final = run_triage(make_finding())

    assert final.debate_round == 3
    assert final.triage_state == TriageState.NEEDS_REVIEW
    config_module.reset_settings()


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

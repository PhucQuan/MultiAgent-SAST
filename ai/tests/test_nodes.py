"""Test Task 7 — từng node chạy riêng với LLM giả."""

from ai.nodes.auditor import auditor_node
from ai.nodes.hypothesis_builder import hypothesis_builder_node
from ai.nodes.judge import judge_node
from ai.nodes.knowledge_loader import knowledge_loader_node
from ai.nodes.planner import planner_node
from ai.nodes.skeptic import skeptic_node
from ai.schemas.finding import Language
from ai.schemas.state import GraphState
from ai.schemas.verdict import TriageState
from conftest import (
    FakeMessage,
    FakeResponse,
    FakeToolCall,
    FakeUsage,
    judge_decision,
    make_finding,
    verdict,
)


# --- Planner --------------------------------------------------------------
def test_planner_short_circuits_on_weak_evidence():
    state = GraphState(finding=make_finding(evidence_quality=0.2))
    assert planner_node(state).triage_state == TriageState.NEEDS_REVIEW


def test_planner_passes_through_on_good_evidence():
    state = GraphState(finding=make_finding(evidence_quality=0.8))
    assert planner_node(state).triage_state is None


def test_planner_does_not_mutate_input_state():
    state = GraphState(finding=make_finding(evidence_quality=0.1))
    planner_node(state)
    assert state.triage_state is None


# --- Hypothesis Builder ---------------------------------------------------
def test_hypothesis_builder_sets_hypothesis(fake_structured, hypothesis):
    fake = fake_structured({"StructuredHypothesis": hypothesis})
    out = hypothesis_builder_node(GraphState(finding=make_finding()))
    assert out.hypothesis == hypothesis
    assert out.llm_failed is False
    assert fake.calls[0]["schema"] == "StructuredHypothesis"


def test_hypothesis_builder_marks_llm_failed(fake_structured):
    fake_structured({"StructuredHypothesis": None})
    out = hypothesis_builder_node(GraphState(finding=make_finding()))
    assert out.hypothesis is None
    assert out.llm_failed is True


def test_hypothesis_builder_skipped_when_already_decided(fake_structured, hypothesis):
    fake = fake_structured({"StructuredHypothesis": hypothesis})
    state = GraphState(finding=make_finding(), triage_state=TriageState.NEEDS_REVIEW)
    out = hypothesis_builder_node(state)
    assert out.hypothesis is None
    assert fake.calls == []


# --- Knowledge Loader -----------------------------------------------------
def test_knowledge_loader_loads_two_cards():
    out = knowledge_loader_node(GraphState(finding=make_finding()))
    assert len(out.knowledge_cards) == 2
    assert out.knowledge_cards[0]["language"] == "php"
    assert out.knowledge_cards[0]["cwe"] == "CWE-89"


def test_knowledge_loader_matches_language():
    finding = make_finding(language=Language.JAVA, cwe="CWE-78")
    out = knowledge_loader_node(GraphState(finding=finding))
    assert out.knowledge_cards[0]["language"] == "java"


# --- Auditor --------------------------------------------------------------
def test_auditor_without_hypothesis_fails_open(fake_structured):
    fake_structured({"AgentVerdict": verdict()})
    out = auditor_node(GraphState(finding=make_finding()))
    assert out.auditor_verdict is None
    assert out.llm_failed is True


def test_auditor_returns_verdict(fake_structured, hypothesis):
    fake_structured({"AgentVerdict": verdict(confidence=0.85)})
    state = GraphState(finding=make_finding(), hypothesis=hypothesis)
    out = auditor_node(state)
    assert out.auditor_verdict.confidence == 0.85
    assert out.llm_failed is False


def test_auditor_executes_tool_calls(
    fake_structured, fake_openai, hypothesis, mock_code_tools
):
    mock_code_tools()
    fake_structured({"AgentVerdict": verdict()})
    tool_call = FakeToolCall("call_1", "get_function_body", '{"function_name": "run"}')
    fake_openai(
        [
            FakeResponse(FakeMessage(content=None, tool_calls=[tool_call]), FakeUsage()),
            FakeResponse(FakeMessage(content="xong"), FakeUsage()),
        ]
    )
    state = GraphState(finding=make_finding(), hypothesis=hypothesis)
    out = auditor_node(state)

    assert len(out.tool_calls_made) == 1
    assert out.tool_calls_made[0]["name"] == "get_function_body"
    assert "mock: run" in out.tool_calls_made[0]["result"]


def test_auditor_tool_loop_capped_at_five(fake_structured, fake_openai, hypothesis):
    fake_structured({"AgentVerdict": verdict()})
    always_tool = [
        FakeResponse(
            FakeMessage(
                content=None,
                tool_calls=[FakeToolCall(f"c{i}", "get_callers", '{"function_name": "f"}')],
            ),
            FakeUsage(),
        )
        for i in range(10)
    ]
    fake = fake_openai(always_tool)
    out = auditor_node(GraphState(finding=make_finding(), hypothesis=hypothesis))

    assert len(fake.calls) == 5  # MAX_TOOL_CALLS
    assert len(out.tool_calls_made) == 5


def test_auditor_fails_open_only_when_final_verdict_call_fails(
    fake_structured, fake_openai, hypothesis
):
    """Fail-open chỉ khi bước CHỐT verdict hỏng, không phải khi vòng tool hỏng."""
    fake_structured({"AgentVerdict": None})
    fake_openai([RuntimeError("nvidia 500")])
    out = auditor_node(GraphState(finding=make_finding(), hypothesis=hypothesis))
    assert out.llm_failed is True
    assert out.auditor_verdict is None


def test_auditor_reround_prompt_includes_skeptic_feedback(
    fake_structured, hypothesis
):
    fake = fake_structured({"AgentVerdict": verdict()})
    state = GraphState(
        finding=make_finding(),
        hypothesis=hypothesis,
        auditor_verdict=verdict(),
        skeptic_verdict=verdict(exploitable=False, confidence=0.6),
        debate_round=1,
    )
    auditor_node(state)
    prompt = fake.calls[0]["messages"][1]["content"]
    assert "Phản biện từ Skeptic" in prompt


# --- Skeptic --------------------------------------------------------------
def test_skeptic_uses_neutral_mode_when_auditor_confident(fake_structured, hypothesis):
    fake_structured({"AgentVerdict": verdict(confidence=0.7)})
    state = GraphState(
        finding=make_finding(),
        hypothesis=hypothesis,
        auditor_verdict=verdict(confidence=0.7),
    )
    out = skeptic_node(state)
    assert out.skeptic_mode == "neutral"


def test_skeptic_switches_to_adversarial_on_low_confidence(
    fake_structured, hypothesis
):
    fake = fake_structured({"AgentVerdict": verdict(confidence=0.4)})
    state = GraphState(
        finding=make_finding(),
        hypothesis=hypothesis,
        auditor_verdict=verdict(confidence=0.4),
    )
    out = skeptic_node(state)
    assert out.skeptic_mode == "adversarial"
    assert "false-positive hunter" in fake.calls[0]["messages"][0]["content"]


def test_skeptic_skipped_without_auditor_verdict(fake_structured):
    fake = fake_structured({"AgentVerdict": verdict()})
    out = skeptic_node(GraphState(finding=make_finding()))
    assert out.skeptic_verdict is None
    assert fake.calls == []


def test_skeptic_llm_failure_marks_state(fake_structured, hypothesis):
    fake_structured({"AgentVerdict": None})
    state = GraphState(
        finding=make_finding(), hypothesis=hypothesis, auditor_verdict=verdict()
    )
    out = skeptic_node(state)
    assert out.llm_failed is True


# --- Judge ----------------------------------------------------------------
def test_judge_returns_llm_decision(fake_structured):
    fake_structured({"JudgeDecision": judge_decision(TriageState.CONFIRMED)})
    state = GraphState(finding=make_finding(), auditor_verdict=verdict())
    out = judge_node(state)
    assert out.triage_state == TriageState.CONFIRMED


def test_judge_fail_open_when_llm_dead(fake_structured):
    fake_structured({"JudgeDecision": None})
    state = GraphState(finding=make_finding(), auditor_verdict=verdict())
    out = judge_node(state)
    assert out.triage_state == TriageState.NEEDS_REVIEW
    assert out.judge_decision.policy_applied == ["fail_open"]
    assert out.llm_failed is True


def test_judge_never_suppresses_sensitive_cwe(fake_structured):
    """Anti-over-suppression phải chặn ngay cả khi LLM trả suppressed."""
    fake_structured({"JudgeDecision": judge_decision(TriageState.SUPPRESSED)})
    state = GraphState(
        finding=make_finding(cwe="CWE-327"), auditor_verdict=verdict(exploitable=False)
    )
    out = judge_node(state)
    assert out.triage_state == TriageState.NEEDS_REVIEW
    assert "anti_over_suppression_enforced" in out.judge_decision.policy_applied


def test_judge_never_suppresses_when_llm_failed(fake_structured):
    fake_structured({"JudgeDecision": judge_decision(TriageState.SUPPRESSED)})
    state = GraphState(
        finding=make_finding(), auditor_verdict=verdict(), llm_failed=True
    )
    out = judge_node(state)
    assert out.triage_state == TriageState.NEEDS_REVIEW
    assert "fail_open_enforced" in out.judge_decision.policy_applied


def test_judge_can_suppress_ordinary_cwe(fake_structured):
    fake_structured({"JudgeDecision": judge_decision(TriageState.SUPPRESSED)})
    state = GraphState(
        finding=make_finding(cwe="CWE-89"), auditor_verdict=verdict(exploitable=False)
    )
    out = judge_node(state)
    assert out.triage_state == TriageState.SUPPRESSED


def test_judge_respects_planner_decision(fake_structured):
    fake = fake_structured({"JudgeDecision": judge_decision()})
    state = GraphState(
        finding=make_finding(), triage_state=TriageState.NEEDS_REVIEW
    )
    out = judge_node(state)
    assert out.triage_state == TriageState.NEEDS_REVIEW
    assert fake.calls == []


def test_auditor_tool_loop_error_degrades_instead_of_failing(
    fake_structured, fake_openai, hypothesis
):
    """Lỗi ở vòng tool-use phải bỏ tool rồi vẫn chốt verdict, không fail-open.

    Đo 2026-09-10: khi vòng tool-use fail-open ngay, 4/12 và 6/12 finding của hai
    lần chạy độc lập rơi vào needs-review mà chưa hề được Auditor đánh giá.
    """
    fake_structured({"AgentVerdict": verdict(confidence=0.7)})
    fake_openai([RuntimeError("503 Service temporarily overloaded")])
    out = auditor_node(GraphState(finding=make_finding(), hypothesis=hypothesis))

    assert out.llm_failed is False
    assert out.auditor_verdict is not None
    assert out.auditor_verdict.confidence == 0.7
    assert out.tool_calls_made == []


def test_auditor_tool_budget_is_per_finding_not_per_round(
    fake_structured, fake_openai, hypothesis
):
    """Trần 5 tool call tính cho cả finding, kể cả khi debate lại nhiều vòng.

    auditor_reround gọi lại node này; nếu trần tính theo vòng thì tổng sẽ nhân
    lên — đo 2026-09-06 có finding dùng tới 20 tool call.
    """
    fake_structured({"AgentVerdict": verdict(confidence=0.7)})
    always_tool = [
        FakeResponse(
            FakeMessage(
                content=None,
                tool_calls=[FakeToolCall(f"c{i}", "get_callers", '{"function_name": "f"}')],
            ),
            FakeUsage(),
        )
        for i in range(10)
    ]
    fake = fake_openai(always_tool)
    state = GraphState(
        finding=make_finding(),
        hypothesis=hypothesis,
        tool_calls_made=[{"name": "get_callers", "args": {}, "result": "{}"}] * 3,
    )
    out = auditor_node(state)

    assert len(fake.calls) == 2          # chỉ còn 5 - 3 = 2 lượt
    assert len(out.tool_calls_made) == 5  # tổng cộng vẫn đúng trần

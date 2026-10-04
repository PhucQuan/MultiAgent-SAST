"""Judge — chốt triage_state. Policy được enforce ở CẢ prompt VÀ Python code."""

from ..config import get_settings, settings
from ..llm.nvidia_client import llm_client
from ..policies.suppression import apply_suppression_policy
from ..prompts.judge import SENSITIVE_CWES, build_judge_prompt
from ..schemas.state import GraphState
from ..schemas.verdict import JudgeDecision, TriageState


def judge_node(state: GraphState) -> GraphState:
    new_state = state.model_copy(deep=True)
    if new_state.triage_state:  # đã chốt ở Planner
        return new_state

    debate_hard_stopped = state.debate_round >= settings.debate_round_max

    messages = build_judge_prompt(
        finding_json=state.finding.model_dump_json(indent=2),
        auditor_verdict_json=(
            state.auditor_verdict.model_dump_json(indent=2)
            if state.auditor_verdict
            else "null"
        ),
        skeptic_verdict_json=(
            state.skeptic_verdict.model_dump_json(indent=2)
            if state.skeptic_verdict
            else None
        ),
        llm_failed=state.llm_failed,
        debate_hard_stopped=debate_hard_stopped,
        cwe=state.finding.cwe,
    )

    decision = llm_client.call_structured(
        model=settings.model_judge,
        messages=messages,
        schema=JudgeDecision,
        temperature=settings.temp_judge,
    )

    # HARD-CODED FAIL-OPEN nếu LLM Judge fail
    if decision is None:
        new_state.llm_failed = True
        new_state.triage_state = TriageState.NEEDS_REVIEW
        new_state.judge_decision = JudgeDecision(
            reasoning="LLM Judge failed. Fail-open policy applied.",
            correctness_score=0.5,
            severity_score=0.5,
            exploitability_score=0.5,
            triage_state=TriageState.NEEDS_REVIEW,
            confidence=0.0,
            policy_applied=["fail_open"],
        )
        new_state.record_policy("fail_open")
        return new_state

    # DOUBLE-ENFORCE anti-over-suppression cho nhóm CWE nhạy cảm
    if (
        state.finding.cwe in SENSITIVE_CWES
        and decision.triage_state == TriageState.SUPPRESSED
    ):
        decision.triage_state = TriageState.NEEDS_REVIEW
        decision.policy_applied.append("anti_over_suppression_enforced")

    # Policy tất định là tiếng nói cuối cùng. Judge chỉ ĐỀ XUẤT một trạng
    # thái; việc nó có được phép giấu cảnh báo hay không do Python quyết,
    # dựa trên validator và citation — không dựa trên lời model tự khẳng định.
    outcome = apply_suppression_policy(
        new_state, decision.triage_state, get_settings()
    )
    for event in outcome.events:
        new_state.record_policy(event)
    if outcome.changed:
        decision.policy_applied.extend(outcome.events)
    decision.triage_state = outcome.triage_state

    new_state.judge_decision = decision
    new_state.triage_state = decision.triage_state
    return new_state

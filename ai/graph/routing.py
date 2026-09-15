"""Conditional edge cho LangGraph."""

from ..config import settings
from ..schemas.state import GraphState


def route_after_planner(state: GraphState) -> str:
    return "end" if state.triage_state else "hypothesis_builder"


def route_after_hypothesis(state: GraphState) -> str:
    return "judge" if state.llm_failed else "knowledge_loader"


def route_after_auditor(state: GraphState) -> str:
    if state.llm_failed:
        return "judge"
    # Confidence cao rõ ràng → skip Skeptic (tiết kiệm token).
    # Ngưỡng lấy từ cấu hình: confidence LLM tự chấm không được hiệu chỉnh nên
    # hằng số 0.8 của guide làm nhánh Skeptic chết hoàn toàn.
    if (
        state.auditor_verdict
        and state.auditor_verdict.confidence >= settings.skip_skeptic_confidence
    ):
        return "judge"
    return "skeptic"


def route_after_skeptic(state: GraphState) -> str:
    if state.llm_failed:
        return "judge"
    if state.debate_round >= settings.debate_round_max:
        return "judge"  # hard-stop

    # Đồng thuận + confidence cao → chốt
    if (
        state.auditor_verdict
        and state.skeptic_verdict
        and state.auditor_verdict.exploitable == state.skeptic_verdict.exploitable
        and min(state.auditor_verdict.confidence, state.skeptic_verdict.confidence)
        >= 0.7
    ):
        return "judge"

    return "auditor_reround"  # debate thêm vòng

"""Planner — rule-based, không gọi LLM."""

from ..schemas.state import GraphState
from ..schemas.verdict import TriageState


def planner_node(state: GraphState) -> GraphState:
    """Rule-based, không gọi LLM. Skip LLM nếu evidence quá kém."""
    new_state = state.model_copy(deep=True)
    if state.finding.evidence.evidence_quality < 0.3:
        new_state.triage_state = TriageState.NEEDS_REVIEW
    return new_state

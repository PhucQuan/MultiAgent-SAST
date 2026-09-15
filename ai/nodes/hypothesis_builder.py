"""Hypothesis Builder — dựng StructuredHypothesis từ EvidenceBundle."""

from ..config import settings
from ..llm.nvidia_client import llm_client
from ..prompts.hypothesis_builder import build_hypothesis_prompt
from ..schemas.hypothesis import StructuredHypothesis
from ..schemas.state import GraphState


def hypothesis_builder_node(state: GraphState) -> GraphState:
    new_state = state.model_copy(deep=True)
    if new_state.triage_state:
        return new_state

    messages = build_hypothesis_prompt(state.finding.model_dump_json(indent=2))
    hypothesis = llm_client.call_structured(
        model=settings.model_hypothesis,
        messages=messages,
        schema=StructuredHypothesis,
        temperature=settings.temp_hypothesis,
    )

    if hypothesis is None:
        new_state.llm_failed = True
    else:
        new_state.hypothesis = hypothesis
    return new_state

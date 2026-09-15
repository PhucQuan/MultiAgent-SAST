"""Skeptic — 2 mode: neutral (mặc định) và adversarial (khi Auditor thiếu tự tin)."""

from ..config import settings
from ..llm.nvidia_client import llm_client
from ..prompts.skeptic import build_skeptic_prompt
from ..schemas.state import GraphState
from ..schemas.verdict import AgentVerdict


def skeptic_node(state: GraphState) -> GraphState:
    new_state = state.model_copy(deep=True)
    if new_state.triage_state or not new_state.auditor_verdict:
        return new_state

    # Neutral default, adversarial khi confidence thấp
    mode = "adversarial" if state.auditor_verdict.confidence < 0.5 else "neutral"
    new_state.skeptic_mode = mode

    messages = build_skeptic_prompt(
        state.finding.model_dump_json(indent=2),
        state.hypothesis.model_dump_json(indent=2) if state.hypothesis else "null",
        state.auditor_verdict.model_dump_json(indent=2),
        state.knowledge_cards,
        mode=mode,
    )

    verdict = llm_client.call_structured(
        model=settings.model_skeptic,
        messages=messages,
        schema=AgentVerdict,
        temperature=settings.temp_skeptic,
    )
    if verdict is None:
        new_state.llm_failed = True
    else:
        new_state.skeptic_verdict = verdict
    return new_state

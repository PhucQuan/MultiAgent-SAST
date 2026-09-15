"""GraphState — state dùng chung cho toàn bộ LangGraph workflow."""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from .finding import NormalizedFinding
from .hypothesis import StructuredHypothesis
from .verdict import AgentVerdict, JudgeDecision, TriageState


class GraphState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    finding: NormalizedFinding
    hypothesis: Optional[StructuredHypothesis] = None
    knowledge_cards: list[dict] = Field(default_factory=list)
    auditor_verdict: Optional[AgentVerdict] = None
    skeptic_verdict: Optional[AgentVerdict] = None
    skeptic_mode: str = "neutral"
    judge_decision: Optional[JudgeDecision] = None
    triage_state: Optional[TriageState] = None
    debate_round: int = 0
    llm_failed: bool = False
    tool_calls_made: list[dict] = Field(default_factory=list)

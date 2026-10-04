"""Verdict schema — REASONING LUÔN ĐẶT TRƯỚC VERDICT.

Thứ tự field không phải chuyện thẩm mỹ: LLM sinh JSON tuần tự nên field đứng
trước sẽ điều kiện hoá field đứng sau (IRIS ICLR 2025, Tam et al. EMNLP 2024).
Đảo thứ tự = verdict được sinh trước khi mô hình kịp suy luận.
"""

from enum import Enum

from pydantic import BaseModel, Field


class TriageState(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    NEEDS_REVIEW = "needs-review"
    SUPPRESSED = "suppressed"


class AgentVerdict(BaseModel):
    """reasoning ĐẶT TRƯỚC exploitable — quy tắc bắt buộc."""

    reasoning: str = Field(description="Suy luận step-by-step DỰA TRÊN evidence")
    grounded_citations: list[str] = Field(
        default_factory=list, description="Cite 'file:line' trong evidence"
    )
    exploitable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    fp_indicators_found: list[str] = Field(default_factory=list)


class JudgeDecision(BaseModel):
    """3 tiêu chí kiểu GPTLens. reasoning TRƯỚC triage_state."""

    reasoning: str
    correctness_score: float = Field(ge=0.0, le=1.0)
    severity_score: float = Field(ge=0.0, le=1.0)
    exploitability_score: float = Field(ge=0.0, le=1.0)
    triage_state: TriageState
    confidence: float = Field(ge=0.0, le=1.0)
    policy_applied: list[str] = Field(default_factory=list)

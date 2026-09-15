"""StructuredHypothesis theo VulAgent Phase II (arXiv:2509.11523)."""

from typing import Literal

from pydantic import BaseModel, Field


class Assumption(BaseModel):
    id: str
    text: str
    status: Literal["plausible", "contradicted", "unknown"] = "unknown"
    evidence: str | None = None


class TriggerPathNode(BaseModel):
    file: str
    line: int
    description: str


class Guard(BaseModel):
    file: str
    line: int
    kind: Literal[
        "sanitizer", "bounds_check", "null_check", "auth_check", "early_return", "other"
    ]
    description: str
    dominates_sink: bool = False


class StructuredHypothesis(BaseModel):
    """Theo VulAgent Phase II.

    HypothesisBuilder xây object này, TUYỆT ĐỐI không tự lọc/pruning.
    Filtering làm ở Judge.
    """

    assumptions: list[Assumption]
    trigger_path: list[TriggerPathNode]
    guards_on_path: list[Guard] = Field(default_factory=list)

"""Schema cho knowledge card (theo Vul-RAG, arXiv:2406.11147)."""

from pydantic import BaseModel, Field


class FewShotExample(BaseModel):
    code: str
    label: str  # "TP" or "FP"
    why: str


class KnowledgeCard(BaseModel):
    cwe: str
    name: str
    language: str
    functional_semantics: str
    sources: list[str]
    sinks: list[str]
    sanitizers: list[str]
    root_cause: str
    fp_indicators: list[str]  # TRỌNG YẾU cho Skeptic
    few_shot: list[FewShotExample] = Field(default_factory=list, max_length=3)

"""Pydantic schemas for multilingual AI knowledge cards."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class StrictKnowledgeModel(BaseModel):
    """Base model for knowledge-layer contracts."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the model to a JSON-friendly dictionary."""
        return self.model_dump(mode="json")


class LanguageKnowledgeSection(StrictKnowledgeModel):
    """Language-specific security knowledge used by AI prompts."""

    sources: List[str] = Field(default_factory=list)
    sinks: List[str] = Field(default_factory=list)
    sanitizers: List[str] = Field(default_factory=list)
    insufficient_sanitizers: List[str] = Field(default_factory=list)
    false_positive_patterns: List[str] = Field(default_factory=list)
    secure_fix_patterns: List[str] = Field(default_factory=list)
    framework_notes: Dict[str, List[str]] = Field(default_factory=dict)


class EvidenceRubric(StrictKnowledgeModel):
    """Evidence expectations for validating a finding."""

    required: List[str] = Field(default_factory=list)
    strong_signals: List[str] = Field(default_factory=list)
    weak_signals: List[str] = Field(default_factory=list)
    suppress_when: List[str] = Field(default_factory=list)


class KnowledgeCard(StrictKnowledgeModel):
    """A structured security note bound to CWE and vulnerability type."""

    card_id: str
    title: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    finding_type: Optional[str] = None
    description: str = ""
    language: Optional[str] = None
    sources: List[str] = Field(default_factory=list)
    sinks: List[str] = Field(default_factory=list)
    sanitizers: List[str] = Field(default_factory=list)
    false_positive_patterns: List[str] = Field(default_factory=list)
    remediation_notes: List[str] = Field(default_factory=list)
    languages: Dict[str, LanguageKnowledgeSection] = Field(default_factory=dict)
    evidence_rubric: EvidenceRubric = Field(default_factory=EvidenceRubric)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeLoaderInput(StrictKnowledgeModel):
    """Input used to select the smallest useful knowledge section."""

    cwe_id: Optional[str] = None
    vuln_type: Optional[str] = None
    language: str
    framework: Optional[str] = None


class KnowledgeLoaderResult(StrictKnowledgeModel):
    """Selected knowledge for a finding."""

    card: Optional[KnowledgeCard]
    matched_language_section: Optional[LanguageKnowledgeSection] = None
    matched_framework_section: List[str] = Field(default_factory=list)
    fallback_used: bool = False
    warnings: List[str] = Field(default_factory=list)

    @property
    def card_id(self) -> Optional[str]:
        """Return the selected card id when available."""
        return self.card.card_id if self.card else None

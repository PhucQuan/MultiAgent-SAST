"""Structured contracts exchanged by AI triage orchestration nodes."""

from typing import Any, Dict, List, Optional

from pydantic import Field, model_validator

from aegis_sast.core.models import TriageStatus
from aegis_sast.knowledge.schema import KnowledgeLoaderResult
from aegis_sast.orchestration.context import EvidenceContext
from aegis_sast.triage.schema import AITriageInput, StrictContractModel, TriageDecision


class PlannerInput(StrictContractModel):
    """Input to the planner node."""

    triage_input: AITriageInput


class PlannerResult(StrictContractModel):
    """Structured output from the planner node."""

    finding_id: str
    route_hints: List[str] = Field(default_factory=list)
    required_knowledge: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    should_use_skeptic: bool
    reasoning_summary: str


class KnowledgeLoaderNodeInput(StrictContractModel):
    """Input to the knowledge-loader node."""

    triage_input: AITriageInput
    plan: PlannerResult


class KnowledgeLoaderNodeResult(StrictContractModel):
    """Structured output from the knowledge-loader node."""

    finding_id: str
    selection: KnowledgeLoaderResult
    warnings: List[str] = Field(default_factory=list)


class AuditorResult(StrictContractModel):
    """Required structured output from the auditor node."""

    is_exploitable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_strength: str
    sanitizer_effective: bool
    reasoning_summary: str
    missing_evidence: List[str] = Field(default_factory=list)


class AuditorInput(StrictContractModel):
    """Input to the auditor node."""

    triage_input: AITriageInput
    plan: PlannerResult
    knowledge: KnowledgeLoaderNodeResult


class SkepticResult(StrictContractModel):
    """Required structured output from the skeptic node."""

    objections: List[str] = Field(default_factory=list)
    false_positive_indicators: List[str] = Field(default_factory=list)
    sanitizer_found: bool
    dead_code_suspected: bool
    recommended_status: TriageStatus
    confidence: float = Field(ge=0.0, le=1.0)


class SkepticInput(StrictContractModel):
    """Input to the skeptic node."""

    triage_input: AITriageInput
    auditor_result: AuditorResult
    knowledge: KnowledgeLoaderNodeResult


class JudgeInput(StrictContractModel):
    """Input to the judge node."""

    triage_input: AITriageInput
    plan: PlannerResult
    auditor_result: AuditorResult
    skeptic_result: Optional[SkepticResult] = None
    route_taken: List[str] = Field(default_factory=list)


class ReporterInput(StrictContractModel):
    """Input to the reporter node."""

    triage_input: AITriageInput
    decision: TriageDecision
    knowledge: KnowledgeLoaderNodeResult


class ReportEnrichment(StrictContractModel):
    """Structured report enrichment produced after final triage."""

    finding_id: str
    explanation: str
    remediation_note: str
    supporting_evidence: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    route_taken: List[str] = Field(default_factory=list)


class AuditorReview(AuditorResult):
    """Workflow auditor output with deterministic routing metadata."""

    finding_id: str
    route_id: str
    route_steps: List[str]
    evidence_score: float = Field(ge=0.0, le=1.0)
    matched_card_ids: List[str] = Field(default_factory=list)
    context: Optional[EvidenceContext] = None
    summary: str = ""
    notes: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def fill_contract_fields(cls, data: Any) -> Any:
        """Populate required AI fields from legacy workflow values."""
        if not isinstance(data, dict):
            return data

        evidence_score = float(data.get("evidence_score", data.get("confidence", 0.0)))
        data.setdefault("is_exploitable", evidence_score >= 0.7)
        data.setdefault("confidence", evidence_score)
        data.setdefault(
            "evidence_strength",
            "strong" if evidence_score >= 0.75 else "moderate" if evidence_score >= 0.5 else "weak",
        )
        data.setdefault("sanitizer_effective", False)
        data.setdefault("reasoning_summary", data.get("summary", "Auditor reviewed evidence."))
        data.setdefault("missing_evidence", [])
        return data

    def to_dict(self) -> Dict[str, Any]:
        """Convert the review to a JSON-friendly dictionary."""
        payload = self.model_dump(exclude={"context"}, mode="json")
        payload["context"] = self.context.to_dict() if self.context else None
        return payload


class SkepticReview(SkepticResult):
    """Workflow skeptic output with deterministic validation metadata."""

    finding_id: str
    executed: bool
    summary: str
    mitigation_signals: List[str] = Field(default_factory=list)
    suggested_status: Optional[TriageStatus] = None
    confidence_cap: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def fill_contract_fields(cls, data: Any) -> Any:
        """Populate required AI fields from deterministic skeptic values."""
        if not isinstance(data, dict):
            return data

        mitigation_signals = data.get("mitigation_signals", [])
        suggested_status = data.get("suggested_status")
        confidence_cap = data.get("confidence_cap")
        recommended_status = suggested_status or data.get("recommended_status")
        if recommended_status is None:
            recommended_status = (
                TriageStatus.SUPPRESSED if mitigation_signals else TriageStatus.NEEDS_REVIEW
            )

        data.setdefault("false_positive_indicators", mitigation_signals)
        data.setdefault("sanitizer_found", bool(mitigation_signals))
        data.setdefault("dead_code_suspected", False)
        data.setdefault("recommended_status", recommended_status)
        data.setdefault("confidence", confidence_cap if confidence_cap is not None else 0.5)
        return data

    def to_dict(self) -> Dict[str, Any]:
        """Convert the review to a JSON-friendly dictionary."""
        return self.model_dump(mode="json")


class JudgeReview(StrictContractModel):
    """Structured output from the final judge stage."""

    finding_id: str
    final_status: TriageStatus
    final_confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the review to a JSON-friendly dictionary."""
        return self.model_dump(mode="json")

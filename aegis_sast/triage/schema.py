"""Pydantic schemas for AI triage inputs, outputs, and records."""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_sast.core.models import NormalizedFinding as CoreNormalizedFinding
from aegis_sast.core.models import TriageStatus


TriageStatusLiteral = Literal["confirmed", "likely", "needs-review", "suppressed"]
SeverityLiteral = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


class StrictContractModel(BaseModel):
    """Base model for structured AI contracts."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the model to a JSON-friendly dictionary."""
        return self.model_dump(mode="json")


class SourceLocation(StrictContractModel):
    """Normalized source-code location passed to AI."""

    file_path: str
    line_number: int = Field(ge=1)
    column_number: int = Field(ge=0)
    code_snippet: str
    symbol_name: Optional[str] = None


class SanitizerInfo(StrictContractModel):
    """Sanitizer evidence observed by the deterministic core."""

    present: bool
    effective: bool
    sanitizer_type: Optional[str] = None
    function_name: Optional[str] = None
    location: Optional[SourceLocation] = None
    notes: List[str] = Field(default_factory=list)


class GraphMetadata(StrictContractModel):
    """Graph evidence supplied by the deterministic core."""

    cfg_edge_count: int = Field(default=0, ge=0)
    dfg_edge_count: int = Field(default=0, ge=0)
    dead_path_suspected: bool = False
    unsupported_framework: bool = False
    notes: List[str] = Field(default_factory=list)


class EvidenceBundle(StrictContractModel):
    """Structured evidence supplied to AI after deterministic analysis."""

    finding_id: str
    source_location: SourceLocation
    sink_location: SourceLocation
    evidence_snippets: List[str] = Field(min_length=1)
    data_flow_path: List[SourceLocation] = Field(min_length=1)
    sanitizer_info: SanitizerInfo
    graph_metadata: GraphMetadata = Field(default_factory=GraphMetadata)
    cross_file: bool
    call_chain_depth: int = Field(ge=0)

    @field_validator("evidence_snippets")
    @classmethod
    def snippets_must_not_be_blank(cls, snippets: List[str]) -> List[str]:
        """Reject empty evidence strings because agents cannot verify them."""
        if any(not snippet.strip() for snippet in snippets):
            raise ValueError("evidence_snippets entries must not be blank")
        return snippets


class NormalizedFinding(StrictContractModel):
    """AI-facing normalized finding contract."""

    finding_id: str
    rule_id: str
    language: Literal["python", "javascript", "java", "php"]
    vuln_type: str
    cwe_id: Optional[str] = None
    severity: SeverityLiteral
    confidence: float = Field(ge=0.0, le=1.0)
    static_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    source_location: SourceLocation
    sink_location: SourceLocation
    evidence_snippets: List[str] = Field(min_length=1)
    data_flow_path: List[SourceLocation] = Field(min_length=1)
    sanitizer_info: SanitizerInfo
    graph_metadata: GraphMetadata = Field(default_factory=GraphMetadata)
    cross_file: bool
    call_chain_depth: int = Field(ge=0)

    @model_validator(mode="before")
    @classmethod
    def default_static_confidence(cls, data: Any) -> Any:
        """Keep legacy confidence payloads valid while exposing static_confidence."""
        if isinstance(data, dict) and "static_confidence" not in data:
            data["static_confidence"] = data.get("confidence")
        return data

    @field_validator("finding_id", "vuln_type", "rule_id")
    @classmethod
    def required_strings_must_not_be_blank(cls, value: str) -> str:
        """Reject blank identifiers and labels."""
        if not value.strip():
            raise ValueError("required string fields must not be blank")
        return value

    def to_evidence_bundle(self) -> EvidenceBundle:
        """Extract the evidence subset for node inputs."""
        return EvidenceBundle(
            finding_id=self.finding_id,
            source_location=self.source_location,
            sink_location=self.sink_location,
            evidence_snippets=self.evidence_snippets,
            data_flow_path=self.data_flow_path,
            sanitizer_info=self.sanitizer_info,
            graph_metadata=self.graph_metadata,
            cross_file=self.cross_file,
            call_chain_depth=self.call_chain_depth,
        )


class BenchmarkMetadata(StrictContractModel):
    """Optional benchmark metadata for evaluation and reproducibility."""

    benchmark_id: str
    dataset_name: str
    case_id: str
    expected_status: Optional[TriageStatusLiteral] = None
    ground_truth_vuln: Optional[bool] = None
    language: Literal["python", "javascript", "java", "php"]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AITriageInput(StrictContractModel):
    """Only data shape accepted by the AI layer."""

    finding: NormalizedFinding
    evidence: EvidenceBundle
    benchmark: Optional[BenchmarkMetadata] = None

    @model_validator(mode="after")
    def finding_and_evidence_ids_must_match(self) -> "AITriageInput":
        """Reject payloads where evidence belongs to a different finding."""
        if self.finding.finding_id != self.evidence.finding_id:
            raise ValueError("finding.finding_id must match evidence.finding_id")
        return self


class TriageDecision(StrictContractModel):
    """Final structured triage decision emitted by the judge node."""

    finding_id: Optional[str] = None
    status: TriageStatus
    confidence: float = Field(ge=0.0, le=1.0)
    vulnerability_explanation: str
    remediation_note: str
    supporting_evidence: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    route_taken: List[str] = Field(default_factory=list)
    token_usage: Dict[str, int] = Field(default_factory=dict)
    latency_ms: Optional[float] = Field(default=None, ge=0.0)
    model_name: Optional[str] = None
    reviewer: str = "judge-node-v1"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("vulnerability_explanation", "remediation_note")
    @classmethod
    def narrative_fields_must_not_be_blank(cls, value: str) -> str:
        """Reject blank explanations in final decisions."""
        if not value.strip():
            raise ValueError("decision narrative fields must not be blank")
        return value

    @property
    def explanation(self) -> str:
        """Backward-compatible alias for deterministic triage code."""
        return self.vulnerability_explanation

    @property
    def recommendation(self) -> str:
        """Backward-compatible alias for deterministic triage code."""
        return self.remediation_note

    @property
    def ai_confidence(self) -> float:
        """Contract alias for AI-specific confidence."""
        return self.confidence

    @property
    def evidence_notes(self) -> List[str]:
        """Backward-compatible alias for supporting evidence."""
        return self.supporting_evidence

    @classmethod
    def from_legacy(
        cls,
        *,
        status: TriageStatus | TriageStatusLiteral,
        confidence: float,
        explanation: str,
        recommendation: Optional[str] = None,
        reviewer: str = "triage-engine-v1",
        evidence_notes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "TriageDecision":
        """Build the locked decision schema from existing deterministic fields."""
        status_value = status.value if isinstance(status, TriageStatus) else status
        return cls(
            status=status_value,
            confidence=confidence,
            vulnerability_explanation=explanation,
            remediation_note=recommendation or "Review the affected source-to-sink path.",
            supporting_evidence=evidence_notes or [],
            limitations=[],
            reviewer=reviewer,
            metadata=metadata or {},
        )


class TriageRecord(StrictContractModel):
    """Bundles a core normalized finding with the structured triage decision."""

    finding: CoreNormalizedFinding
    decision: TriageDecision

    def to_dict(self) -> Dict[str, Any]:
        """Convert the record to a JSON-friendly dictionary."""
        return {
            "finding": self.finding.to_dict(),
            "decision": self.decision.to_dict(),
        }

"""Contracts exchanged between deterministic workflow nodes."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from aegis_sast.core.models import TriageStatus
from aegis_sast.orchestration.context import EvidenceContext


@dataclass
class AuditorReview:
    """Structured output from the auditor stage."""

    finding_id: str
    route_id: str
    route_steps: List[str]
    evidence_score: float
    matched_card_ids: List[str] = field(default_factory=list)
    context: Optional[EvidenceContext] = None
    summary: str = ""
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        """Convert the review to a JSON-friendly dictionary."""
        return {
            "finding_id": self.finding_id,
            "route_id": self.route_id,
            "route_steps": self.route_steps,
            "evidence_score": self.evidence_score,
            "matched_card_ids": self.matched_card_ids,
            "context": self.context.to_dict() if self.context else None,
            "summary": self.summary,
            "notes": self.notes,
            "metadata": self.metadata,
        }


@dataclass
class SkepticReview:
    """Structured output from the skeptic validation stage."""

    finding_id: str
    executed: bool
    summary: str
    objections: List[str] = field(default_factory=list)
    mitigation_signals: List[str] = field(default_factory=list)
    suggested_status: Optional[TriageStatus] = None
    confidence_cap: Optional[float] = None
    metadata: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        """Convert the skeptic review to a JSON-friendly dictionary."""
        return {
            "finding_id": self.finding_id,
            "executed": self.executed,
            "summary": self.summary,
            "objections": self.objections,
            "mitigation_signals": self.mitigation_signals,
            "suggested_status": (
                self.suggested_status.value if self.suggested_status else None
            ),
            "confidence_cap": self.confidence_cap,
            "metadata": self.metadata,
        }


@dataclass
class JudgeReview:
    """Structured output from the final judge stage."""

    finding_id: str
    final_status: TriageStatus
    final_confidence: float
    summary: str
    metadata: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        """Convert the judge review to a JSON-friendly dictionary."""
        return {
            "finding_id": self.finding_id,
            "final_status": self.final_status.value,
            "final_confidence": self.final_confidence,
            "summary": self.summary,
            "metadata": self.metadata,
        }

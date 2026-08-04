"""Schemas for triage decisions and agent-ready review records."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aegis_sast.core.models import NormalizedFinding, TriageStatus


@dataclass
class TriageDecision:
    """Represents the final triage decision for a normalized finding."""

    status: TriageStatus
    confidence: float
    explanation: str
    recommendation: Optional[str] = None
    reviewer: str = "deterministic-core"
    reason_codes: List[str] = field(default_factory=list)
    evidence_summary: Dict[str, Any] = field(default_factory=dict)
    manual_review_required: bool = False
    evidence_notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the decision to a JSON-friendly dictionary."""
        return {
            "status": self.status.value,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "reviewer": self.reviewer,
            "reason_codes": self.reason_codes,
            "evidence_summary": self.evidence_summary,
            "manual_review_required": self.manual_review_required,
            "evidence_notes": self.evidence_notes,
            "metadata": self.metadata,
        }


@dataclass
class TriageRecord:
    """Bundles a normalized finding with the triage decision applied to it."""

    finding: NormalizedFinding
    decision: TriageDecision

    def to_dict(self) -> Dict[str, Any]:
        """Convert the record to a JSON-friendly dictionary."""
        return {
            "finding": self.finding.to_dict(),
            "decision": self.decision.to_dict(),
        }

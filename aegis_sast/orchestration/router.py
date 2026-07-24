"""Simple routing helpers for the staged scan and triage workflow."""

from dataclasses import dataclass, field
from typing import Dict, List

from aegis_sast.core.models import NormalizedFinding


@dataclass
class WorkflowRoute:
    """Represents a suggested workflow path for one finding."""

    route_id: str
    steps: List[str]
    reason: str
    metadata: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        """Convert the route to a JSON-friendly dictionary."""
        return {
            "route_id": self.route_id,
            "steps": self.steps,
            "reason": self.reason,
            "metadata": self.metadata,
        }


def route_finding(finding: NormalizedFinding) -> WorkflowRoute:
    """
    Pick a conservative workflow path based on evidence strength.

    High-confidence findings without sanitizers can skip the skeptic stage.
    Findings with sanitizers or weaker evidence should go through skeptical review.
    """
    evidence_summary = finding.evidence_summary
    has_sanitizers = finding.is_effectively_sanitized

    if finding.confidence >= 0.85 and not has_sanitizers:
        return WorkflowRoute(
            route_id="direct-judge",
            steps=[
                "planner",
                "knowledge_loader",
                "auditor",
                "judge",
                "reporter",
            ],
            reason="High-confidence evidence can move directly to judging.",
            metadata={
                "language": finding.language,
                "confidence": finding.confidence,
                "has_sanitizers": has_sanitizers,
                "path_length": evidence_summary.get("path_length", 0),
                "intermediate_step_count": evidence_summary.get(
                    "intermediate_step_count",
                    0,
                ),
            },
        )

    return WorkflowRoute(
        route_id="skeptic-review",
        steps=[
            "planner",
            "knowledge_loader",
            "auditor",
            "skeptic_validator",
            "judge",
            "reporter",
        ],
        reason="Finding needs skeptical validation due to weaker or conflicting evidence.",
        metadata={
            "language": finding.language,
            "confidence": finding.confidence,
            "has_sanitizers": has_sanitizers,
            "path_length": evidence_summary.get("path_length", 0),
            "intermediate_step_count": evidence_summary.get(
                "intermediate_step_count",
                0,
            ),
        },
    )

"""Knowledge-assisted triage engine for normalized findings."""

from typing import Iterable, List, Optional

from aegis_sast.core.models import (
    NormalizedFinding,
    Severity,
    TriageStatus,
    Vulnerability,
)
from aegis_sast.knowledge import KnowledgeCard, KnowledgeLoader
from aegis_sast.orchestration.router import route_finding
from aegis_sast.triage.schema import TriageDecision, TriageRecord


class TriageEngine:
    """Applies deterministic and knowledge-assisted triage to findings."""

    def __init__(
        self,
        knowledge_loader: Optional[KnowledgeLoader] = None,
        cards: Optional[List[KnowledgeCard]] = None,
    ):
        self.knowledge_loader = knowledge_loader or KnowledgeLoader()
        self.cards = cards if cards is not None else self.knowledge_loader.load_directory()

    def triage_vulnerability(self, vulnerability: Vulnerability) -> TriageRecord:
        """Convert a vulnerability into a triage record."""
        finding = vulnerability.to_normalized_finding()
        matched_cards = self._match_cards(finding)
        decision = self._decide(finding, matched_cards)

        finding.triage_status = decision.status
        finding.confidence = decision.confidence
        if decision.explanation:
            finding.explanation = decision.explanation
        if decision.recommendation and not finding.recommendation:
            finding.recommendation = decision.recommendation
        triage_metadata = finding.metadata.setdefault("triage", {})
        triage_metadata["knowledge_card_ids"] = [
            card.card_id for card in matched_cards
        ]
        triage_metadata["workflow_route"] = decision.metadata.get("workflow_route")
        triage_metadata["reviewer"] = decision.reviewer
        finding.metadata["knowledge_card_ids"] = [
            card.card_id for card in matched_cards
        ]
        finding.metadata["workflow_route"] = decision.metadata.get("workflow_route")

        return TriageRecord(finding=finding, decision=decision)

    def triage_vulnerabilities(
        self,
        vulnerabilities: Iterable[Vulnerability],
    ) -> List[TriageRecord]:
        """Triages a batch of vulnerabilities."""
        return [self.triage_vulnerability(vuln) for vuln in vulnerabilities]

    def summarize(self, records: Iterable[TriageRecord]) -> dict:
        """Return aggregate counts for each triage status."""
        counts = {
            TriageStatus.CONFIRMED.value: 0,
            TriageStatus.LIKELY.value: 0,
            TriageStatus.NEEDS_REVIEW.value: 0,
            TriageStatus.SUPPRESSED.value: 0,
        }
        for record in records:
            counts[record.decision.status.value] += 1
        return counts

    def _match_cards(self, finding: NormalizedFinding) -> List[KnowledgeCard]:
        """Return built-in knowledge cards relevant to the finding."""
        return self.knowledge_loader.filter_cards(
            self.cards,
            language=finding.language,
            finding_type=finding.vulnerability_type,
        )

    def _decide(
        self,
        finding: NormalizedFinding,
        matched_cards: List[KnowledgeCard],
    ) -> TriageDecision:
        """Make a conservative triage decision based on evidence and knowledge."""
        route = route_finding(finding)
        evidence_summary = finding.evidence_summary
        graph_slice = evidence_summary.get("graph_slice", {})
        notes = [
            f"matched_cards={len(matched_cards)}",
            f"path_length={evidence_summary.get('path_length', 0)}",
            f"intermediate_steps={evidence_summary.get('intermediate_step_count', 0)}",
            f"sanitizers={evidence_summary.get('sanitizer_count', 0)}",
            f"route={' -> '.join(route.steps)}",
        ]
        if graph_slice:
            notes.append(
                "graph_slice="
                f"nodes:{graph_slice.get('node_count', 0)},"
                f"cfg:{graph_slice.get('cfg_edge_count', 0)},"
                f"dfg:{graph_slice.get('dfg_edge_count', 0)},"
                f"path_nodes:{graph_slice.get('path_node_count', 0)},"
                f"path_edges:{graph_slice.get('path_edge_count', 0)}"
            )

        status = finding.triage_status
        confidence = finding.confidence
        recommendation = finding.recommendation or self._recommendation_from_cards(
            matched_cards
        )
        explanation = finding.explanation or finding.message

        if finding.is_effectively_sanitized:
            notes.append("effective_sanitizer_detected=true")
            if status == TriageStatus.CONFIRMED:
                status = TriageStatus.NEEDS_REVIEW
                confidence = min(confidence, 0.65)
                explanation = (
                    "The dataflow includes a sanitizer that may neutralize the sink. "
                    "Manual review is still recommended before suppression."
                )
            elif status in (TriageStatus.LIKELY, TriageStatus.NEEDS_REVIEW):
                status = TriageStatus.SUPPRESSED
                confidence = min(confidence, 0.4)
                explanation = (
                    "Built-in triage found an effective sanitizer on the path, so the "
                    "finding is likely a false positive."
                )

        elif status == TriageStatus.NEEDS_REVIEW:
            if evidence_summary.get("intermediate_step_count", 0) > 0:
                status = TriageStatus.LIKELY
                confidence = max(confidence, 0.7)
                explanation = (
                    "The finding contains a multi-step dataflow trace and no effective "
                    "sanitizer was observed."
                )
            elif finding.severity in (Severity.CRITICAL, Severity.HIGH):
                confidence = max(confidence, 0.6)
                explanation = (
                    "High-severity sink reached from user-controlled input, but the "
                    "current evidence is still too shallow for confirmation."
                )

        if status == TriageStatus.SUPPRESSED and finding.severity in (
            Severity.CRITICAL,
            Severity.HIGH,
        ):
            notes.append("suppressed_high_severity=true")

        notes.extend(
            [f"knowledge_card={card.card_id}" for card in matched_cards]
        )

        return TriageDecision(
            status=status,
            confidence=confidence,
            explanation=explanation,
            recommendation=recommendation,
            reviewer="triage-engine-v1",
            evidence_notes=notes,
            metadata={
                "knowledge_card_ids": [card.card_id for card in matched_cards],
                "workflow_route": route.to_dict(),
            },
        )

    @staticmethod
    def _recommendation_from_cards(cards: List[KnowledgeCard]) -> Optional[str]:
        """Return the first remediation note available from matching cards."""
        for card in cards:
            if card.remediation_notes:
                return card.remediation_notes[0]
        return None

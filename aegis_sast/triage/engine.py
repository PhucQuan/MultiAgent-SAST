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

    LOCAL_OPERATOR_SOURCE_TYPES = {"COMMAND_LINE_ARGS", "ENVIRONMENT_VAR"}
    DEFAULT_NEEDS_REVIEW_CONFIDENCE = 0.55
    DEFAULT_LIKELY_CONFIDENCE = 0.7

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
        triage_metadata["reason_codes"] = decision.reason_codes
        triage_metadata["evidence_summary"] = decision.evidence_summary
        triage_metadata["manual_review_required"] = decision.manual_review_required
        finding.metadata["knowledge_card_ids"] = [
            card.card_id for card in matched_cards
        ]
        finding.metadata["workflow_route"] = decision.metadata.get("workflow_route")
        finding.metadata["reason_codes"] = decision.reason_codes
        finding.metadata["manual_review_required"] = decision.manual_review_required

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
        triage_input = finding.to_triage_input()
        evidence_pack = triage_input.get("evidence", {})
        route = route_finding(finding)
        evidence_summary = evidence_pack.get("summary", {})
        graph_slice = evidence_pack.get("graph_slice", {})
        decision_evidence_summary = dict(evidence_summary)
        if graph_slice:
            decision_evidence_summary["graph_slice"] = graph_slice
        notes = [
            f"triage_input_schema={triage_input.get('schema_version', 'unknown')}",
            f"matched_cards={len(matched_cards)}",
            f"path_length={evidence_summary.get('path_length', 0)}",
            f"intermediate_steps={evidence_summary.get('intermediate_step_count', 0)}",
            f"sanitizers={evidence_summary.get('sanitizer_count', 0)}",
            f"route={' -> '.join(route.steps)}",
        ]
        reason_codes = [f"workflow-route:{route.route_id}"]
        if matched_cards:
            reason_codes.append("knowledge-card-match")
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
            reason_codes.append("effective-sanitizer")
            if status == TriageStatus.CONFIRMED:
                status = TriageStatus.NEEDS_REVIEW
                confidence = min(confidence, 0.65)
                explanation = (
                    "The dataflow includes a sanitizer that may neutralize the sink. "
                    "Manual review is still recommended before suppression."
                )
                reason_codes.append("high-severity-sanitized-path")
            elif status in (TriageStatus.LIKELY, TriageStatus.NEEDS_REVIEW):
                status = TriageStatus.SUPPRESSED
                confidence = min(confidence, 0.4)
                explanation = (
                    "Built-in triage found an effective sanitizer on the path, so the "
                    "finding is likely a false positive."
                )
                reason_codes.append("sanitized-path-suppressed")

        elif self._is_local_operator_source(finding):
            notes.append("local_operator_input=true")
            reason_codes.append("local-operator-input-source")
            if self._should_suppress_local_operator_finding(finding):
                status = TriageStatus.SUPPRESSED
                confidence = min(confidence, 0.35)
                explanation = (
                    "The path starts from local operator-controlled input such as "
                    "argv or environment variables, so it is lower priority than a "
                    "remote attacker-controlled flow."
                )
                reason_codes.append("operator-controlled-source-suppressed")
            elif status == TriageStatus.NEEDS_REVIEW:
                confidence = min(max(confidence, 0.45), 0.55)
                explanation = (
                    "The sink is reached from local operator-controlled input rather "
                    "than a remote request source, so manual review is still needed "
                    "before treating it as exploitable."
                )
                reason_codes.append("operator-controlled-source-needs-review")

        elif status == TriageStatus.NEEDS_REVIEW:
            if self._should_keep_needs_review(finding):
                confidence = min(
                    max(confidence, self.DEFAULT_NEEDS_REVIEW_CONFIDENCE),
                    0.62,
                )
                explanation = self._needs_review_explanation(finding)
                reason_codes.append(self._needs_review_reason_code(finding))
            elif self._supports_likely_promotion(
                finding,
                evidence_summary,
            ):
                status = TriageStatus.LIKELY
                confidence = max(confidence, self._likely_confidence_floor(finding))
                explanation = (
                    "The finding contains a clear deterministic dataflow into a "
                    "security-sensitive sink and no effective sanitizer was observed."
                )
                reason_codes.append("clear-deterministic-dataflow")
            elif finding.severity in (Severity.CRITICAL, Severity.HIGH):
                confidence = max(confidence, 0.6)
                explanation = (
                    "High-severity sink reached from user-controlled input, but the "
                    "current evidence is still too shallow for confirmation."
                )
                reason_codes.append("high-severity-ambiguous-exploitability")

        if status == TriageStatus.SUPPRESSED and finding.severity in (
            Severity.CRITICAL,
            Severity.HIGH,
        ):
            notes.append("suppressed_high_severity=true")
            reason_codes.append("suppressed-high-severity")

        notes.extend(
            [f"knowledge_card={card.card_id}" for card in matched_cards]
        )
        manual_review_required = status == TriageStatus.NEEDS_REVIEW or (
            status == TriageStatus.SUPPRESSED
            and finding.severity in (Severity.CRITICAL, Severity.HIGH)
        )

        return TriageDecision(
            status=status,
            confidence=confidence,
            explanation=explanation,
            recommendation=recommendation,
            reviewer="triage-engine-v1",
            reason_codes=self._dedupe_reason_codes(reason_codes),
            evidence_summary=decision_evidence_summary,
            manual_review_required=manual_review_required,
            evidence_notes=notes,
            metadata={
                "triage_input_schema": triage_input.get("schema_version"),
                "knowledge_card_ids": [card.card_id for card in matched_cards],
                "workflow_route": route.to_dict(),
                "reason_codes": self._dedupe_reason_codes(reason_codes),
                "evidence_summary": decision_evidence_summary,
                "manual_review_required": manual_review_required,
            },
        )

    @staticmethod
    def _recommendation_from_cards(cards: List[KnowledgeCard]) -> Optional[str]:
        """Return the first remediation note available from matching cards."""
        for card in cards:
            if card.remediation_notes:
                return card.remediation_notes[0]
        return None

    @classmethod
    def _is_local_operator_source(cls, finding: NormalizedFinding) -> bool:
        """Return True when the source is local operator input rather than a request."""
        return finding.detection_metadata.get("source_type") in cls.LOCAL_OPERATOR_SOURCE_TYPES

    @staticmethod
    def _should_suppress_local_operator_finding(finding: NormalizedFinding) -> bool:
        """Suppress noisy local-input findings that are common in tooling code."""
        if finding.vulnerability_type in {"PATH_TRAVERSAL", "MASS_ASSIGNMENT"}:
            return True

        if finding.vulnerability_type != "COMMAND_INJECTION":
            return False

        sink_function = str(finding.detection_metadata.get("sink_function") or "")
        sink_arguments = finding.detection_metadata.get("sink_arguments", [])
        normalized_arguments = {
            str(argument).replace(" ", "").lower() for argument in sink_arguments
        }

        return sink_function.startswith("subprocess.") and "shell=true" not in normalized_arguments

    @staticmethod
    def _dedupe_reason_codes(reason_codes: List[str]) -> List[str]:
        """Keep reason codes stable and free of duplicates."""
        return list(dict.fromkeys(code for code in reason_codes if code))

    @staticmethod
    def _has_clear_deterministic_evidence(evidence_summary: dict) -> bool:
        """Return True when the finding includes a non-trivial source-to-sink path."""
        return (
            evidence_summary.get("path_length", 0) >= 3
            or evidence_summary.get("intermediate_step_count", 0) > 0
        )

    @classmethod
    def _supports_likely_promotion(
        cls,
        finding: NormalizedFinding,
        evidence_summary: dict,
    ) -> bool:
        """Return True when deterministic evidence is strong enough for likely."""
        if not cls._has_clear_deterministic_evidence(evidence_summary):
            return False

        if finding.vulnerability_type == "OPEN_REDIRECT":
            return False

        if cls._is_low_impact_path_finding(finding):
            return False

        return finding.vulnerability_type in {
            "COMMAND_INJECTION",
            "CODE_INJECTION",
            "INSECURE_DESERIALIZATION",
            "PATH_TRAVERSAL",
            "SQL_INJECTION",
        }

    @staticmethod
    def _likely_confidence_floor(finding: NormalizedFinding) -> float:
        """Return a family-aware confidence floor for likely findings."""
        if finding.vulnerability_type in {
            "CODE_INJECTION",
            "INSECURE_DESERIALIZATION",
            "SQL_INJECTION",
        }:
            return 0.74

        if finding.vulnerability_type == "PATH_TRAVERSAL":
            return 0.68

        return TriageEngine.DEFAULT_LIKELY_CONFIDENCE

    @classmethod
    def _should_keep_needs_review(cls, finding: NormalizedFinding) -> bool:
        """Keep ambiguity visible when exploitability still depends on context."""
        return finding.vulnerability_type == "OPEN_REDIRECT" or cls._is_low_impact_path_finding(
            finding
        )

    @staticmethod
    def _needs_review_explanation(finding: NormalizedFinding) -> str:
        """Return a stable explanation for findings that should stay review-only."""
        if finding.vulnerability_type == "OPEN_REDIRECT":
            return (
                "Open redirects depend heavily on target validation and deployment "
                "context, so this finding stays visible but still needs manual review."
            )

        return (
            "The path reaches a lower-impact filesystem check rather than a direct "
            "file read or write sink, so manual review is still required."
        )

    @staticmethod
    def _needs_review_reason_code(finding: NormalizedFinding) -> str:
        """Return the reason code used when a finding stays in manual review."""
        if finding.vulnerability_type == "OPEN_REDIRECT":
            return "manual-review-open-redirect"
        return "manual-review-low-impact-path-check"

    @staticmethod
    def _is_low_impact_path_finding(finding: NormalizedFinding) -> bool:
        """Return True for path findings that only reach existence checks."""
        if finding.vulnerability_type != "PATH_TRAVERSAL":
            return False

        sink_function = str(finding.detection_metadata.get("sink_function") or "").lower()
        sink_pattern = str(finding.detection_metadata.get("sink_pattern") or "").lower()
        return sink_function.endswith("exists") or ".exists" in sink_pattern

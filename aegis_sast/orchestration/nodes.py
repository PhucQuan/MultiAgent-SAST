"""Deterministic workflow nodes that approximate future LangGraph stages."""

from copy import deepcopy
from typing import List, Optional, Tuple

from aegis_sast.core.models import NormalizedFinding, Severity, TriageStatus
from aegis_sast.knowledge import KnowledgeCard
from aegis_sast.orchestration.context import SourceContextReader
from aegis_sast.orchestration.contracts import (
    AuditorReview,
    JudgeReview,
    SkepticReview,
)
from aegis_sast.orchestration.state import RepoProfile
from aegis_sast.triage.schema import TriageDecision, TriageRecord


class AuditorNode:
    """Review evidence quality and attach source context to a finding."""

    def __init__(self, context_reader: Optional[SourceContextReader] = None):
        self.context_reader = context_reader or SourceContextReader()

    def review(
        self,
        record: TriageRecord,
        matched_cards: List[KnowledgeCard],
        repo_profile: RepoProfile,
    ) -> AuditorReview:
        """Generate an evidence-aware review before skeptical validation."""
        route = record.decision.metadata.get("workflow_route", {})
        route_id = route.get("route_id", "unknown")
        route_steps = route.get("steps", [])
        evidence_score = self._score_evidence(record.finding, record.decision.confidence)
        context = self.context_reader.read_for_finding(record.finding)
        notes = [
            f"scan_profile={repo_profile.scan_profile}",
            f"language={record.finding.language}",
            f"severity={record.finding.severity.value}",
            f"context_loaded={bool(context.source_window or context.sink_window)}",
        ]
        notes.extend(
            [f"framework_hint={hint}" for hint in repo_profile.framework_hints[:4]]
        )
        summary = (
            f"Auditor rated the finding at evidence_score={evidence_score:.2f} "
            f"with route={route_id}."
        )
        return AuditorReview(
            finding_id=record.finding.id,
            route_id=route_id,
            route_steps=route_steps,
            evidence_score=evidence_score,
            matched_card_ids=[card.card_id for card in matched_cards],
            context=context,
            summary=summary,
            notes=notes,
            metadata={
                "scan_profile": repo_profile.scan_profile,
                "framework_hints": repo_profile.framework_hints,
            },
        )

    @staticmethod
    def _score_evidence(finding: NormalizedFinding, base_confidence: float) -> float:
        """Estimate how strong the deterministic evidence currently looks."""
        score = 0.35
        score += min(len(finding.evidence.intermediate_steps) * 0.12, 0.24)
        score += min(base_confidence * 0.35, 0.35)
        if finding.evidence.source.file_path:
            score += 0.08
        if finding.evidence.sink.file_path:
            score += 0.08
        if finding.evidence.has_sanitizers:
            score -= 0.14
        graph_summary = finding.evidence.metadata.get("graph_summary", {})
        if graph_summary.get("cfg_edge_count", 0) > 0:
            score += 0.04
        if graph_summary.get("dfg_edge_count", 0) > 0:
            score += 0.04
        return max(0.0, min(score, 1.0))


class SkepticValidatorNode:
    """Look for mitigation signals or ambiguity before final judgement."""

    MITIGATION_PATTERNS = {
        "SQL_INJECTION": [
            "preparedstatement",
            "execute(query, params)",
            "cursor.execute(query, params)",
            "bindparam",
            "parameterized",
        ],
        "COMMAND_INJECTION": [
            "execfile(",
            "spawn(",
            "shell=false",
            "subprocess.run([",
        ],
        "PATH_TRAVERSAL": [
            "resolve(",
            "startswith(",
            "normalize(",
            "realpath(",
        ],
        "XSS": [
            "escape(",
            "html.escape(",
            "htmlspecialchars(",
            "autoescape",
        ],
        "SSRF": [
            "allowlist",
            "urlparse(",
            "validate_url",
            "trusted_hosts",
        ],
    }

    def review(
        self,
        record: TriageRecord,
        matched_cards: List[KnowledgeCard],
        auditor_review: AuditorReview,
    ) -> SkepticReview:
        """Run deterministic skeptical validation on routed findings."""
        if auditor_review.route_id != "skeptic-review":
            return SkepticReview(
                finding_id=record.finding.id,
                executed=False,
                summary="Route skipped skeptical validation.",
                metadata={"route_id": auditor_review.route_id},
            )

        context_text = self._collect_context_text(auditor_review).lower()
        mitigation_signals: List[str] = []
        objections: List[str] = []
        suggested_status = None
        confidence_cap = None

        if record.finding.metadata.get("is_sanitized"):
            mitigation_signals.append("Dataflow already contains a sanitizer.")

        for token in self.MITIGATION_PATTERNS.get(
            record.finding.vulnerability_type,
            [],
        ):
            if token.lower() in context_text:
                mitigation_signals.append(
                    f"Context contains mitigation-like token: {token}"
                )

        if mitigation_signals:
            if record.finding.severity in (Severity.CRITICAL, Severity.HIGH):
                if record.decision.status == TriageStatus.CONFIRMED:
                    suggested_status = TriageStatus.NEEDS_REVIEW
                    confidence_cap = 0.65
                else:
                    suggested_status = TriageStatus.SUPPRESSED
                    confidence_cap = 0.45
            else:
                suggested_status = TriageStatus.SUPPRESSED
                confidence_cap = 0.45
        elif record.decision.confidence < 0.6:
            objections.append("Confidence remains low after audit.")
            suggested_status = TriageStatus.NEEDS_REVIEW
            confidence_cap = 0.55

        summary = (
            "Skeptic validator "
            + (
                "found mitigation signals in nearby context."
                if mitigation_signals
                else "did not find strong mitigation signals."
            )
        )
        return SkepticReview(
            finding_id=record.finding.id,
            executed=True,
            summary=summary,
            objections=objections,
            mitigation_signals=mitigation_signals,
            suggested_status=suggested_status,
            confidence_cap=confidence_cap,
            metadata={
                "matched_card_ids": [card.card_id for card in matched_cards],
                "matched_card_count": len(matched_cards),
                "route_id": auditor_review.route_id,
            },
        )

    @staticmethod
    def _collect_context_text(auditor_review: AuditorReview) -> str:
        """Flatten source and sink windows into one string."""
        context = auditor_review.context
        if context is None:
            return ""

        chunks: List[str] = []
        if context.source_window:
            chunks.extend(context.source_window.lines)
        if context.sink_window:
            chunks.extend(context.sink_window.lines)
        return "\n".join(chunks)


class JudgeNode:
    """Finalize a triage record after audit and skeptical validation."""

    RISKY_SQL_TOKENS = ["select ", "insert ", "update ", "delete "]
    DIRECT_SQL_EXECUTION_TOKENS = [
        "cursor.execute(query)",
        "statement.execute(query)",
        "statement.executequery(query)",
    ]
    DYNAMIC_SQL_TOKENS = [' + ', 'f"', "f'", ".format(", '" %', "' %"]
    DANGEROUS_SHELL_TOKENS = [
        "os.system(",
        "os.popen(",
        "subprocess.call(",
        "subprocess.run(",
        "shell=true",
    ]

    def finalize(
        self,
        record: TriageRecord,
        auditor_review: AuditorReview,
        skeptic_review: SkepticReview,
    ) -> Tuple[TriageRecord, JudgeReview]:
        """Apply conservative overrides and attach node outputs."""
        updated_record = deepcopy(record)
        decision = updated_record.decision

        final_status = decision.status
        final_confidence = decision.confidence
        explanation = decision.explanation
        recommendation = decision.recommendation
        risk_signals = self._collect_risk_signals(updated_record.finding, auditor_review)
        promotion_applied = False

        if skeptic_review.executed:
            if skeptic_review.suggested_status is not None:
                final_status = skeptic_review.suggested_status
            if skeptic_review.confidence_cap is not None:
                final_confidence = min(final_confidence, skeptic_review.confidence_cap)
            if skeptic_review.mitigation_signals:
                explanation = (
                    explanation
                    + " Skeptic validation found mitigation signals in nearby code context."
                )
            elif self._should_promote_to_likely(
                updated_record.finding,
                final_status,
                auditor_review,
                skeptic_review,
                risk_signals,
            ):
                final_status = TriageStatus.LIKELY
                final_confidence = max(
                    final_confidence,
                    min(max(auditor_review.evidence_score, 0.72), 0.85),
                )
                explanation = (
                    explanation
                    + " Auditor evidence is strong and skeptical validation did not find mitigation signals."
                )
                promotion_applied = True
            elif skeptic_review.objections:
                explanation = (
                    explanation
                    + " Skeptic validation kept the finding visible because the evidence is still ambiguous."
                )

        judge_summary = (
            f"Judge finalized the finding as {final_status.value} "
            f"with confidence={final_confidence:.2f}."
        )
        judge_review = JudgeReview(
            finding_id=updated_record.finding.id,
            final_status=final_status,
            final_confidence=final_confidence,
            summary=judge_summary,
            metadata={
                "auditor_route_id": auditor_review.route_id,
                "skeptic_executed": skeptic_review.executed,
                "promotion_applied": promotion_applied,
                "risk_signals": risk_signals,
            },
        )

        updated_record.finding.triage_status = final_status
        updated_record.finding.confidence = final_confidence
        updated_record.finding.explanation = explanation
        if recommendation and not updated_record.finding.recommendation:
            updated_record.finding.recommendation = recommendation
        updated_record.finding.metadata["auditor_review"] = auditor_review.to_dict()
        updated_record.finding.metadata["skeptic_review"] = skeptic_review.to_dict()
        updated_record.finding.metadata["judge_review"] = judge_review.to_dict()

        updated_record.decision = TriageDecision.from_legacy(
            status=final_status,
            confidence=final_confidence,
            explanation=explanation,
            recommendation=recommendation,
            reviewer="judge-node-v1",
            evidence_notes=(
                decision.evidence_notes
                + auditor_review.notes
                + [f"risk_signal={signal}" for signal in risk_signals]
                + skeptic_review.objections
                + skeptic_review.mitigation_signals
            ),
            metadata={
                **decision.metadata,
                "auditor_review": auditor_review.to_dict(),
                "skeptic_review": skeptic_review.to_dict(),
                "judge_review": judge_review.to_dict(),
            },
        )
        return updated_record, judge_review

    @staticmethod
    def _should_promote_to_likely(
        finding: NormalizedFinding,
        current_status: TriageStatus,
        auditor_review: AuditorReview,
        skeptic_review: SkepticReview,
        risk_signals: List[str],
    ) -> bool:
        """Promote strong unmitigated findings from needs-review to likely."""
        return (
            current_status == TriageStatus.NEEDS_REVIEW
            and finding.severity in (Severity.CRITICAL, Severity.HIGH)
            and not finding.metadata.get("is_sanitized")
            and not skeptic_review.mitigation_signals
            and not skeptic_review.objections
            and auditor_review.evidence_score >= 0.7
            and bool(risk_signals)
        )

    @staticmethod
    def _collect_risk_signals(
        finding: NormalizedFinding,
        auditor_review: AuditorReview,
    ) -> List[str]:
        """Collect simple risk signals from nearby code context."""
        context_text = SkepticValidatorNode._collect_context_text(auditor_review).lower()
        signals: List[str] = []

        if not context_text:
            return signals

        if finding.vulnerability_type == "SQL_INJECTION":
            has_sql_keyword = any(
                token in context_text for token in JudgeNode.RISKY_SQL_TOKENS
            )
            has_dynamic_sql = (
                "query =" in context_text
                and any(token in context_text for token in JudgeNode.DYNAMIC_SQL_TOKENS)
            ) or ("% " in context_text and "query =" in context_text)
            has_direct_execution = any(
                token in context_text
                for token in JudgeNode.DIRECT_SQL_EXECUTION_TOKENS
            )
            if has_sql_keyword and has_dynamic_sql:
                signals.append("dynamic-sql-construction")
            if has_direct_execution:
                signals.append("query-executed-directly")

        elif finding.vulnerability_type == "COMMAND_INJECTION":
            if any(token in context_text for token in JudgeNode.DANGEROUS_SHELL_TOKENS):
                signals.append("dangerous-shell-invocation")
            if "shell=true" in context_text:
                signals.append("shell-true-enabled")

        return signals

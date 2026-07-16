"""LangGraph-ready orchestration helpers for staged scan and triage flows."""

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from aegis_sast.core.models import ScanResult
from aegis_sast.knowledge import KnowledgeLoader
from aegis_sast.orchestration.nodes import AuditorNode, JudgeNode, SkepticValidatorNode
from aegis_sast.orchestration.repo_intake import RepoIntake
from aegis_sast.triage import TriageEngine

from aegis_sast.orchestration.state import RepoProfile, ScanWorkflowState


class ScanWorkflow:
    """
    Execute a deterministic, stateful workflow around scan results.

    This is not a full LangGraph integration yet. It provides the same
    step-oriented state shape so the project can evolve into a true agent
    workflow without rewriting the surrounding data contracts.
    """

    def __init__(
        self,
        knowledge_loader: Optional[KnowledgeLoader] = None,
        triage_engine: Optional[TriageEngine] = None,
        auditor_node: Optional[AuditorNode] = None,
        skeptic_node: Optional[SkepticValidatorNode] = None,
        judge_node: Optional[JudgeNode] = None,
    ):
        self.knowledge_loader = knowledge_loader or KnowledgeLoader()
        self.triage_engine = triage_engine or TriageEngine(self.knowledge_loader)
        self.auditor_node = auditor_node or AuditorNode()
        self.skeptic_node = skeptic_node or SkepticValidatorNode()
        self.judge_node = judge_node or JudgeNode()

    def run(
        self,
        scan_result: ScanResult,
        repo_profile: Optional[RepoProfile] = None,
    ) -> ScanWorkflowState:
        """Build a workflow state from a finished scan result."""
        state = ScanWorkflowState(errors=list(scan_result.errors))
        state.repo_profile, profile_source = self._resolve_repo_profile(
            scan_result,
            repo_profile=repo_profile,
        )
        state.metadata["target_path"] = scan_result.target_path
        state.metadata["total_findings"] = len(scan_result.vulnerabilities)
        state.metadata["scan_profile"] = state.repo_profile.scan_profile
        state.metadata["framework_hints"] = state.repo_profile.framework_hints

        state.add_trace(
            "repo_intake",
            f"Resolved repo profile using {profile_source}.",
            metadata={
                "scan_profile": state.repo_profile.scan_profile,
                "detected_languages": state.repo_profile.detected_languages,
                "framework_hints": state.repo_profile.framework_hints,
                "analysis_plan": state.repo_profile.metadata.get("analysis_plan", {}),
            },
        )

        state.add_trace(
            "planner",
            "Prepared staged scan workflow from detector output.",
            metadata={
                "target_path": scan_result.target_path,
                "files_scanned": scan_result.files_scanned,
                "detected_languages": state.repo_profile.detected_languages,
                "scan_profile": state.repo_profile.scan_profile,
            },
        )

        state.findings = [
            vulnerability.to_normalized_finding()
            for vulnerability in scan_result.vulnerabilities
        ]
        state.add_trace(
            "normalize",
            f"Normalized {len(state.findings)} findings into a stable schema.",
            metadata={
                "languages": state.repo_profile.detected_languages,
                "vulnerability_types": sorted(
                    {finding.vulnerability_type for finding in state.findings}
                ),
            },
        )

        cards = self.knowledge_loader.load_directory()
        state.knowledge_refs = sorted(card.card_id for card in cards)
        state.metadata["knowledge_card_count"] = len(state.knowledge_refs)
        state.add_trace(
            "knowledge_loader",
            f"Loaded {len(state.knowledge_refs)} knowledge cards for triage.",
            metadata={"knowledge_card_ids": state.knowledge_refs},
        )

        raw_triage_records = self.triage_engine.triage_vulnerabilities(
            scan_result.vulnerabilities
        )
        cards_by_id = {card.card_id: card for card in cards}
        (
            state.triage_records,
            auditor_reviews,
            skeptic_reviews,
            judge_reviews,
        ) = self._run_review_nodes(
            raw_triage_records,
            cards_by_id,
            state.repo_profile,
        )
        triage_summary = self.triage_engine.summarize(state.triage_records)
        route_summary = self._summarize_routes(state.triage_records)
        auditor_summary = self._summarize_auditor_reviews(auditor_reviews)
        skeptic_summary = self._summarize_skeptic_reviews(skeptic_reviews)
        state.metadata["triage_summary"] = triage_summary
        state.metadata["route_summary"] = route_summary
        state.metadata["auditor_summary"] = auditor_summary
        state.metadata["skeptic_summary"] = skeptic_summary
        state.metadata["judge_summary"] = {
            "finalized_findings": len(judge_reviews),
        }

        state.add_trace(
            "auditor",
            f"Auditor reviewed {len(auditor_reviews)} findings.",
            metadata=auditor_summary,
        )
        state.add_trace(
            "skeptic_validator",
            f"Skeptic validator executed for {skeptic_summary['executed']} findings.",
            metadata=skeptic_summary,
        )
        state.add_trace(
            "judge",
            "Assigned final triage statuses for downstream reporting.",
            metadata={"triage_summary": triage_summary},
        )
        state.add_trace(
            "reporter",
            "Workflow state is ready for JSON, Markdown, and SARIF export.",
            metadata={"supported_formats": ["json", "markdown", "sarif"]},
        )

        return state

    def _resolve_repo_profile(
        self,
        scan_result: ScanResult,
        repo_profile: Optional[RepoProfile] = None,
    ) -> Tuple[RepoProfile, str]:
        """Resolve repo metadata from intake when possible, else fall back to findings."""
        if repo_profile is not None:
            resolved = repo_profile
            source = "provided_repo_intake"
        else:
            target = Path(scan_result.target_path)
            if target.exists():
                resolved = RepoIntake().analyze_target(target)
                source = "repo_intake"
            else:
                resolved = self._build_repo_profile_from_findings(scan_result)
                source = "scan_result_fallback"

        resolved.files_scanned = scan_result.files_scanned or resolved.files_scanned
        resolved.metadata.setdefault("actual_files_scanned", scan_result.files_scanned)
        resolved.metadata.setdefault("finding_count", len(scan_result.vulnerabilities))
        resolved.metadata["profile_source"] = source
        return resolved, source

    @staticmethod
    def _build_repo_profile_from_findings(scan_result: ScanResult) -> RepoProfile:
        """Infer a conservative repo profile from scan findings."""
        detected_languages = sorted(
            {
                language
                for language in (
                    vulnerability.to_normalized_finding().language
                    for vulnerability in scan_result.vulnerabilities
                )
                if language
            }
        )
        if not detected_languages:
            inferred = RepoIntake.infer_language_from_target(scan_result.target_path)
            if inferred:
                detected_languages.append(inferred)

        return RepoProfile(
            target_path=scan_result.target_path,
            scan_profile=RepoIntake.choose_scan_profile(detected_languages),
            detected_languages=detected_languages,
            files_scanned=scan_result.files_scanned,
            metadata={
                "error_count": len(scan_result.errors),
                "finding_count": len(scan_result.vulnerabilities),
                "analysis_plan": RepoIntake.build_analysis_plan(detected_languages),
            },
        )

    @staticmethod
    def _summarize_routes(triage_records) -> Dict[str, int]:
        """Count how many findings followed each workflow route."""
        counts: Dict[str, int] = {}
        for record in triage_records:
            route = record.decision.metadata.get("workflow_route", {})
            route_id = route.get("route_id", "unknown")
            counts[route_id] = counts.get(route_id, 0) + 1
        return counts

    def _run_review_nodes(
        self,
        triage_records,
        cards_by_id,
        repo_profile: RepoProfile,
    ) -> Tuple[List, List, List, List]:
        """Run auditor, skeptic, and judge nodes on each triaged finding."""
        final_records = []
        auditor_reviews = []
        skeptic_reviews = []
        judge_reviews = []

        for record in triage_records:
            card_ids = record.decision.metadata.get("knowledge_card_ids", [])
            matched_cards = [
                cards_by_id[card_id] for card_id in card_ids if card_id in cards_by_id
            ]
            auditor_review = self.auditor_node.review(
                record,
                matched_cards,
                repo_profile,
            )
            skeptic_review = self.skeptic_node.review(
                record,
                matched_cards,
                auditor_review,
            )
            final_record, judge_review = self.judge_node.finalize(
                record,
                auditor_review,
                skeptic_review,
            )

            final_records.append(final_record)
            auditor_reviews.append(auditor_review)
            skeptic_reviews.append(skeptic_review)
            judge_reviews.append(judge_review)

        return final_records, auditor_reviews, skeptic_reviews, judge_reviews

    @staticmethod
    def _summarize_auditor_reviews(auditor_reviews) -> Dict[str, object]:
        """Return aggregate information from the auditor stage."""
        if not auditor_reviews:
            return {"reviewed": 0, "average_evidence_score": 0.0}

        average_score = sum(review.evidence_score for review in auditor_reviews) / len(
            auditor_reviews
        )
        return {
            "reviewed": len(auditor_reviews),
            "average_evidence_score": round(average_score, 3),
        }

    @staticmethod
    def _summarize_skeptic_reviews(skeptic_reviews) -> Dict[str, object]:
        """Return aggregate information from the skeptic stage."""
        executed = [review for review in skeptic_reviews if review.executed]
        with_mitigation = [
            review for review in executed if review.mitigation_signals
        ]
        return {
            "executed": len(executed),
            "skipped": len(skeptic_reviews) - len(executed),
            "mitigation_hits": len(with_mitigation),
        }

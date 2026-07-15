"""LangGraph-ready orchestration helpers for staged scan and triage flows."""

from pathlib import Path
from typing import Dict, Optional, Tuple

from aegis_sast.core.models import ScanResult
from aegis_sast.knowledge import KnowledgeLoader
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
    ):
        self.knowledge_loader = knowledge_loader or KnowledgeLoader()
        self.triage_engine = triage_engine or TriageEngine(self.knowledge_loader)

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

        state.triage_records = self.triage_engine.triage_vulnerabilities(
            scan_result.vulnerabilities
        )
        triage_summary = self.triage_engine.summarize(state.triage_records)
        route_summary = self._summarize_routes(state.triage_records)
        state.metadata["triage_summary"] = triage_summary
        state.metadata["route_summary"] = route_summary

        state.add_trace(
            "auditor",
            f"Applied evidence-aware triage to {len(state.triage_records)} findings.",
            metadata={"route_summary": route_summary},
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

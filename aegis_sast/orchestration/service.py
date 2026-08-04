"""Reusable scan orchestration service decoupled from the CLI entrypoint."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

from aegis_sast.core.config import AegisConfig, get_config, set_config
from aegis_sast.core.models import ScanResult
from aegis_sast.core.registry import get_registry
from aegis_sast.integrations import SARIFFormatter
from aegis_sast.knowledge import KnowledgeLoader
from aegis_sast.orchestration.repo_intake import RepoIntake
from aegis_sast.orchestration.state import RepoProfile, ScanWorkflowState
from aegis_sast.orchestration.workflow import ScanWorkflow
from aegis_sast.reporting.json_exporter import JSONExporter
from aegis_sast.reporting.markdown_exporter import MarkdownExporter
from aegis_sast.triage import AITriageRunner, TriageRecord

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector


@dataclass
class ScanPipelineRequest:
    """Input contract for one CLI/API-driven scan pipeline run."""

    target_path: Path
    rules_path: Optional[Path] = None
    append_rules_paths: list[Path] = field(default_factory=list)
    enable_ai_verification: bool = True
    max_analysis_depth: int = 5
    exclude_dir_names: list[str] = field(default_factory=list)
    exclude_globs: list[str] = field(default_factory=list)
    output_formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    export_reports: bool = True

    def __post_init__(self) -> None:
        """Normalize filesystem inputs and list values."""
        self.target_path = Path(self.target_path)
        self.rules_path = Path(self.rules_path) if self.rules_path is not None else None
        self.append_rules_paths = [Path(path) for path in self.append_rules_paths]
        self.exclude_dir_names = [
            value.strip()
            for value in self.exclude_dir_names
            if isinstance(value, str) and value.strip()
        ]
        self.exclude_globs = [
            value.strip()
            for value in self.exclude_globs
            if isinstance(value, str) and value.strip()
        ]
        self.output_dir = Path(self.output_dir)
        self.output_formats = [value.lower() for value in self.output_formats]


@dataclass
class ScanPipelineResult:
    """Stable result contract returned by the scan orchestration service."""

    request: ScanPipelineRequest
    config: AegisConfig
    repo_profile: RepoProfile
    scan_result: ScanResult
    supported_languages: list[str]
    import_failures: dict[str, str]
    workflow_state: Optional[ScanWorkflowState] = None
    triage_records: list[TriageRecord] = field(default_factory=list)
    workflow_metadata: dict[str, Any] = field(default_factory=dict)
    exported_reports: dict[str, Path] = field(default_factory=dict)
    ai_requested: bool = False
    ai_enabled: bool = False
    ai_error: Optional[str] = None

    @property
    def exit_code(self) -> int:
        """Return the conventional CLI exit code for the finished scan."""
        if self.scan_result.critical_count > 0:
            return 2
        if self.scan_result.total_vulnerabilities > 0:
            return 1
        return 0


class ScanPipelineService:
    """Run deterministic scan, optional AI triage, and report export."""

    def __init__(
        self,
        *,
        registry_factory: Callable[[], Any] = get_registry,
        workflow_factory: Optional[Callable[[], ScanWorkflow]] = None,
        ai_client_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.registry_factory = registry_factory
        self.workflow_factory = workflow_factory or (
            lambda: ScanWorkflow(KnowledgeLoader())
        )
        self.ai_client_factory = ai_client_factory

    def run(self, request: ScanPipelineRequest) -> ScanPipelineResult:
        """Execute the full scan pipeline for one target."""
        config = self._prepare_config(request)
        if request.enable_ai_verification and self.ai_client_factory is not None:
            config.enable_ai_verification = True
            set_config(config)
        registry = self.registry_factory()
        repo_profile = self._create_repo_profile(registry, request.target_path)
        detector = self._build_detector(request, config)
        scan_result = self._run_scan(detector, request.target_path, request)
        repo_profile.files_scanned = scan_result.files_scanned or repo_profile.files_scanned
        repo_profile.metadata.setdefault("actual_files_scanned", scan_result.files_scanned)

        ai_requested = request.enable_ai_verification
        ai_client = None
        ai_error = None
        ai_enabled = False

        if ai_requested:
            ai_client, ai_error = self._build_ai_client(config)
            ai_enabled = ai_client is not None

        workflow_state = None
        triage_records: list[TriageRecord] = []
        workflow_metadata: dict[str, Any] = {}
        if scan_result.vulnerabilities:
            workflow_state = self._run_workflow(scan_result, repo_profile)
            triage_records = list(workflow_state.triage_records)
            workflow_metadata = dict(workflow_state.metadata)
            if ai_client and triage_records:
                triage_records, workflow_metadata = self._apply_ai_triage_overlay(
                    ai_client,
                    triage_records,
                    workflow_metadata,
                )
                workflow_state.triage_records = list(triage_records)
                workflow_state.findings = [record.finding for record in triage_records]
                workflow_state.metadata = dict(workflow_metadata)

        exported_reports: dict[str, Path] = {}
        if request.export_reports:
            exported_reports = self._export_reports(
                request.output_formats,
                request.output_dir,
                scan_result,
                triage_records,
                workflow_metadata=workflow_metadata or None,
            )

        return ScanPipelineResult(
            request=request,
            config=config,
            repo_profile=repo_profile,
            scan_result=scan_result,
            supported_languages=sorted(registry.get_supported_languages()),
            import_failures=dict(registry.get_import_failures()),
            workflow_state=workflow_state,
            triage_records=triage_records,
            workflow_metadata=workflow_metadata,
            exported_reports=exported_reports,
            ai_requested=ai_requested,
            ai_enabled=ai_enabled,
            ai_error=ai_error,
        )

    @staticmethod
    def _prepare_config(request: ScanPipelineRequest) -> AegisConfig:
        """Materialize one runtime config object for the current pipeline run."""
        base_config = get_config()
        config = replace(
            base_config,
            max_analysis_depth=request.max_analysis_depth,
            enable_ai_verification=(
                base_config.enable_ai_verification and request.enable_ai_verification
            ),
            custom_rules_path=request.rules_path,
            output_formats=list(request.output_formats),
            output_dir=request.output_dir,
        )
        set_config(config)
        return config

    @staticmethod
    def _create_repo_profile(registry: Any, target: Path) -> RepoProfile:
        """Build repo intake metadata for the current target."""
        return RepoIntake(registry).analyze_target(target)

    @staticmethod
    def _build_detector(
        request: ScanPipelineRequest,
        config: AegisConfig,
    ) -> "VulnerabilityDetector":
        """Create a detector bound to one rule-engine configuration."""
        from aegis_sast.analysis.rule_engine import RuleEngine
        from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector

        rule_engine = RuleEngine(
            config.custom_rules_path,
            extra_rules_paths=request.append_rules_paths,
        )
        return VulnerabilityDetector(rule_engine, request.max_analysis_depth)

    def _run_workflow(
        self,
        scan_result: ScanResult,
        repo_profile: RepoProfile,
    ) -> ScanWorkflowState:
        """Execute the post-detection triage workflow."""
        return self.workflow_factory().run(scan_result, repo_profile=repo_profile)

    def _build_ai_client(
        self,
        config: AegisConfig,
    ) -> tuple[Any | None, Optional[str]]:
        """Return the configured AI client or a stable fallback reason."""
        if not config.enable_ai_verification:
            return None, None

        try:
            if self.ai_client_factory is not None:
                client = self.ai_client_factory()
            else:
                from aegis_sast.llm import GeminiClient

                client = GeminiClient()
        except Exception as exc:
            config.enable_ai_verification = False
            set_config(config)
            return None, str(exc)

        active_backend = getattr(client, "client", client)
        if active_backend is None or not config.enable_ai_verification:
            config.enable_ai_verification = False
            set_config(config)
            return (
                None,
                "AI verification is unavailable with the current configuration.",
            )

        return client, None

    @staticmethod
    def _run_scan(detector: Any, target: Path, request: ScanPipelineRequest) -> ScanResult:
        """Run the detector against the provided target."""
        if target.is_dir():
            return detector.analyze_directory(
                target,
                exclude_dir_names=request.exclude_dir_names,
                exclude_globs=request.exclude_globs,
            )

        start_time = datetime.now()
        vulnerabilities = detector.analyze_file(target)
        end_time = datetime.now()
        return ScanResult(
            target_path=str(target),
            start_time=start_time,
            end_time=end_time,
            vulnerabilities=vulnerabilities,
            files_scanned=1,
        )

    @staticmethod
    def _apply_ai_triage_overlay(
        ai_client: Any,
        triage_records: list[TriageRecord],
        workflow_metadata: dict[str, Any],
    ) -> tuple[list[TriageRecord], dict[str, Any]]:
        """Overlay AI review on top of deterministic triage records."""
        model_name = getattr(getattr(ai_client, "config", None), "gemini_model", None)
        runner = AITriageRunner(
            response_provider=ai_client._call_api,
            model_name=model_name,
        )
        reviewed_records = [runner.review_record(record) for record in triage_records]
        ai_triage_summary = ScanPipelineService._summarize_ai_overlay(
            triage_records,
            reviewed_records,
            model_name=model_name or "custom-provider",
        )

        updated_metadata = dict(workflow_metadata)
        updated_metadata["deterministic_triage_summary"] = dict(
            updated_metadata.get("triage_summary", {})
        )
        updated_metadata["triage_summary"] = ScanPipelineService._summarize_triage_records(
            reviewed_records
        )
        updated_metadata["ai_triage_applied"] = True
        updated_metadata["ai_model"] = model_name or "custom-provider"
        updated_metadata["ai_triage_summary"] = ai_triage_summary
        return reviewed_records, updated_metadata

    @staticmethod
    def _summarize_triage_records(triage_records: list[TriageRecord]) -> dict[str, int]:
        """Count final triage decisions by status."""
        summary = {
            "confirmed": 0,
            "likely": 0,
            "needs-review": 0,
            "suppressed": 0,
        }
        for record in triage_records:
            status = record.decision.status.value
            summary[status] = summary.get(status, 0) + 1
        return summary

    @staticmethod
    def _summarize_ai_overlay(
        base_records: list[TriageRecord],
        reviewed_records: list[TriageRecord],
        *,
        model_name: str,
    ) -> dict[str, Any]:
        """Summarize how much the AI overlay changed deterministic triage."""
        changed_status_count = 0
        changed_confidence_count = 0
        fallback_count = 0

        for base_record, reviewed_record in zip(base_records, reviewed_records, strict=False):
            if base_record.decision.status != reviewed_record.decision.status:
                changed_status_count += 1
            if abs(base_record.decision.confidence - reviewed_record.decision.confidence) > 1e-9:
                changed_confidence_count += 1
            if reviewed_record.decision.metadata.get("fallback_used"):
                fallback_count += 1

        return {
            "model": model_name,
            "findings_reviewed": len(reviewed_records),
            "changed_status_count": changed_status_count,
            "changed_confidence_count": changed_confidence_count,
            "fallback_count": fallback_count,
            "base_triage_summary": ScanPipelineService._summarize_triage_records(
                base_records
            ),
            "final_triage_summary": ScanPipelineService._summarize_triage_records(
                reviewed_records
            ),
        }

    @staticmethod
    def _export_reports(
        output_formats: list[str],
        output_dir: Path,
        scan_result: ScanResult,
        triage_records: list[TriageRecord],
        workflow_metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Path]:
        """Export reports in the requested formats and return concrete paths."""
        exported_reports: dict[str, Path] = {}

        if "json" in output_formats:
            exported_reports["json"] = JSONExporter(output_dir).export(
                scan_result,
                triage_records=triage_records,
                workflow_metadata=workflow_metadata,
            )

        if "markdown" in output_formats:
            exported_reports["markdown"] = MarkdownExporter(output_dir).export(
                scan_result,
                triage_records=triage_records,
                workflow_metadata=workflow_metadata,
            )

        if "sarif" in output_formats:
            exported_reports["sarif"] = SARIFFormatter(output_dir).export(
                scan_result,
                triage_records=triage_records,
                workflow_metadata=workflow_metadata,
            )

        return exported_reports

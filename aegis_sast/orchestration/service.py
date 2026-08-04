"""Reusable scan orchestration service decoupled from the CLI entrypoint."""

from __future__ import annotations

import asyncio
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
from aegis_sast.triage import TriageRecord

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
    output_formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    export_reports: bool = True

    def __post_init__(self) -> None:
        """Normalize filesystem inputs and list values."""
        self.target_path = Path(self.target_path)
        self.rules_path = Path(self.rules_path) if self.rules_path is not None else None
        self.append_rules_paths = [Path(path) for path in self.append_rules_paths]
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
    """Run deterministic scan, optional AI verify, triage, and report export."""

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
        registry = self.registry_factory()
        repo_profile = self._create_repo_profile(registry, request.target_path)
        detector = self._build_detector(request, config)
        scan_result = self._run_scan(detector, request.target_path)

        ai_requested = request.enable_ai_verification
        ai_client = None
        ai_error = None
        ai_enabled = False

        if ai_requested:
            ai_client, ai_error = self._build_ai_client(config)
            ai_enabled = ai_client is not None

        if ai_client and scan_result.vulnerabilities:
            asyncio.run(self._verify_all(ai_client, scan_result))

        workflow_state = None
        triage_records: list[TriageRecord] = []
        workflow_metadata: dict[str, Any] = {}
        if scan_result.vulnerabilities:
            workflow_state = self._run_workflow(scan_result, repo_profile)
            triage_records = list(workflow_state.triage_records)
            workflow_metadata = dict(workflow_state.metadata)

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
    def _run_scan(detector: Any, target: Path) -> ScanResult:
        """Run the detector against the provided target."""
        if target.is_dir():
            return detector.analyze_directory(target)

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
    async def _verify_all(ai_client: Any, scan_result: ScanResult) -> None:
        """Verify all findings concurrently with the configured AI client."""
        tasks = []
        for vulnerability in scan_result.vulnerabilities:
            tasks.append(
                ai_client.async_verify_vulnerability(
                    vuln_type=vulnerability.vuln_type,
                    source_code=vulnerability.dataflow.source.location.code_snippet,
                    dataflow_path=vulnerability.dataflow.get_path_summary(),
                    sink_code=vulnerability.dataflow.sink.location.code_snippet,
                )
            )

        results = await asyncio.gather(*tasks)
        for index, result in enumerate(results):
            scan_result.vulnerabilities[index].ai_verification = result

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

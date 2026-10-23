from pathlib import Path

from aegis_sast.api.routes import ScanPipelineRequestModel
from aegis_sast.orchestration.service import ScanPipelineRequest, ScanPipelineService
from aegis_sast.orchestration.state import RepoProfile


def test_scan_request_accepts_legacy_repo_path_alias():
    request = ScanPipelineRequestModel(repo_path="examples/vulnerable_owasp_top10.py")

    assert request.resolved_path() == "examples/vulnerable_owasp_top10.py"


def test_semgrep_empty_result_does_not_use_deterministic_detector(tmp_path, monkeypatch):
    target = tmp_path / "demo.py"
    target.write_text("user = input()\nopen(user)\n", encoding="utf-8")
    class EmptySemgrep:
        last_error = None
        config_description = "test-config"
        last_command = []
        last_match_count = 0

        def __init__(self, **kwargs):
            pass

        def run(self, target_path, *, exclude_dir_names=None, exclude_globs=None):
            return []

    class FallbackDetector:
        def analyze_file(self, target_path, project_root=None):
            raise AssertionError("deterministic detector must not run")

    monkeypatch.setattr(
        "aegis_sast.integrations.semgrep_runner.SemgrepRunner",
        EmptySemgrep,
    )

    service = ScanPipelineService()
    monkeypatch.setattr(service, "_build_detector", lambda request, config: FallbackDetector())
    monkeypatch.setattr(
        service,
        "_create_repo_profile",
        lambda registry, target_path: RepoProfile(target_path=str(target_path)),
    )
    monkeypatch.setattr(service, "registry_factory", lambda: type(
        "Registry",
        (),
        {
            "get_supported_languages": lambda self: ["python"],
            "get_import_failures": lambda self: {},
        },
    )())

    result = service.run(
        ScanPipelineRequest(
            target_path=target,
            enable_ai_verification=False,
            export_reports=False,
        )
    )

    assert result.scan_result is not None
    assert result.workflow_metadata["scan_engine_used"] == "semgrep"
    assert result.scan_result.total_vulnerabilities == 0

from datetime import datetime
from pathlib import Path

from aegis_sast.api.routes import ScanPipelineRequestModel
from aegis_sast.core.models import ScanResult
from aegis_sast.orchestration.service import ScanPipelineRequest, ScanPipelineService
from aegis_sast.orchestration.state import RepoProfile


def test_scan_request_accepts_legacy_repo_path_alias():
    request = ScanPipelineRequestModel(repo_path="examples/vulnerable_owasp_top10.py")

    assert request.resolved_path() == "examples/vulnerable_owasp_top10.py"


def test_semgrep_empty_result_uses_deterministic_detector(tmp_path, monkeypatch):
    target = tmp_path / "demo.py"
    target.write_text("user = input()\nopen(user)\n", encoding="utf-8")
    fallback_result = ScanResult(
        target_path=str(target),
        start_time=datetime.now(),
        end_time=datetime.now(),
        vulnerabilities=[],
        files_scanned=1,
    )
    calls = {"fallback": 0}

    class EmptySemgrep:
        def __init__(self, rules_path=None):
            pass

        def run(self, target_path, *, exclude_dir_names=None, exclude_globs=None):
            return []

    class FallbackDetector:
        def analyze_file(self, target_path, project_root=None):
            calls["fallback"] += 1
            assert project_root == target.parent
            return []

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
    assert calls["fallback"] == 1

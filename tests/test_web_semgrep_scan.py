"""Focused proof that the web scan contract executes Semgrep and preserves findings."""

from __future__ import annotations

import json
import importlib.util
import subprocess
from pathlib import Path

from aegis_sast.api.routes import ScanPipelineConfig, ScanPipelineRequestModel
from aegis_sast.integrations.semgrep_runner import SemgrepRunner
from aegis_sast.orchestration.service import ScanPipelineRequest, ScanPipelineService


def _load_bridge():
    script = Path(__file__).resolve().parents[1] / "scripts" / "run_scan_pipeline_json.py"
    spec = importlib.util.spec_from_file_location("run_scan_pipeline_json", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_web_scan_defaults_to_semgrep_and_executes_process(monkeypatch, tmp_path):
    target = tmp_path / "vulnerable.py"
    target.write_text("user = input()\nsubprocess.run(user, shell=True)\n", encoding="utf-8")
    calls: list[list[str]] = []

    semgrep_payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.subprocess-shell-true",
                "path": str(target),
                "start": {"line": 2, "col": 1},
                "end": {"line": 2, "col": 43},
                "fingerprint": "semgrep-fingerprint-1",
                "extra": {
                    "message": "Command execution with shell=True",
                    "severity": "ERROR",
                    "lines": "subprocess.run(user, shell=True)",
                    "metadata": {
                        "cwe": ["CWE-78"],
                        "languages": ["python"],
                    },
                },
            }
        ]
    }

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(semgrep_payload),
            stderr="",
        )

    monkeypatch.setattr("aegis_sast.integrations.semgrep_runner.subprocess.run", fake_run)
    runner = SemgrepRunner(rule_profile="auto", languages=["python"])
    matches = runner.run(str(target))

    assert calls
    assert calls[0][0] == runner.semgrep_executable
    assert calls[0][1:3] == ["scan", "--json"]
    assert "p/python" in calls[0]
    assert matches[0].check_id == "python.lang.security.audit.subprocess-shell-true"
    assert matches[0].line == 2

    service = ScanPipelineService()
    result = service.run(
        ScanPipelineRequest(
            target_path=target,
            enable_ai_verification=False,
            export_reports=False,
            scan_engine="semgrep",
        )
    )

    assert result.workflow_metadata["scan_engine_used"] == "semgrep"
    assert result.workflow_metadata["scan_fallback"] is False
    assert result.scan_result.total_vulnerabilities == 1
    finding = result.scan_result.vulnerabilities[0].to_normalized_finding()
    assert finding.rule_id == "python.lang.security.audit.subprocess-shell-true"
    assert finding.id == "semgrep-fingerprint-1"
    assert finding.file_path == str(target)
    assert finding.line_number == 2
    assert finding.severity.value == "HIGH"
    assert finding.metadata["cwe"] == ["CWE-78"]
    assert finding.evidence.sink.code_snippet


def test_web_scan_contract_defaults_to_semgrep():
    config = ScanPipelineConfig()
    assert config.scan_engine == "semgrep"
    assert config.rule_profile == "auto"

    request = ScanPipelineRequestModel(path="examples/vulnerable_express.js")
    assert request.config.scan_engine == "semgrep"

    bridge_request = _load_bridge().build_request(
        {"targetPath": "examples/vulnerable_express.js"}
    )
    assert bridge_request.scan_engine == "semgrep"
    assert bridge_request.rule_profile == "auto"


def test_web_scan_reports_deterministic_fallback_when_semgrep_fails(monkeypatch, tmp_path):
    target = tmp_path / "safe.py"
    target.write_text("value = 1\n", encoding="utf-8")

    class BrokenRunner:
        last_error = "Semgrep is not installed or was not found in PATH."
        last_command = ["semgrep", "scan"]
        config_description = "p/python"

        def __init__(self, **kwargs):
            pass

        def run(self, *args, **kwargs):
            return []

    monkeypatch.setattr(
        "aegis_sast.integrations.semgrep_runner.SemgrepRunner",
        BrokenRunner,
    )
    service = ScanPipelineService()

    class EmptyDetector:
        def analyze_file(self, target_path, project_root=None):
            return []

    monkeypatch.setattr(service, "_build_detector", lambda request, config: EmptyDetector())
    result = service.run(
        ScanPipelineRequest(
            target_path=target,
            enable_ai_verification=False,
            export_reports=False,
            scan_engine="semgrep",
        )
    )

    assert result.workflow_metadata["scan_engine_used"] == "deterministic"
    assert result.workflow_metadata["scan_fallback"] is True
    assert "not installed" in result.workflow_metadata["scan_fallback_reason"]

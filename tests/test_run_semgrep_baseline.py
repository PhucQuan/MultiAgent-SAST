"""Tests for the Semgrep baseline mini benchmark runner."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_semgrep_baseline.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("run_semgrep_baseline", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_resolve_manifest_cases_infers_default_semgrep_configs(tmp_path):
    module = _load_module()
    manifest_path = tmp_path / "cases.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "aegis-reviewed-bundle-benchmark-v1",
                "cases": [
                    {
                        "case_id": "python-command-injection",
                        "family": "COMMAND_INJECTION",
                        "target": "examples/vulnerable_rce.py",
                    },
                    {
                        "case_id": "python-ssrf-extension",
                        "family": "SSRF",
                        "target": "examples/vulnerable_ssrf.py",
                    },
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    manifest = module.load_manifest(manifest_path)
    cases = module.resolve_manifest_cases(manifest)

    assert len(cases) == 2
    assert cases[0]["semgrep_config"].name == "python_command_injection_semgrep_shape.yaml"
    assert cases[1]["semgrep_config"].name == "python_ssrf_semgrep_shape.yaml"
    assert cases[0]["target"].name == "vulnerable_rce.py"


def test_resolve_manifest_cases_honors_manifest_semgrep_config_override(tmp_path):
    module = _load_module()
    manifest_path = tmp_path / "cases.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "aegis-reviewed-bundle-benchmark-v1",
                "cases": [
                    {
                        "case_id": "python-command-injection",
                        "family": "COMMAND_INJECTION",
                        "target": "examples/vulnerable_rce.py",
                        "semgrep_config": "datasets/synthetic/rule_review_v1/seed_inputs/python_path_traversal_semgrep_shape.yaml",
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    manifest = module.load_manifest(manifest_path)
    cases = module.resolve_manifest_cases(manifest)

    assert len(cases) == 1
    assert cases[0]["semgrep_config"].name == "python_path_traversal_semgrep_shape.yaml"


def test_discover_semgrep_command_accepts_explicit_binary(monkeypatch):
    module = _load_module()

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=b"1.0.0", stderr=b"")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    command = module.discover_semgrep_command("C:/tools/semgrep.exe")

    assert command == ["C:/tools/semgrep.exe"]


def test_decode_subprocess_output_replaces_invalid_utf8_bytes():
    module = _load_module()

    decoded = module._decode_subprocess_output(b"ok\x90broken")

    assert isinstance(decoded, str)
    assert decoded.startswith("ok")


def test_load_semgrep_report_accepts_json_stdout_bytes(tmp_path):
    module = _load_module()
    report_path = tmp_path / "semgrep_report.json"
    payload = {"results": [], "errors": []}
    process_result = subprocess.CompletedProcess(
        ["semgrep"],
        0,
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
    )

    loaded = module._load_semgrep_report(report_path, process_result)

    assert loaded == payload
    assert report_path.exists()


def test_summarize_semgrep_report_counts_results_errors_and_files(tmp_path):
    module = _load_module()
    report_path = tmp_path / "semgrep_report.json"
    report = {
        "results": [
            {
                "check_id": "python.command.shell-true",
                "path": "examples/vulnerable_rce.py",
                "extra": {"severity": "ERROR"},
            },
            {
                "check_id": "python.command.shell-true",
                "path": "examples/vulnerable_rce.py",
                "extra": {"severity": "ERROR"},
            },
            {
                "check_id": "python.sqli.execute",
                "path": "examples/vulnerable_sqli.py",
                "extra": {"severity": "WARNING"},
            },
        ],
        "errors": [{"type": "ParseError", "path": "broken.py"}],
        "paths": {
            "scanned": [
                "examples/vulnerable_rce.py",
                "examples/vulnerable_sqli.py",
            ]
        },
    }

    summary = module.summarize_semgrep_report(report, report_path)

    assert summary["result_count"] == 3
    assert summary["error_count"] == 1
    assert summary["files_scanned"] == 2
    assert summary["by_check_id"]["python.command.shell-true"] == 2
    assert summary["by_severity"]["ERROR"] == 2
    assert summary["by_severity"]["WARNING"] == 1


def test_aggregate_case_results_sums_counts_and_severity(tmp_path):
    module = _load_module()
    summary = module.aggregate_case_results(
        [
            {
                "case_id": "python-command-injection",
                "family": "COMMAND_INJECTION",
                "goal": "",
                "target": "examples/vulnerable_rce.py",
                "semgrep_config": "datasets/synthetic/rule_review_v1/seed_inputs/python_command_injection_semgrep_shape.yaml",
                "command": ["semgrep"],
                "raw_report_path": "reports/benchmark/case1.json",
                "stdout_path": "reports/benchmark/case1.stdout.txt",
                "stderr_path": "reports/benchmark/case1.stderr.txt",
                "result_count": 4,
                "error_count": 0,
                "files_scanned": 1,
                "by_check_id": {"python.command.shell-true": 4},
                "by_severity": {"ERROR": 4},
                "by_path": {"examples/vulnerable_rce.py": 4},
            },
            {
                "case_id": "python-ssrf-extension",
                "family": "SSRF",
                "goal": "",
                "target": "examples/vulnerable_ssrf.py",
                "semgrep_config": "datasets/synthetic/rule_review_v1/seed_inputs/python_ssrf_semgrep_shape.yaml",
                "command": ["semgrep"],
                "raw_report_path": "reports/benchmark/case2.json",
                "stdout_path": "reports/benchmark/case2.stdout.txt",
                "stderr_path": "reports/benchmark/case2.stderr.txt",
                "result_count": 3,
                "error_count": 1,
                "files_scanned": 1,
                "by_check_id": {"python.ssrf.http-get": 3},
                "by_severity": {"ERROR": 2, "WARNING": 1},
                "by_path": {"examples/vulnerable_ssrf.py": 3},
            },
        ],
        manifest_path=tmp_path / "cases.json",
        output_dir=tmp_path / "outputs",
        semgrep_command=["semgrep"],
    )

    aggregate = summary["aggregate"]
    assert summary["case_count"] == 2
    assert aggregate["result_count"] == 7
    assert aggregate["error_count"] == 1
    assert aggregate["files_scanned"] == 2
    assert aggregate["by_family_results"]["COMMAND_INJECTION"] == 4
    assert aggregate["by_case_results"]["python-ssrf-extension"] == 3
    assert aggregate["by_severity"]["ERROR"] == 6
    assert aggregate["by_severity"]["WARNING"] == 1


def test_render_markdown_contains_aggregate_and_case_rows(tmp_path):
    module = _load_module()
    summary = {
        "manifest_path": str(tmp_path / "cases.json"),
        "output_dir": str(tmp_path / "outputs"),
        "generated_at": "2026-07-30T11:45:00",
        "semgrep_command": ["semgrep"],
        "case_count": 1,
        "cases": [
            {
                "case_id": "python-path-traversal",
                "family": "PATH_TRAVERSAL",
                "goal": "Keep path-based sink coverage visible.",
                "target": "examples/vulnerable_path_traversal.py",
                "semgrep_config": "datasets/synthetic/rule_review_v1/seed_inputs/python_path_traversal_semgrep_shape.yaml",
                "command": ["semgrep"],
                "raw_report_path": "reports/benchmark/path_traversal/semgrep_report.json",
                "stdout_path": "reports/benchmark/path_traversal/semgrep_stdout.txt",
                "stderr_path": "reports/benchmark/path_traversal/semgrep_stderr.txt",
                "result_count": 4,
                "error_count": 0,
                "files_scanned": 1,
                "by_check_id": {"python.path.read": 3, "python.path.list": 1},
                "by_severity": {"ERROR": 4},
                "by_path": {"examples/vulnerable_path_traversal.py": 4},
            }
        ],
        "aggregate": {
            "result_count": 4,
            "error_count": 0,
            "files_scanned": 1,
            "by_family_results": {"PATH_TRAVERSAL": 4},
            "by_case_results": {"python-path-traversal": 4},
            "by_severity": {"ERROR": 4},
        },
    }

    content = module.render_markdown(summary)

    assert "# Semgrep Baseline V1" in content
    assert "| Metric | Value |" in content
    assert "`python-path-traversal`" in content
    assert "Keep path-based sink coverage visible." in content
    assert "Top checks" in content

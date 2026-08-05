"""Tests for the Semgrep baseline mini benchmark runner."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_semgrep_baseline.py"
OWASP_PYTHON_SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "run_semgrep_owasp_python.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("run_semgrep_baseline", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_owasp_python_module():
    spec = importlib.util.spec_from_file_location(
        "run_semgrep_owasp_python",
        OWASP_PYTHON_SCRIPT_PATH,
    )
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


def test_owasp_python_runner_resolves_curated_rule_configs():
    module = _load_owasp_python_module()
    profile = module.resolve_profile("benchmark-python")

    resolved = module.resolve_rule_configs(
        ["COMMAND_INJECTION", "PATH_TRAVERSAL", "INSECURE_DESERIALIZATION", "SQL_INJECTION"],
        ruleset_map=profile["rulesets"],
    )

    assert set(resolved) == {
        "COMMAND_INJECTION",
        "PATH_TRAVERSAL",
        "INSECURE_DESERIALIZATION",
        "SQL_INJECTION",
    }
    assert len(resolved["COMMAND_INJECTION"]) >= 4
    assert len(resolved["PATH_TRAVERSAL"]) >= 3
    assert len(resolved["INSECURE_DESERIALIZATION"]) >= 3
    assert len(resolved["SQL_INJECTION"]) >= 4
    assert all(path.exists() for paths in resolved.values() for path in paths)


def test_owasp_python_runner_supports_code_injection_and_open_redirect():
    module = _load_owasp_python_module()
    profile = module.resolve_profile("benchmark-python")

    resolved = module.resolve_rule_configs(
        ["CODE_INJECTION", "OPEN_REDIRECT"],
        ruleset_map=profile["rulesets"],
    )

    assert set(resolved) == {"CODE_INJECTION", "OPEN_REDIRECT"}
    assert len(resolved["CODE_INJECTION"]) >= 6
    assert len(resolved["OPEN_REDIRECT"]) >= 2
    assert all(path.exists() for paths in resolved.values() for path in paths)


def test_owasp_java_runner_resolves_curated_rule_configs():
    module = _load_owasp_python_module()
    profile = module.resolve_profile("benchmark-java")

    resolved = module.resolve_rule_configs(
        ["COMMAND_INJECTION", "PATH_TRAVERSAL", "INSECURE_DESERIALIZATION", "SQL_INJECTION"],
        ruleset_map=profile["rulesets"],
    )

    assert set(resolved) == {
        "COMMAND_INJECTION",
        "PATH_TRAVERSAL",
        "INSECURE_DESERIALIZATION",
        "SQL_INJECTION",
    }
    assert len(resolved["COMMAND_INJECTION"]) >= 2
    assert len(resolved["PATH_TRAVERSAL"]) >= 2
    assert len(resolved["INSECURE_DESERIALIZATION"]) >= 4
    assert len(resolved["SQL_INJECTION"]) >= 6
    assert all(path.exists() for paths in resolved.values() for path in paths)


def test_owasp_runner_converts_semgrep_result_to_aegis_finding():
    module = _load_owasp_python_module()
    result = {
        "check_id": "python.flask.security.injection.subprocess-injection",
        "path": "D:/BenchmarkPython/testcode/BenchmarkTest00165.py",
        "start": {"line": 20, "col": 5},
        "extra": {
            "message": "Potential command injection",
            "severity": "ERROR",
            "fingerprint": "abc123",
            "lines": "subprocess.run(cmd, shell=True)",
            "metadata": {
                "cwe": ["CWE-78"],
                "owasp": ["A03:2021"],
                "references": ["https://semgrep.dev/r/example"],
                "fix": "Use an allowlist of safe commands.",
                "confidence": "HIGH",
            },
            "dataflow_trace": {
                "taint_source": [
                    "CliLoc",
                    [
                        {
                            "path": "D:/BenchmarkPython/testcode/BenchmarkTest00165.py",
                            "start": {"line": 10, "col": 12},
                        },
                        "request.args.get('cmd')",
                    ],
                ],
                "intermediate_vars": [
                    {
                        "location": {
                            "path": "D:/BenchmarkPython/testcode/BenchmarkTest00165.py",
                            "start": {"line": 15, "col": 5},
                        },
                        "content": "cmd",
                    }
                ],
                "taint_sink": [
                    "CliLoc",
                    [
                        {
                            "path": "D:/BenchmarkPython/testcode/BenchmarkTest00165.py",
                            "start": {"line": 20, "col": 5},
                        },
                        "subprocess.run(cmd, shell=True)",
                    ],
                ],
            },
        },
    }

    finding = module.semgrep_result_to_finding(
        result,
        language="python",
        family="COMMAND_INJECTION",
        finding_id="SEMGREP-00001",
        detected_at="2026-08-05T15:30:00",
    )

    assert finding["id"] == "SEMGREP-00001"
    assert finding["tool"] == "semgrep-community"
    assert finding["language"] == "python"
    assert finding["type"] == "COMMAND_INJECTION"
    assert finding["severity"] == "HIGH"
    assert finding["triage_status"] == "likely"
    assert finding["confidence"] == 0.85
    assert finding["file"].endswith("BenchmarkTest00165.py")
    assert finding["line"] == 20
    assert finding["message"] == "Potential command injection"
    assert finding["evidence"]["source"]["line"] == 10
    assert finding["evidence"]["sink"]["line"] == 20
    assert finding["evidence"]["intermediate_steps"][0]["line"] == 15
    assert finding["recommendation"] == "Use an allowlist of safe commands."
    assert finding["metadata"]["check_id"] == result["check_id"]


def test_owasp_runner_transient_family_artifact_root_is_hidden(tmp_path):
    module = _load_owasp_python_module()

    root = module.transient_family_artifact_root(tmp_path)

    assert root == tmp_path / ".family_artifacts"


def test_owasp_runner_markdown_notes_when_family_artifacts_are_not_kept():
    module = _load_owasp_python_module()
    report = {
        "scan_metadata": {
            "target": "D:/BenchmarkPython/testcode",
            "files_scanned": 101,
            "duration_seconds": 12.5,
        },
        "findings": [{"id": "SEMGREP-00001"}],
    }
    family_runs = [
        {
            "family": "COMMAND_INJECTION",
            "result_count": 10,
            "error_count": 0,
            "files_scanned": 101,
            "configs": ["rules/command.yaml"],
            "artifacts_kept": False,
            "raw_report_path": None,
            "stdout_path": None,
            "stderr_path": None,
        }
    ]

    content = module.render_markdown(
        "Semgrep BenchmarkPython (python)",
        report,
        ["COMMAND_INJECTION"],
        ["semgrep"],
        family_runs,
        score_summary=None,
    )

    assert "## Family Artifacts" in content
    assert "Per-family raw Semgrep artifacts were not kept in this run." in content

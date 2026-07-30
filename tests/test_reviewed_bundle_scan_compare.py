"""Tests for the reviewed-bundle comparison helper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "compare_reviewed_bundle_scan.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "compare_reviewed_bundle_scan",
        SCRIPT_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finding(
    finding_id: str,
    *,
    file_path: str,
    line: int,
    sink_column: int,
    vuln_type: str,
    severity: str,
    triage_status: str,
    source_pattern: str,
    source_snippet: str,
    sink_function: str,
    sink_pattern: str,
) -> dict:
    return {
        "id": finding_id,
        "file": file_path,
        "line": line,
        "type": vuln_type,
        "severity": severity,
        "triage_status": triage_status,
        "evidence": {
            "source": {
                "file": file_path,
                "line": max(line - 1, 1),
                "column": 0,
                "snippet": source_snippet,
            },
            "sink": {
                "file": file_path,
                "line": line,
                "column": sink_column,
                "snippet": f"{sink_function}(value)",
            },
        },
        "metadata": {
            "detection": {
                "source_pattern": source_pattern,
                "sink_function": sink_function,
                "sink_pattern": sink_pattern,
            }
        },
    }


def test_ensure_report_formats_keeps_json_first_and_dedupes():
    module = _load_module()
    assert module.ensure_report_formats(["markdown", "json", "sarif", "markdown"]) == [
        "json",
        "markdown",
        "sarif",
    ]


def test_build_comparison_summary_tracks_deltas_and_mismatches(tmp_path):
    module = _load_module()
    default_path = tmp_path / "default.json"
    reviewed_path = tmp_path / "reviewed.json"

    default_path.write_text(
        json.dumps(
            {
                "scan_metadata": {"target": "examples/vulnerable_rce.py", "files_scanned": 1},
                "findings": [
                    _finding(
                        "F-1",
                        file_path="examples/vulnerable_rce.py",
                        line=23,
                        sink_column=4,
                        vuln_type="COMMAND_INJECTION",
                        severity="CRITICAL",
                        triage_status="likely",
                        source_pattern="request.args.get(",
                        source_snippet="cmd = request.args.get('cmd')",
                        sink_function="os.system",
                        sink_pattern="os.system(",
                    ),
                    _finding(
                        "F-2",
                        file_path="examples/vulnerable_rce.py",
                        line=60,
                        sink_column=4,
                        vuln_type="CODE_INJECTION",
                        severity="CRITICAL",
                        triage_status="needs-review",
                        source_pattern="input(",
                        source_snippet="payload = value_from_cache",
                        sink_function="eval",
                        sink_pattern="eval(",
                    ),
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    reviewed_path.write_text(
        json.dumps(
            {
                "scan_metadata": {"target": "examples/vulnerable_rce.py", "files_scanned": 1},
                "findings": [
                    _finding(
                        "F-10",
                        file_path="examples/vulnerable_rce.py",
                        line=23,
                        sink_column=4,
                        vuln_type="COMMAND_INJECTION",
                        severity="CRITICAL",
                        triage_status="likely",
                        source_pattern="request.args.get(",
                        source_snippet="cmd = request.args.get('cmd')",
                        sink_function="os.system",
                        sink_pattern="os.system(",
                    ),
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    summary = module.build_comparison_summary(
        target=Path("examples/vulnerable_rce.py"),
        reviewed_rules=Path("reports/rule_review/command.legacy.yaml"),
        output_dir=tmp_path / "outputs",
        default_report_path=default_path,
        reviewed_report_path=reviewed_path,
        mismatch_limit=10,
    )

    assert summary["default"]["total_findings"] == 2
    assert summary["reviewed"]["total_findings"] == 1
    assert summary["comparison"]["finding_delta"] == -1
    assert summary["comparison"]["coverage_delta"] == -1
    assert summary["comparison"]["by_type_delta"]["CODE_INJECTION"] == -1
    assert summary["default"]["mismatch_count"] == 1
    assert summary["reviewed"]["mismatch_count"] == 0

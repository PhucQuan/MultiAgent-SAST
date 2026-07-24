"""Tests for the scan-report analysis helper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "analyze_scan_report.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("analyze_scan_report", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finding(
    finding_id: str,
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
                "line": max(line - 2, 1),
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


def test_summarize_report_counts_duplicates_and_patterns(tmp_path):
    module = _load_module()
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "scan_metadata": {
                    "target": "sample",
                    "files_scanned": 2,
                },
                "findings": [
                    _finding(
                        "VULN-001",
                        "app.py",
                        10,
                        4,
                        "PATH_TRAVERSAL",
                        "HIGH",
                        "likely",
                        "input(",
                        "user_path = input()",
                        "open",
                        "open(",
                    ),
                    _finding(
                        "VULN-002",
                        "app.py",
                        10,
                        4,
                        "PATH_TRAVERSAL",
                        "HIGH",
                        "likely",
                        "input(",
                        "other_path = input()",
                        "open",
                        "open(",
                    ),
                    _finding(
                        "VULN-003",
                        "worker.py",
                        30,
                        8,
                        "COMMAND_INJECTION",
                        "CRITICAL",
                        "needs-review",
                        "sys.argv",
                        "for arg in sys.argv:",
                        "subprocess.run",
                        "subprocess.run(",
                    ),
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    summary = module.summarize_report(
        module.load_report(report_path),
        report_path,
    )

    assert summary["total_findings"] == 3
    assert summary["duplicate_delta"] == 1
    assert summary["by_type"]["PATH_TRAVERSAL"] == 2
    assert summary["by_type"]["COMMAND_INJECTION"] == 1
    assert summary["by_source_pattern"]["input("] == 2
    assert summary["by_sink_function"]["open"] == 2
    assert summary["duplicate_groups"][0]["count"] == 2


def test_compare_summaries_tracks_total_and_unique_key_deltas(tmp_path):
    module = _load_module()
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"

    old_path.write_text(
        json.dumps(
            {
                "scan_metadata": {"target": "sample", "files_scanned": 1},
                "findings": [
                    _finding(
                        "VULN-001",
                        "app.py",
                        10,
                        4,
                        "PATH_TRAVERSAL",
                        "HIGH",
                        "likely",
                        "input(",
                        "path = input()",
                        "open",
                        "open(",
                    ),
                    _finding(
                        "VULN-002",
                        "app.py",
                        20,
                        4,
                        "CODE_INJECTION",
                        "CRITICAL",
                        "needs-review",
                        "sys.argv",
                        "for arg in sys.argv:",
                        "eval",
                        "eval(",
                    ),
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    new_path.write_text(
        json.dumps(
            {
                "scan_metadata": {"target": "sample", "files_scanned": 1},
                "findings": [
                    _finding(
                        "VULN-010",
                        "app.py",
                        10,
                        4,
                        "PATH_TRAVERSAL",
                        "HIGH",
                        "likely",
                        "input(",
                        "path = input()",
                        "open",
                        "open(",
                    ),
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    old_summary = module.summarize_report(module.load_report(old_path), old_path)
    new_summary = module.summarize_report(module.load_report(new_path), new_path)
    comparison = module.compare_summaries(old_summary, new_summary)

    assert comparison["finding_delta"] == -1
    assert comparison["unique_delta"] == -1
    assert len(comparison["removed_keys"]) == 1
    assert len(comparison["added_keys"]) == 0
    assert comparison["by_type_delta"]["CODE_INJECTION"] == -1


def test_find_source_pattern_mismatches_flags_unrelated_source_snippets():
    module = _load_module()
    report = {
        "findings": [
            _finding(
                "VULN-001",
                "codegen.py",
                103,
                12,
                "PATH_TRAVERSAL",
                "HIGH",
                "likely",
                "input(",
                "file_rows = list(reader)",
                "open",
                "open(",
            ),
            _finding(
                "VULN-002",
                "worker.py",
                40,
                8,
                "COMMAND_INJECTION",
                "CRITICAL",
                "needs-review",
                "sys.argv",
                "for arg in sys.argv:",
                "subprocess.run",
                "subprocess.run(",
            ),
        ]
    }

    mismatches = module.find_source_pattern_mismatches(report, limit=10)

    assert len(mismatches) == 1
    assert mismatches[0]["source_pattern"] == "input("
    assert mismatches[0]["source_snippet"] == "file_rows = list(reader)"

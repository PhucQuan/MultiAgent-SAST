"""Tests for the normalized-rule legacy exporter bridge."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "export_normalized_rules_legacy.py"
)


def _load_exporter_module():
    spec = importlib.util.spec_from_file_location("export_normalized_rules_legacy", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_export_single_normalized_rule_to_legacy_format():
    module = _load_exporter_module()
    document = {
        "schema_version": "aegis-normalized-rule-v1",
        "rule_id": "PY-CMD-SEED-001",
        "title": "Potential command injection via shell-enabled subprocess",
        "language": "python",
        "family": "COMMAND_INJECTION",
        "severity": "CRITICAL",
        "taxonomy": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
        "detection": {
            "match_mode": "semgrep-taint-subset",
            "source_patterns": [
                {
                    "pattern": "request.args.get(...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                },
                {
                    "pattern": "input(...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                },
            ],
            "sink_patterns": [
                {
                    "pattern": "subprocess.run(..., shell=True, ...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                },
                {
                    "pattern": "os.system(...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                },
            ],
            "sanitizers": [
                {
                    "pattern": "shlex.quote(...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                }
            ],
        },
        "triage": {"knowledge_refs": [], "fp_hints": [], "remediation_notes": []},
        "provenance": {
            "source": "manual-semgrep-fixture",
            "source_rule_id": "python.command-injection.subprocess-shell-true",
            "source_path": "refs/manual_rule_seeds/python_command_injection_semgrep_shape.yaml",
            "importer": "scripts/import_semgrep_subset.py",
            "snapshot_version": "unit-test",
        },
        "notes": [],
    }

    legacy_document, report = module.export_legacy_rules(document, language_filter="python")

    assert report["rules_selected"] == 1
    assert report["exported_sources"] == 2
    assert report["exported_sinks"] == 2
    assert report["exported_sanitizers"] == 1

    source_patterns = {item["pattern"] for item in legacy_document["sources"]}
    assert "request.args.get(" in source_patterns
    assert "input(" in source_patterns

    rce_patterns = {item["pattern"] for item in legacy_document["sinks"]["rce"]}
    assert "subprocess.run(" in rce_patterns
    assert "os.system(" in rce_patterns

    sanitizer_patterns = {item["pattern"] for item in legacy_document["sanitizers"]}
    assert "shlex.quote(" in sanitizer_patterns


def test_export_reports_skipped_unsupported_patterns():
    module = _load_exporter_module()
    document = {
        "schema_version": "aegis-normalized-rule-v1",
        "rule_id": "PY-CMD-SEED-REGEX",
        "title": "Pattern modes unsupported by legacy engine",
        "language": "python",
        "family": "COMMAND_INJECTION",
        "severity": "HIGH",
        "taxonomy": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
        "detection": {
            "match_mode": "semgrep-taint-subset",
            "source_patterns": [
                {
                    "pattern": "re:^input\\(",
                    "pattern_mode": "pattern-regex",
                    "exact": False,
                    "by_side_effect": False,
                }
            ],
            "sink_patterns": [
                {
                    "pattern": "$PROC.run(...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                }
            ],
            "sanitizers": [],
        },
        "triage": {"knowledge_refs": [], "fp_hints": [], "remediation_notes": []},
        "provenance": {
            "source": "manual",
            "source_rule_id": "regex-demo",
            "source_path": "manual",
            "importer": "manual",
            "snapshot_version": "unit-test",
        },
        "notes": [],
    }

    legacy_document, report = module.export_legacy_rules(document)

    assert legacy_document["sources"] == []
    assert legacy_document["sinks"]["rce"] == []
    assert len(report["skipped_patterns"]) == 2
    reasons = {item["reason"] for item in report["skipped_patterns"]}
    assert "unsupported pattern_mode pattern-regex" in reasons
    assert "pattern cannot be represented in the legacy rule engine" in reasons


def test_cli_writes_legacy_json_and_report(tmp_path):
    module = _load_exporter_module()
    input_path = tmp_path / "normalized.json"
    output_path = tmp_path / "legacy.json"
    report_path = tmp_path / "legacy_report.json"
    input_path.write_text(
        json.dumps(
            {
                "schema_version": "aegis-normalized-rule-set-v1",
                "rules": [
                    {
                        "rule_id": "PY-CMD-SEED-001",
                        "title": "Potential command injection via shell-enabled subprocess",
                        "language": "python",
                        "family": "COMMAND_INJECTION",
                        "severity": "CRITICAL",
                        "taxonomy": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
                        "detection": {
                            "match_mode": "semgrep-taint-subset",
                            "source_patterns": [
                                {
                                    "pattern": "input(...)",
                                    "pattern_mode": "pattern",
                                    "exact": True,
                                    "by_side_effect": False,
                                }
                            ],
                            "sink_patterns": [
                                {
                                    "pattern": "os.system(...)",
                                    "pattern_mode": "pattern",
                                    "exact": True,
                                    "by_side_effect": False,
                                }
                            ],
                            "sanitizers": [],
                        },
                        "triage": {
                            "knowledge_refs": [],
                            "fp_hints": [],
                            "remediation_notes": [],
                        },
                        "provenance": {
                            "source": "manual",
                            "source_rule_id": "seed",
                            "source_path": "manual",
                            "importer": "manual",
                            "snapshot_version": "unit-test",
                        },
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    exit_code = module.main(
        [
            str(input_path),
            "--output",
            str(output_path),
            "--format",
            "json",
            "--report-output",
            str(report_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["sinks"]["rce"][0]["pattern"] == "os.system("
    assert report["exported_sinks"] == 1

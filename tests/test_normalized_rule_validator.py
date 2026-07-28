"""Tests for the normalized rule validator."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_normalized_rule.py"
EXAMPLE_RULE_PATH = (
    Path(__file__).resolve().parents[1] / "rules" / "schema" / "normalized_rule.example.yaml"
)


def _load_validator_module():
    spec = importlib.util.spec_from_file_location("validate_normalized_rule", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validate_example_rule_has_no_errors_or_warnings():
    module = _load_validator_module()
    document = module.load_rule_document(EXAMPLE_RULE_PATH)

    report = module.validate_normalized_document(
        document,
        profile="python-rule-workbench-v1",
    )

    assert report["valid"] is True
    assert report["rules_checked"] == 1
    assert report["error_count"] == 0
    assert report["warning_count"] == 0


def test_validate_rule_set_reports_exact_call_warning_and_missing_source_path():
    module = _load_validator_module()
    document = {
        "schema_version": "aegis-normalized-rule-set-v1",
        "rules": [
            {
                "rule_id": "PY-CMD-AI-001",
                "title": "Potential command injection via subprocess",
                "language": "python",
                "family": "COMMAND_INJECTION",
                "severity": "HIGH",
                "taxonomy": {
                    "cwe": ["CWE-78"],
                    "owasp": ["A05:2025"],
                },
                "detection": {
                    "match_mode": "aegis-ai-draft",
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
                            "pattern": "subprocess.run(..., shell=True, ...)",
                            "pattern_mode": "pattern",
                            "exact": False,
                            "by_side_effect": False,
                        }
                    ],
                    "sanitizers": [],
                },
                "triage": {
                    "knowledge_refs": ["generic-command-injection"],
                    "fp_hints": ["constant-command-string"],
                    "remediation_notes": ["Prefer argument arrays."],
                },
                "provenance": {
                    "source": "ai-adapted",
                    "source_rule_id": "seed.command.subprocess",
                    "source_path": "",
                    "importer": "rule-workbench",
                    "snapshot_version": "draft-v1",
                },
                "notes": ["Draft adapted from a local seed."],
            }
        ],
    }

    report = module.validate_normalized_document(
        document,
        profile="python-rule-workbench-v1",
    )

    assert report["valid"] is True
    assert report["error_count"] == 0
    warning_codes = {issue["code"] for issue in report["warnings"]}
    assert "call_pattern_without_exact" in warning_codes
    assert "missing_source_path" in warning_codes


def test_validate_workbench_profile_rejects_out_of_scope_rule():
    module = _load_validator_module()
    document = {
        "schema_version": "aegis-normalized-rule-v1",
        "rule_id": "JAVA-SQL-001",
        "title": "Potential JDBC SQL injection",
        "language": "java",
        "family": "SQL_INJECTION",
        "severity": "HIGH",
        "taxonomy": {
            "cwe": ["CWE-89"],
            "owasp": ["A03:2021"],
        },
        "detection": {
            "match_mode": "semgrep-taint-subset",
            "source_patterns": [
                {
                    "pattern": "request.getParameter(...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                }
            ],
            "sink_patterns": [
                {
                    "pattern": "statement.executeQuery(...)",
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
            "source": "semgrep",
            "source_rule_id": "java.sql.seed",
            "source_path": "snapshot/java/sqli.yaml",
            "importer": "scripts/import_semgrep_subset.py",
            "snapshot_version": "unit-test",
        },
        "notes": [],
    }

    report = module.validate_normalized_document(
        document,
        profile="python-rule-workbench-v1",
    )

    assert report["valid"] is False
    error_codes = {issue["code"] for issue in report["errors"]}
    assert "out_of_scope_language" in error_codes
    assert "out_of_scope_family" in error_codes


def test_cli_writes_json_report_and_returns_nonzero_on_invalid_rule(tmp_path):
    module = _load_validator_module()
    input_path = tmp_path / "invalid_rule.json"
    output_path = tmp_path / "validation_report.json"
    input_path.write_text(
        json.dumps(
            {
                "schema_version": "aegis-normalized-rule-v1",
                "rule_id": "PY-BROKEN-001",
                "title": "Broken rule",
                "language": "python",
                "family": "COMMAND_INJECTION",
                "severity": "HIGH",
                "taxonomy": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
                "detection": {
                    "match_mode": "aegis-ai-draft",
                    "source_patterns": [],
                    "sink_patterns": [],
                    "sanitizers": [],
                },
                "triage": {
                    "knowledge_refs": [],
                    "fp_hints": [],
                    "remediation_notes": [],
                },
                "provenance": {
                    "source": "ai-adapted",
                    "source_rule_id": "seed.command",
                    "source_path": "",
                    "importer": "rule-workbench",
                    "snapshot_version": "draft-v1",
                },
                "notes": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    exit_code = module.main(
        [
            str(input_path),
            "--profile",
            "python-rule-workbench-v1",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 1
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["valid"] is False
    assert payload["error_count"] >= 2

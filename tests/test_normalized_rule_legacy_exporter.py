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


def test_merge_normalized_documents_deduplicates_rules_and_preserves_sources(tmp_path):
    module = _load_exporter_module()
    first_input = tmp_path / "first.json"
    second_input = tmp_path / "second.json"

    shared_rule = {
        "rule_id": "JAVA-CMD-001",
        "title": "Command execution from servlet input",
        "language": "java",
        "family": "COMMAND_INJECTION",
        "severity": "CRITICAL",
        "taxonomy": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
        "detection": {
            "match_mode": "semgrep-taint-subset",
            "source_patterns": [
                {
                    "pattern": "(HttpServletRequest $REQ)",
                    "pattern_mode": "pattern",
                    "exact": False,
                    "by_side_effect": False,
                }
            ],
            "sink_patterns": [
                {
                    "pattern": "Runtime.getRuntime(...).exec(...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                }
            ],
            "sanitizers": [],
        },
        "triage": {"knowledge_refs": [], "fp_hints": [], "remediation_notes": []},
        "provenance": {
            "source": "semgrep",
            "source_rule_id": "tainted-cmd-from-http-request",
            "source_path": "refs/rule_sources/semgrep-rules/java/lang/security/audit/tainted-cmd-from-http-request.yaml",
            "importer": "aegis_sast.rule_workbench.service",
            "snapshot_version": "unit-test",
        },
        "notes": [],
    }
    unique_rule = {
        "rule_id": "JAVA-PATH-001",
        "title": "File input stream from request parameter",
        "language": "java",
        "family": "PATH_TRAVERSAL",
        "severity": "CRITICAL",
        "taxonomy": {"cwe": ["CWE-22"], "owasp": ["A01:2025"]},
        "detection": {
            "match_mode": "semgrep-taint-subset",
            "source_patterns": [
                {
                    "pattern": "(HttpServletRequest $REQ)",
                    "pattern_mode": "pattern",
                    "exact": False,
                    "by_side_effect": False,
                }
            ],
            "sink_patterns": [
                {
                    "pattern": "new java.io.FileInputStream(...)",
                    "pattern_mode": "pattern",
                    "exact": True,
                    "by_side_effect": False,
                }
            ],
            "sanitizers": [],
        },
        "triage": {"knowledge_refs": [], "fp_hints": [], "remediation_notes": []},
        "provenance": {
            "source": "semgrep",
            "source_rule_id": "httpservlet-path-traversal",
            "source_path": "refs/rule_sources/semgrep-rules/java/lang/security/httpservlet-path-traversal.yaml",
            "importer": "aegis_sast.rule_workbench.service",
            "snapshot_version": "unit-test",
        },
        "notes": [],
    }

    first_input.write_text(
        json.dumps(
            {
                "schema_version": "aegis-normalized-rule-set-v1",
                "source_documents": ["refs/a.yaml"],
                "rule_count": 1,
                "rules": [shared_rule],
                "skipped_rules": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    second_input.write_text(
        json.dumps(
            {
                "schema_version": "aegis-normalized-rule-set-v1",
                "source_path": "refs/bundle-b",
                "rule_count": 2,
                "rules": [shared_rule, unique_rule],
                "skipped_rules": [{"rule_id": "ignored", "reason": "test"}],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    merged = module.merge_normalized_documents(
        [
            module.load_normalized_document(first_input),
            module.load_normalized_document(second_input),
        ],
        source_paths=[first_input, second_input],
    )

    assert merged["rule_count"] == 2
    assert merged["source_document_count"] == 2
    assert merged["source_documents"] == ["refs/a.yaml", "refs/bundle-b"]
    assert merged["skipped_rules"] == [{"rule_id": "ignored", "reason": "test"}]


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


def test_cli_accepts_multiple_inputs_and_exports_merged_legacy_json(tmp_path):
    module = _load_exporter_module()
    first_input = tmp_path / "command.json"
    second_input = tmp_path / "path.json"
    output_path = tmp_path / "legacy.json"
    report_path = tmp_path / "legacy_report.json"

    first_input.write_text(
        json.dumps(
            {
                "schema_version": "aegis-normalized-rule-set-v1",
                "rules": [
                    {
                        "rule_id": "JAVA-CMD-001",
                        "title": "Command exec",
                        "language": "java",
                        "family": "COMMAND_INJECTION",
                        "severity": "CRITICAL",
                        "taxonomy": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
                        "detection": {
                            "match_mode": "semgrep-taint-subset",
                            "source_patterns": [
                                {
                                    "pattern": "(HttpServletRequest $REQ)",
                                    "pattern_mode": "pattern",
                                    "exact": False,
                                    "by_side_effect": False,
                                }
                            ],
                            "sink_patterns": [
                                {
                                    "pattern": "Runtime.getRuntime(...).exec(...)",
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
                            "source_rule_id": "cmd",
                            "source_path": "refs/cmd.yaml",
                            "importer": "manual",
                            "snapshot_version": "unit-test",
                        },
                        "notes": [],
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    second_input.write_text(
        json.dumps(
            {
                "schema_version": "aegis-normalized-rule-set-v1",
                "rules": [
                    {
                        "rule_id": "JAVA-PATH-001",
                        "title": "Path traversal",
                        "language": "java",
                        "family": "PATH_TRAVERSAL",
                        "severity": "CRITICAL",
                        "taxonomy": {"cwe": ["CWE-22"], "owasp": ["A01:2025"]},
                        "detection": {
                            "match_mode": "semgrep-taint-subset",
                            "source_patterns": [
                                {
                                    "pattern": "(HttpServletRequest $REQ)",
                                    "pattern_mode": "pattern",
                                    "exact": False,
                                    "by_side_effect": False,
                                }
                            ],
                            "sink_patterns": [
                                {
                                    "pattern": "new java.io.FileInputStream(...)",
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
                            "source_rule_id": "path",
                            "source_path": "refs/path.yaml",
                            "importer": "manual",
                            "snapshot_version": "unit-test",
                        },
                        "notes": [],
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    exit_code = module.main(
        [
            str(first_input),
            str(second_input),
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
    assert payload["sinks"]["rce"][0]["pattern"] == "Runtime.getRuntime("
    assert payload["sinks"]["path_traversal"][0]["pattern"] == "new java.io.FileInputStream("
    assert report["exported_sinks"] == 2

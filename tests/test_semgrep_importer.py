"""Tests for the Semgrep subset importer script."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "import_semgrep_subset.py"


def _load_importer_module():
    spec = importlib.util.spec_from_file_location("import_semgrep_subset", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_normalize_semgrep_taint_rule_maps_reviewable_subset():
    module = _load_importer_module()
    document = {
        "rules": [
            {
                "id": "python.command-injection.subprocess-shell",
                "message": "Potential command injection",
                "severity": "ERROR",
                "mode": "taint",
                "languages": ["python"],
                "pattern-sources": [
                    {
                        "pattern-either": [
                            {"pattern": "request.args.get(...)"},
                            {"pattern": "input(...)"},
                        ]
                    }
                ],
                "pattern-sinks": [
                    {"pattern": "subprocess.run(..., shell=True, ...)"},
                    {"pattern": "os.system(...)"},
                ],
                "pattern-sanitizers": [
                    {"pattern": "shlex.quote(...)", "exact": True}
                ],
                "metadata": {
                    "cwe": ["CWE-78: OS Command Injection"],
                    "owasp": ["A05:2025"],
                    "fix": "Use argument arrays and keep shell disabled.",
                },
            }
        ]
    }

    normalized = module.normalize_semgrep_document(
        document,
        language_filter="python",
        provenance_source="semgrep",
        snapshot_version="unit-test",
    )

    assert normalized["schema_version"] == "aegis-normalized-rule-set-v1"
    assert normalized["rule_count"] == 1
    assert normalized["skipped_rules"] == []

    rule = normalized["rules"][0]
    assert rule["rule_id"] == "python.command-injection.subprocess-shell"
    assert rule["language"] == "python"
    assert rule["family"] == "COMMAND_INJECTION"
    assert rule["severity"] == "CRITICAL"
    assert rule["taxonomy"]["cwe"] == ["CWE-78"]
    assert rule["taxonomy"]["owasp"] == ["A05:2025"]
    assert len(rule["detection"]["source_patterns"]) == 2
    assert len(rule["detection"]["sink_patterns"]) == 2
    assert len(rule["detection"]["sanitizers"]) == 1
    assert rule["triage"]["remediation_notes"] == [
        "Use argument arrays and keep shell disabled."
    ]
    assert rule["provenance"]["source"] == "semgrep"
    assert rule["provenance"]["snapshot_version"] == "unit-test"
    assert all(entry["exact"] is True for entry in rule["detection"]["source_patterns"])
    assert all(entry["exact"] is True for entry in rule["detection"]["sink_patterns"])


def test_normalize_semgrep_document_skips_non_taint_and_unsupported_rules():
    module = _load_importer_module()
    document = {
        "rules": [
            {
                "id": "python.pattern-only.demo",
                "message": "Pattern only rule",
                "severity": "WARNING",
                "languages": ["python"],
                "pattern": "eval(...)",
            },
            {
                "id": "javascript.taint.demo",
                "message": "JavaScript only rule",
                "severity": "WARNING",
                "mode": "taint",
                "languages": ["javascript"],
                "pattern-sources": [{"pattern": "req.query.foo"}],
                "pattern-sinks": [{"pattern": "eval(...)"}],
                "metadata": {"cwe": ["CWE-79"]},
            },
            {
                "id": "python.deserialization.demo",
                "message": "Unsafe yaml load",
                "severity": "WARNING",
                "mode": "taint",
                "languages": ["python"],
                "pattern-sources": [{"pattern": "request.data"}],
                "pattern-sinks": [{"pattern": "yaml.load(...)"}],
                "metadata": {"cwe": ["CWE-502"]},
            },
        ]
    }

    normalized = module.normalize_semgrep_document(
        document,
        language_filter="python",
        limit=1,
        provenance_source="semgrep",
    )

    assert normalized["rule_count"] == 1
    assert normalized["rules"][0]["family"] == "INSECURE_DESERIALIZATION"

    skipped = {item["rule_id"]: item["reason"] for item in normalized["skipped_rules"]}
    assert skipped["python.pattern-only.demo"] == "only taint-mode rules are supported in V1"
    assert skipped["javascript.taint.demo"] == "rule language is unsupported or filtered out"


def test_importer_infers_exact_true_for_call_like_patterns_without_override():
    module = _load_importer_module()
    document = {
        "rules": [
            {
                "id": "python.command.call-like.default-exact",
                "message": "Potential command injection",
                "severity": "ERROR",
                "mode": "taint",
                "languages": ["python"],
                "pattern-sources": [{"pattern": "input(...)"}],
                "pattern-sinks": [{"pattern": "subprocess.call(..., shell=True, ...)"}],
                "metadata": {"cwe": ["CWE-78"]},
            }
        ]
    }

    normalized = module.normalize_semgrep_document(
        document,
        language_filter="python",
        provenance_source="semgrep",
    )

    rule = normalized["rules"][0]
    assert rule["detection"]["source_patterns"][0]["exact"] is True
    assert rule["detection"]["sink_patterns"][0]["exact"] is True


def test_importer_keeps_pattern_inside_sources_with_focus_metavariable():
    module = _load_importer_module()
    document = {
        "rules": [
            {
                "id": "java.spring.tainted-file-path.demo",
                "message": "Detected user input controlling a file path.",
                "severity": "ERROR",
                "mode": "taint",
                "languages": ["java"],
                "pattern-sources": [
                    {
                        "patterns": [
                            {
                                "pattern-either": [
                                    {
                                        "pattern-inside": (
                                            "$METHODNAME(..., @$REQ(...) $TYPE $SOURCE,...) {\n"
                                            "  ...\n"
                                            "}"
                                        )
                                    }
                                ]
                            },
                            {
                                "metavariable-regex": {
                                    "metavariable": "$REQ",
                                    "regex": "(RequestBody|PathVariable|RequestParam)",
                                }
                            },
                            {"focus-metavariable": "$SOURCE"},
                        ]
                    }
                ],
                "pattern-sinks": [{"pattern-either": [{"pattern": "new File(...)"}]}],
                "metadata": {"cwe": ["CWE-23: Relative Path Traversal"]},
            }
        ]
    }

    normalized = module.normalize_semgrep_document(
        document,
        language_filter="java",
        provenance_source="semgrep",
    )

    assert normalized["rule_count"] == 1
    rule = normalized["rules"][0]
    assert rule["family"] == "PATH_TRAVERSAL"
    assert len(rule["detection"]["source_patterns"]) == 1
    assert rule["detection"]["source_patterns"][0]["focus_metavariable"] == "$SOURCE"
    assert "$METHODNAME" in rule["detection"]["source_patterns"][0]["pattern"]
    assert len(rule["detection"]["sink_patterns"]) == 1


def test_importer_propagates_focus_metavariable_inside_nested_sink_group():
    module = _load_importer_module()
    document = {
        "rules": [
            {
                "id": "java.spring.file-output.demo",
                "message": "Detected user input controlling a file path.",
                "severity": "ERROR",
                "mode": "taint",
                "languages": ["java"],
                "pattern-sources": [{"pattern": "@RequestParam String path"}],
                "pattern-sinks": [
                    {
                        "patterns": [
                            {
                                "pattern-either": [
                                    {"pattern": "new FileOutputStream($FILE, ...)"},
                                    {"pattern": "ResourceUtils.getFile($FILE, ...)"},
                                ]
                            },
                            {"focus-metavariable": "$FILE"},
                        ]
                    }
                ],
                "metadata": {"cwe": ["CWE-22"]},
            }
        ]
    }

    normalized = module.normalize_semgrep_document(
        document,
        language_filter="java",
        provenance_source="semgrep",
    )

    assert normalized["rule_count"] == 1
    sink_patterns = normalized["rules"][0]["detection"]["sink_patterns"]
    assert len(sink_patterns) == 2
    assert {entry["focus_metavariable"] for entry in sink_patterns} == {"$FILE"}


def test_cli_writes_normalized_json_document(tmp_path):
    module = _load_importer_module()
    input_path = tmp_path / "semgrep_subset.json"
    output_path = tmp_path / "normalized.json"
    input_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "python.command.demo",
                        "message": "Potential command injection",
                        "severity": "ERROR",
                        "mode": "taint",
                        "languages": ["python"],
                        "pattern-sources": [{"pattern": "request.args.get(...)"}],
                        "pattern-sinks": [{"pattern": "subprocess.run(..., shell=True, ...)"}],
                        "metadata": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
                    }
                ]
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
            "--language",
            "python",
            "--format",
            "json",
            "--snapshot-version",
            "cli-test",
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["rule_count"] == 1
    assert payload["rules"][0]["provenance"]["snapshot_version"] == "cli-test"


def test_cli_accepts_directory_and_merges_multiple_semgrep_documents(tmp_path):
    module = _load_importer_module()
    input_dir = tmp_path / "semgrep_rules"
    output_path = tmp_path / "normalized_bundle.json"
    input_dir.mkdir(parents=True)

    (input_dir / "command.json").write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "python.command.demo",
                        "message": "Potential command injection",
                        "severity": "ERROR",
                        "mode": "taint",
                        "languages": ["python"],
                        "pattern-sources": [{"pattern": "request.args.get(...)"}],
                        "pattern-sinks": [{"pattern": "subprocess.run(..., shell=True, ...)"}],
                        "metadata": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (input_dir / "sql.json").write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "python.sql.demo",
                        "message": "Potential SQL injection",
                        "severity": "ERROR",
                        "mode": "taint",
                        "languages": ["python"],
                        "pattern-sources": [{"pattern": "request.form.get(...)"}],
                        "pattern-sinks": [{"pattern": "cursor.execute(...)"}],
                        "metadata": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]},
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (input_dir / "ignore.txt").write_text("not a rule document", encoding="utf-8")

    exit_code = module.main(
        [
            str(input_dir),
            "--output",
            str(output_path),
            "--language",
            "python",
            "--format",
            "json",
            "--snapshot-version",
            "dir-test",
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["rule_count"] == 2
    assert payload["source_document_count"] == 2
    assert payload["source_path"] == str(input_dir)
    assert payload["source_documents"] == [
        str(input_dir / "command.json"),
        str(input_dir / "sql.json"),
    ]
    assert {rule["rule_id"] for rule in payload["rules"]} == {
        "python.command.demo",
        "python.sql.demo",
    }
    assert {rule["provenance"]["source_path"] for rule in payload["rules"]} == {
        str(input_dir / "command.json"),
        str(input_dir / "sql.json"),
    }

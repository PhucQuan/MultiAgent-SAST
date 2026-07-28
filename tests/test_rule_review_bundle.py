"""Tests for the rule review bundle builder."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_rule_review_bundle.py"
FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_command_injection_semgrep_shape.yaml"
)
PATH_FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_path_traversal_semgrep_shape.yaml"
)
DESERIALIZATION_FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_insecure_deserialization_semgrep_shape.yaml"
)
SQLI_FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_sql_injection_semgrep_shape.yaml"
)


def _load_bundle_module():
    spec = importlib.util.spec_from_file_location("build_rule_review_bundle", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_review_bundle_writes_normalized_validation_and_legacy_outputs(tmp_path):
    module = _load_bundle_module()
    input_path = tmp_path / "seed.yaml"
    output_dir = tmp_path / "bundle"
    input_path.write_text(
        """
rules:
  - id: python.command-injection.subprocess-shell-true
    message: Potential command injection via shell-enabled subprocess
    severity: ERROR
    mode: taint
    languages: [python]
    pattern-sources:
      - pattern-either:
          - pattern: request.args.get(...)
          - pattern: input(...)
    pattern-sinks:
      - pattern: subprocess.run(..., shell=True, ...)
    pattern-sanitizers:
      - pattern: shlex.quote(...)
        exact: true
    metadata:
      cwe: [CWE-78]
      owasp: [A05:2025]
      references: [generic-command-injection]
      false_positives: [constant-command-string]
      fix: Prefer subprocess argument arrays with shell disabled.
""".strip(),
        encoding="utf-8",
    )

    result = module.build_review_bundle(
        input_path=input_path,
        output_dir=output_dir,
        language="python",
        family="COMMAND_INJECTION",
        normalized_format="json",
        validation_format="json",
        profile="python-rule-workbench-v1",
        provenance_source="manual-semgrep-fixture",
        snapshot_version="unit-test-bundle",
        legacy_format="json",
    )

    assert result["valid"] is True
    assert result["rules_checked"] == 1
    assert result["error_count"] == 0
    assert result["legacy_path"] is not None
    assert result["legacy_report_path"] is not None

    normalized_payload = json.loads(result["normalized_path"].read_text(encoding="utf-8"))
    validation_payload = json.loads(result["validation_path"].read_text(encoding="utf-8"))
    legacy_payload = json.loads(result["legacy_path"].read_text(encoding="utf-8"))
    legacy_report = json.loads(result["legacy_report_path"].read_text(encoding="utf-8"))

    assert normalized_payload["rule_count"] == 1
    assert validation_payload["valid"] is True
    assert legacy_payload["sinks"]["rce"][0]["pattern"] == "subprocess.run("
    assert legacy_report["exported_sinks"] == 1


def test_build_review_bundle_with_command_fixture_exports_extended_sink_set(tmp_path):
    module = _load_bundle_module()
    output_dir = tmp_path / "fixture_bundle"

    result = module.build_review_bundle(
        input_path=FIXTURE_PATH,
        output_dir=output_dir,
        language="python",
        family="COMMAND_INJECTION",
        normalized_format="json",
        validation_format="json",
        profile="python-rule-workbench-v1",
        provenance_source="manual-semgrep-fixture",
        snapshot_version="fixture-test",
        legacy_format="json",
    )

    assert result["valid"] is True
    assert result["warning_count"] == 0

    legacy_payload = json.loads(result["legacy_path"].read_text(encoding="utf-8"))
    sink_patterns = sorted(item["pattern"] for item in legacy_payload["sinks"]["rce"])
    assert sink_patterns == [
        "os.popen(",
        "os.system(",
        "subprocess.Popen(",
        "subprocess.call(",
        "subprocess.run(",
    ]


def test_build_review_bundle_with_path_fixture_exports_reviewed_sink_set(tmp_path):
    module = _load_bundle_module()
    output_dir = tmp_path / "path_fixture_bundle"

    result = module.build_review_bundle(
        input_path=PATH_FIXTURE_PATH,
        output_dir=output_dir,
        language="python",
        family="PATH_TRAVERSAL",
        normalized_format="json",
        validation_format="json",
        profile="python-rule-workbench-v1",
        provenance_source="manual-semgrep-fixture",
        snapshot_version="fixture-test",
        legacy_format="json",
    )

    assert result["valid"] is True
    assert result["warning_count"] == 0

    normalized_payload = json.loads(result["normalized_path"].read_text(encoding="utf-8"))
    legacy_payload = json.loads(result["legacy_path"].read_text(encoding="utf-8"))

    assert normalized_payload["rule_count"] == 2
    assert all(rule["family"] == "PATH_TRAVERSAL" for rule in normalized_payload["rules"])
    assert all("CWE-22" in rule["taxonomy"]["cwe"] for rule in normalized_payload["rules"])

    sink_patterns = sorted(item["pattern"] for item in legacy_payload["sinks"]["path_traversal"])
    assert sink_patterns == [
        "open(",
        "os.listdir(",
        "os.remove(",
        "send_file(",
    ]


def test_build_review_bundle_with_deserialization_fixture_exports_reviewed_sink_set(tmp_path):
    module = _load_bundle_module()
    output_dir = tmp_path / "deserialization_fixture_bundle"

    result = module.build_review_bundle(
        input_path=DESERIALIZATION_FIXTURE_PATH,
        output_dir=output_dir,
        language="python",
        family="INSECURE_DESERIALIZATION",
        normalized_format="json",
        validation_format="json",
        profile="python-rule-workbench-v1",
        provenance_source="manual-semgrep-fixture",
        snapshot_version="fixture-test",
        legacy_format="json",
    )

    assert result["valid"] is True
    assert result["warning_count"] == 0

    normalized_payload = json.loads(result["normalized_path"].read_text(encoding="utf-8"))
    legacy_payload = json.loads(result["legacy_path"].read_text(encoding="utf-8"))

    assert normalized_payload["rule_count"] == 2
    assert all(
        rule["family"] == "INSECURE_DESERIALIZATION" for rule in normalized_payload["rules"]
    )
    assert all("CWE-502" in rule["taxonomy"]["cwe"] for rule in normalized_payload["rules"])

    sink_patterns = sorted(item["pattern"] for item in legacy_payload["sinks"]["deserialization"])
    assert sink_patterns == [
        "pickle.loads(",
        "yaml.load(",
        "yaml.unsafe_load(",
    ]


def test_build_review_bundle_with_sqli_fixture_exports_reviewed_sink_set(tmp_path):
    module = _load_bundle_module()
    output_dir = tmp_path / "sqli_fixture_bundle"

    result = module.build_review_bundle(
        input_path=SQLI_FIXTURE_PATH,
        output_dir=output_dir,
        language="python",
        family="SQL_INJECTION",
        normalized_format="json",
        validation_format="json",
        profile="generic",
        provenance_source="manual-semgrep-fixture",
        snapshot_version="fixture-test",
        legacy_format="json",
    )

    assert result["valid"] is True
    assert result["warning_count"] == 0

    normalized_payload = json.loads(result["normalized_path"].read_text(encoding="utf-8"))
    legacy_payload = json.loads(result["legacy_path"].read_text(encoding="utf-8"))

    assert normalized_payload["rule_count"] == 2
    assert all(rule["family"] == "SQL_INJECTION" for rule in normalized_payload["rules"])
    assert all("CWE-89" in rule["taxonomy"]["cwe"] for rule in normalized_payload["rules"])

    sink_patterns = sorted(item["pattern"] for item in legacy_payload["sinks"]["sqli"])
    assert sink_patterns == [
        "execute(",
        "executemany(",
        "raw(",
    ]

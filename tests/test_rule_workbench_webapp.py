"""Tests for the minimal Rule Workbench web backend."""

from __future__ import annotations

import json
from pathlib import Path

from aegis_sast.rule_workbench.webapp import RuleWorkbenchWebApp


def _write_seed_document(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "python.command.demo",
                        "message": "Potential command injection",
                        "severity": "ERROR",
                        "mode": "taint",
                        "languages": ["python"],
                        "pattern-sources": [{"pattern": "input(...)"}],
                        "pattern-sinks": [{"pattern": "os.system(...)"}],
                        "pattern-sanitizers": [{"pattern": "shlex.quote(...)", "exact": True}],
                        "metadata": {"cwe": ["CWE-78"], "owasp": ["A05:2025"]},
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def test_build_bundle_from_payload_returns_relative_artifacts(tmp_path):
    workspace_root = tmp_path
    seed_path = (
        workspace_root
        / "datasets"
        / "synthetic"
        / "rule_review_v1"
        / "seed_inputs"
        / "command_seed.json"
    )
    _write_seed_document(seed_path)

    app = RuleWorkbenchWebApp(workspace_root=workspace_root)
    result = app.build_bundle_from_payload(
        {
            "input_path": "datasets/synthetic/rule_review_v1/seed_inputs/command_seed.json",
            "output_dir": "reports/rule_review/command_seed_bundle",
            "language": "python",
            "family": "COMMAND_INJECTION",
            "profile": "python-rule-workbench-v1",
            "provenance_source": "manual-semgrep-fixture",
            "snapshot_version": "unit-test",
            "legacy_format": "json",
        }
    )

    assert result["input_path"] == "datasets/synthetic/rule_review_v1/seed_inputs/command_seed.json"
    assert result["output_dir"] == "reports/rule_review/command_seed_bundle"
    assert result["bundle"]["valid"] is True
    assert result["bundle"]["artifacts"]["normalized"].endswith(".normalized.json")
    assert result["bundle"]["artifacts"]["legacy"].endswith(".legacy.json")

    preview = app.read_artifact(result["bundle"]["artifacts"]["normalized"])
    assert "\"rule_count\": 1" in preview["content"]
    assert preview["truncated"] is False


def test_build_draft_from_payload_returns_relative_artifacts(tmp_path):
    workspace_root = tmp_path
    seed_path = (
        workspace_root
        / "datasets"
        / "synthetic"
        / "rule_review_v1"
        / "seed_inputs"
        / "command_seed.json"
    )
    _write_seed_document(seed_path)

    app = RuleWorkbenchWebApp(workspace_root=workspace_root)
    result = app.build_draft_from_payload(
        {
            "description": "\n".join(
                [
                    "Python command injection for subprocess helpers.",
                    "Sources: input(), request.args.get()",
                    "Sinks: os.system(), subprocess.run()",
                ]
            ),
            "seed_input_path": "datasets/synthetic/rule_review_v1/seed_inputs/command_seed.json",
            "output_dir": "reports/rule_review/command_seed_draft",
            "language": "python",
            "family": "COMMAND_INJECTION",
            "profile": "python-rule-workbench-v1",
        }
    )

    assert result["seed_input_path"] == "datasets/synthetic/rule_review_v1/seed_inputs/command_seed.json"
    assert result["output_dir"] == "reports/rule_review/command_seed_draft"
    assert result["draft"]["valid"] is True
    assert result["draft"]["artifacts"]["draft"].endswith(".normalized.json")
    assert result["draft"]["artifacts"]["prompt"].endswith(".prompt.txt")

    preview = app.read_artifact(result["draft"]["artifacts"]["draft"])
    assert "\"match_mode\": \"aegis-ai-draft\"" in preview["content"]
    assert preview["truncated"] is False


def test_list_seed_inputs_reads_supported_fixture_files(tmp_path):
    workspace_root = tmp_path
    json_seed = (
        workspace_root
        / "datasets"
        / "synthetic"
        / "rule_review_v1"
        / "seed_inputs"
        / "demo_seed.json"
    )
    yaml_seed = json_seed.with_suffix(".yaml")
    ignored = json_seed.with_suffix(".txt")

    _write_seed_document(json_seed)
    yaml_seed.write_text("rules: []\n", encoding="utf-8")
    ignored.write_text("ignore me\n", encoding="utf-8")

    app = RuleWorkbenchWebApp(workspace_root=workspace_root)
    listed_paths = [item["path"] for item in app.list_seed_inputs()]
    assert listed_paths == [
        "datasets/synthetic/rule_review_v1/seed_inputs/demo_seed.json",
        "datasets/synthetic/rule_review_v1/seed_inputs/demo_seed.yaml",
    ]


def test_resolve_workspace_path_rejects_escape_attempts(tmp_path):
    app = RuleWorkbenchWebApp(workspace_root=tmp_path)

    try:
        app.resolve_workspace_path("../outside.json", must_exist=False)
    except ValueError as exc:
        assert "workspace" in str(exc).lower()
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("Expected workspace path resolution to reject path traversal.")

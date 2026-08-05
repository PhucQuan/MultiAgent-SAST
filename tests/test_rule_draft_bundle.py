"""Tests for the natural-language rule draft bundle builder."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_rule_draft_bundle.py"
FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_command_injection_semgrep_shape.yaml"
)


def _load_draft_module():
    spec = importlib.util.spec_from_file_location("build_rule_draft_bundle", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_draft_bundle_writes_prompt_context_validation_and_legacy_outputs(tmp_path):
    module = _load_draft_module()
    output_dir = tmp_path / "draft_bundle"
    description = "\n".join(
        [
            "Python command injection for shell-enabled subprocess execution.",
            "Sources: request.args.get(), input()",
            "Sinks: subprocess.run(), os.system()",
            "Sanitizers: shlex.quote()",
        ]
    )

    result = module.build_draft_bundle(
        description=description,
        seed_input_path=FIXTURE_PATH,
        output_dir=output_dir,
        language="python",
        family="COMMAND_INJECTION",
        profile="python-rule-workbench-v1",
        normalized_format="json",
        validation_format="json",
        provenance_source="ai-adapted",
        snapshot_version="unit-test-draft",
        legacy_format="json",
    )

    assert result["valid"] is True
    assert result["rules_checked"] == 1
    assert result["error_count"] == 0
    assert result["warning_count"] == 0

    draft_payload = json.loads(result["draft_path"].read_text(encoding="utf-8"))
    validation_payload = json.loads(result["validation_path"].read_text(encoding="utf-8"))
    seed_context = json.loads(result["seed_context_path"].read_text(encoding="utf-8"))
    prompt_text = result["prompt_path"].read_text(encoding="utf-8")
    legacy_payload = json.loads(result["legacy_path"].read_text(encoding="utf-8"))

    assert draft_payload["schema_version"] == "aegis-normalized-rule-v1"
    assert draft_payload["detection"]["match_mode"] == "aegis-ai-draft"
    assert draft_payload["provenance"]["source"] == "ai-adapted"
    assert "User description:" in "\n".join(draft_payload["notes"])
    assert validation_payload["valid"] is True
    assert seed_context["seed_document_kind"] == "semgrep"
    assert "subprocess.run(...)" in prompt_text
    assert "python_command_injection_semgrep_shape.yaml" in prompt_text
    assert "os.system(" in {
        item["pattern"] for item in legacy_payload["sinks"]["rce"]
    }


def test_cli_main_accepts_description_file_and_returns_zero(tmp_path):
    module = _load_draft_module()
    output_dir = tmp_path / "draft_bundle"
    description_path = tmp_path / "description.txt"
    description_path.write_text(
        "\n".join(
            [
                "Python command injection via subprocess wrappers.",
                "Sources: request.args.get(), input()",
                "Sinks: subprocess.run(), os.system()",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = module.main(
        [
            "--description-file",
            str(description_path),
            "--seed-input",
            str(FIXTURE_PATH),
            "--output-dir",
            str(output_dir),
            "--language",
            "python",
            "--family",
            "COMMAND_INJECTION",
            "--profile",
            "python-rule-workbench-v1",
        ]
    )

    assert exit_code == 0
    assert (output_dir / "python_command_injection_semgrep_shape.ai_draft.prompt.txt").exists()
    assert (output_dir / "python_command_injection_semgrep_shape.ai_draft.validation.json").exists()


def test_build_draft_bundle_accepts_utf8_bom_seed_json(tmp_path):
    module = _load_draft_module()
    seed_path = tmp_path / "command_seed.json"
    output_dir = tmp_path / "draft_bundle"
    seed_path.write_text(
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
        encoding="utf-8-sig",
    )

    result = module.build_draft_bundle(
        description="Python command injection. Sources: input() Sinks: os.system()",
        seed_input_path=seed_path,
        output_dir=output_dir,
        language="python",
        family="COMMAND_INJECTION",
        profile="python-rule-workbench-v1",
    )

    assert result["valid"] is True
    assert result["draft_path"].exists()

"""Tests for the AI triage overlay script."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from aegis_sast.triage import AITriageRunner


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_ai_triage_overlay.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("run_ai_triage_overlay", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_resolve_report_path_accepts_run_directory(tmp_path):
    module = _load_module()
    run_dir = tmp_path / "demo_run"
    run_dir.mkdir()
    report_path = run_dir / "aegis_sast_report_20260730_150000.json"
    report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")

    assert module.resolve_report_path(str(run_dir)) == report_path


def test_apply_ai_overlay_summarizes_changes_and_fallbacks():
    module = _load_module()
    responses = iter(
        [
            {
                "status": "confirmed",
                "confidence": 0.91,
                "explanation": "Strong source-to-sink evidence.",
                "recommendation": "Keep this finding visible.",
            },
            "not-json",
        ]
    )
    runner = AITriageRunner(
        response_provider=lambda _: next(responses),
        model_name="stub-model",
    )
    report = {
        "scan_metadata": {"target": "examples/vulnerable_rce.py"},
        "findings": [
            {
                "id": "VULN-001",
                "type": "COMMAND_INJECTION",
                "severity": "CRITICAL",
                "triage_status": "likely",
                "confidence": 0.7,
                "file": "examples/vulnerable_rce.py",
                "line": 23,
                "message": "Potential command injection",
                "triage_input": {
                    "schema_version": "aegis-triage-input-v1",
                    "finding": {
                        "id": "VULN-001",
                        "type": "COMMAND_INJECTION",
                        "severity": "CRITICAL",
                    },
                    "evidence": {"summary": {"path_length": 2}},
                    "guidance": {},
                    "metadata": {},
                },
            },
            {
                "id": "VULN-002",
                "type": "CODE_INJECTION",
                "severity": "CRITICAL",
                "triage_status": "needs-review",
                "confidence": 0.5,
                "file": "examples/vulnerable_rce.py",
                "line": 49,
                "message": "Potential code injection",
            },
        ],
    }

    overlay = module.apply_ai_overlay(report, runner, source_report="report.json")

    assert overlay["summary"]["findings_reviewed"] == 2
    assert overlay["summary"]["changed_status_count"] == 1
    assert overlay["summary"]["fallback_count"] == 1
    assert overlay["summary"]["legacy_input_count"] == 1
    assert overlay["summary"]["base_status_counts"]["likely"] == 1
    assert overlay["summary"]["ai_status_counts"]["confirmed"] == 1
    assert overlay["results"][0]["status_changed"] is True
    assert overlay["results"][1]["ai_triage_decision"]["metadata"]["fallback_used"] is True


def test_render_overlay_summary_includes_preview_lines():
    module = _load_module()
    overlay = {
        "source_report": "report.json",
        "summary": {
            "findings_reviewed": 1,
            "changed_status_count": 1,
            "changed_confidence_count": 1,
            "fallback_count": 0,
            "legacy_input_count": 0,
            "base_status_counts": {"likely": 1},
            "ai_status_counts": {"confirmed": 1},
        },
        "results": [
            {
                "index": 1,
                "id": "VULN-001",
                "type": "COMMAND_INJECTION",
                "file": "examples/vulnerable_rce.py",
                "line": 23,
                "base_triage_status": "likely",
                "base_confidence": 0.7,
                "ai_triage_decision": {
                    "status": "confirmed",
                    "confidence": 0.91,
                    "metadata": {"fallback_used": False},
                },
            }
        ],
    }

    rendered = module.render_overlay_summary(overlay, max_findings=3)

    assert "changed statuses: 1" in rendered
    assert "likely -> confirmed" in rendered
    assert "COMMAND_INJECTION" in rendered

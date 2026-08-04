"""Tests for the AI-assisted triage overlay runner."""

import pytest

from aegis_sast.core.models import (
    CodeLocation,
    DataFlowPath,
    Severity,
    TaintSink,
    TaintSource,
    Vulnerability,
    VulnerabilityType,
)
from aegis_sast.triage import AITriageRunner, TriageEngine


def _build_record():
    """Create one deterministic triage record that AI review can overlay."""
    source_loc = CodeLocation("app.py", 10, 1, "cmd = request.args.get('cmd')")
    step_loc = CodeLocation("app.py", 12, 1, "user_cmd = cmd")
    sink_loc = CodeLocation("app.py", 20, 1, "os.system(user_cmd)")

    vuln = Vulnerability(
        id="VULN-AI-001",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        dataflow=DataFlowPath(
            source=TaintSource(
                source_loc,
                "HTTP_PARAM",
                "cmd",
                "request.args.get",
            ),
            sink=TaintSink(
                sink_loc,
                VulnerabilityType.COMMAND_INJECTION,
                "os.system",
                "os.system(",
            ),
            intermediate_steps=[step_loc],
        ),
    )
    return TriageEngine().triage_vulnerability(vuln)


def test_ai_triage_runner_maps_json_response_to_decision():
    """The runner should accept JSON text and emit a shared decision contract."""
    record = _build_record()
    captured = {}

    def provider(prompt: str) -> str:
        captured["prompt"] = prompt
        return """```json
        {
          "status": "confirmed",
          "confidence": 0.91,
          "explanation": "The HTTP parameter reaches os.system without mitigation.",
          "recommendation": "Use a fixed argv list instead of shell execution."
        }
        ```"""

    decision = AITriageRunner(
        response_provider=provider,
        model_name="stub-triage-model",
    ).review_finding(record.finding)

    assert decision.status.value == "confirmed"
    assert decision.confidence == pytest.approx(0.91)
    assert decision.reviewer == "ai-triage-runner-v1"
    assert decision.metadata["triage_input_schema"] == "aegis-triage-input-v1"
    assert decision.metadata["model_used"] == "stub-triage-model"
    assert decision.reason_codes == ["ai-status:confirmed", "multi-step-dataflow"]
    assert decision.manual_review_required is False
    assert '"schema_version": "aegis-triage-input-v1"' in captured["prompt"]
    assert '"type": "COMMAND_INJECTION"' in captured["prompt"]


def test_ai_triage_runner_overlays_record_and_preserves_base_metadata():
    """AI review should update the finding while keeping prior triage metadata."""
    record = _build_record()
    reviewed = AITriageRunner(
        response_provider=lambda _: {
            "status": "suppressed",
            "confidence": 0.22,
            "explanation": "Context suggests the shell sink is not practically reachable.",
            "recommendation": "Keep manual review if runtime context changes.",
        },
        model_name="stub-triage-model",
    ).review_record(record)

    assert reviewed.finding.triage_status.value == "suppressed"
    assert reviewed.finding.confidence == pytest.approx(0.22)
    assert reviewed.finding.metadata["triage"]["reviewer"] == "triage-engine-v1"
    assert reviewed.finding.metadata["triage"]["ai_reviewer"] == "ai-triage-runner-v1"
    assert reviewed.finding.metadata["triage"]["ai_triage_applied"] is True
    assert (
        reviewed.finding.metadata["triage"]["deterministic_review"]["reviewer"]
        == "triage-engine-v1"
    )
    assert reviewed.finding.metadata["triage"]["ai_review"]["status"] == "suppressed"
    assert reviewed.finding.metadata["triage"]["manual_review_required"] is True
    assert "ai-status:suppressed" in reviewed.decision.reason_codes
    assert (
        reviewed.finding.metadata["triage"]["workflow_route"]["route_id"]
        == "skeptic-review"
    )


def test_ai_triage_runner_falls_back_to_existing_decision_on_invalid_response():
    """Invalid AI output should keep the deterministic triage result stable."""
    record = _build_record()
    reviewed = AITriageRunner(
        response_provider=lambda _: "not-json-at-all",
        model_name="stub-triage-model",
    ).review_record(record)

    assert reviewed.finding.triage_status == record.finding.triage_status
    assert reviewed.finding.confidence == pytest.approx(record.finding.confidence)
    assert reviewed.decision.reviewer == "ai-triage-fallback-v1"
    assert reviewed.decision.metadata["fallback_used"] is True
    assert reviewed.decision.manual_review_required is True
    assert reviewed.finding.metadata["triage"]["ai_review"]["metadata"]["fallback_used"] is True


def test_ai_triage_runner_accepts_legacy_is_vulnerable_shape():
    """Legacy AI payloads can still be mapped into normalized triage statuses."""
    record = _build_record()
    decision = AITriageRunner(
        response_provider=lambda _: {
            "is_vulnerable": False,
            "confidence": 0.1,
            "explanation": "The path is effectively mitigated.",
            "recommendation": "Suppress and document the mitigation.",
        },
        model_name="stub-triage-model",
    ).review_finding(record.finding)

    assert decision.status.value == "suppressed"
    assert decision.confidence == pytest.approx(0.1)
    assert decision.manual_review_required is True

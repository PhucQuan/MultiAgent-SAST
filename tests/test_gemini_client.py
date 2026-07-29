"""Tests for structured Gemini client behavior without real API calls."""

import pytest

from aegis_sast.ai.gemini_client import StructuredGeminiClient
from aegis_sast.ai.prompts import get_judge_structured_prompt
from aegis_sast.ai.retry import extract_json_object, parse_structured_output
from aegis_sast.ai.schemas import StructuredAIRequest
from aegis_sast.triage.schema import TriageDecision
from tests.test_agent_contracts import _ai_input


def test_structured_client_retries_invalid_json_then_parses_decision():
    calls = {"count": 0}
    triage_input = _ai_input()

    def transport(_request):
        calls["count"] += 1
        if calls["count"] == 1:
            return "not-json"
        return """
        {
          "finding_id": "F-001",
          "status": "likely",
          "confidence": 0.74,
          "vulnerability_explanation": "Observed source reaches sink.",
          "remediation_note": "Avoid shell execution.",
          "supporting_evidence": ["app.py:1 -> app.py:2"],
          "limitations": ["No runtime proof."],
          "route_taken": ["planner", "auditor", "judge"],
          "model_name": "fake-gemini"
        }
        """

    prompt = get_judge_structured_prompt(triage_input, ["planner", "auditor", "judge"])
    request = StructuredAIRequest(
        node_name="judge",
        model_name="fake-gemini",
        prompt=prompt,
        response_schema_name="TriageDecision",
    )
    result = StructuredGeminiClient(
        model_name="fake-gemini",
        transport=transport,
    ).generate_triage_decision(request=request, fallback_finding_id="F-001")

    assert result.parsed.status.value == "likely"
    assert calls["count"] == 2
    assert result.metadata.invalid_output_count == 1
    assert result.parsed.token_usage["total_tokens"] > 0


def test_structured_client_falls_back_to_needs_review_after_invalid_output():
    request = StructuredAIRequest(
        node_name="judge",
        model_name="fake-gemini",
        prompt="Return invalid output",
        response_schema_name="TriageDecision",
    )

    result = StructuredGeminiClient(
        model_name="fake-gemini",
        max_attempts=2,
        transport=lambda _request: "{}",
    ).generate_triage_decision(request=request, fallback_finding_id="F-999")

    assert result.parsed.status.value == "needs-review"
    assert result.parsed.finding_id == "F-999"
    assert result.metadata.invalid_output_count == 2
    assert result.metadata.error


def test_structured_client_normalizes_transport_errors():
    request = StructuredAIRequest(
        node_name="judge",
        model_name="fake-gemini",
        prompt="timeout",
        response_schema_name="TriageDecision",
    )

    def transport(_request):
        raise TimeoutError("synthetic timeout")

    result = StructuredGeminiClient(
        model_name="fake-gemini",
        transport=transport,
    ).generate_triage_decision(request=request, fallback_finding_id="F-001")

    assert result.parsed.status.value == "needs-review"
    assert result.metadata.api_error_count == 1
    assert "synthetic timeout" in result.parsed.limitations[0]


def test_json_extraction_accepts_markdown_fence():
    parsed = extract_json_object(
        """```json
        {"status": "confirmed"}
        ```"""
    )

    assert parsed == {"status": "confirmed"}


def test_parse_structured_output_rejects_missing_fields():
    with pytest.raises(Exception):
        parse_structured_output(TriageDecision, '{"status": "confirmed"}')

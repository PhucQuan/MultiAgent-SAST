"""Tests for Groq structured-output client behavior without real API calls."""

import json
import urllib.error

from aegis_sast.ai.groq_client import (
    DEFAULT_USER_AGENT,
    DEFAULT_GROQ_MODEL,
    GROQ_OPENAI_BASE_URL,
    StructuredGroqClient,
)
from aegis_sast.ai.prompts import get_judge_structured_prompt
from aegis_sast.ai.schemas import StructuredAIRequest
from tests.test_agent_contracts import _ai_input


def _request() -> StructuredAIRequest:
    fixture = _ai_input()
    return StructuredAIRequest(
        node_name="judge",
        model_name=DEFAULT_GROQ_MODEL,
        prompt=get_judge_structured_prompt(fixture, ["planner", "auditor", "judge"]),
        response_schema_name="TriageDecision",
    )


def test_groq_client_retries_invalid_json_then_parses_decision():
    calls = {"count": 0}

    def transport(_request):
        calls["count"] += 1
        if calls["count"] == 1:
            return "not-json"
        return json.dumps(
            {
                "finding_id": "F-001",
                "status": "likely",
                "confidence": 0.73,
                "vulnerability_explanation": "Observed source reaches sink.",
                "remediation_note": "Avoid shell execution.",
                "supporting_evidence": ["app.py:1 -> app.py:2"],
                "limitations": ["No runtime proof."],
                "route_taken": ["planner", "auditor", "judge"],
                "model_name": DEFAULT_GROQ_MODEL,
            }
        )

    result = StructuredGroqClient(transport=transport).generate_triage_decision(
        request=_request(),
        fallback_finding_id="F-001",
    )

    assert result.parsed.status.value == "likely"
    assert calls["count"] == 2
    assert result.metadata.invalid_output_count == 1


def test_groq_client_falls_back_when_api_key_missing():
    result = StructuredGroqClient(api_key=None, transport=None).generate_triage_decision(
        request=_request(),
        fallback_finding_id="F-001",
    )

    assert result.parsed.status.value == "needs-review"
    assert "GROQ_API_KEY is not set" in result.parsed.limitations[0]
    assert result.metadata.api_error_count == 1


def test_groq_http_payload_uses_openai_compatible_chat_endpoint(monkeypatch):
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc_info):
            return None

        def read(self):
            return json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "finding_id": "F-001",
                                        "status": "confirmed",
                                        "confidence": 0.91,
                                        "vulnerability_explanation": "Complete path.",
                                        "remediation_note": "Fix command execution.",
                                        "supporting_evidence": ["path"],
                                        "limitations": [],
                                        "route_taken": ["judge"],
                                    }
                                )
                            }
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 5,
                        "total_tokens": 15,
                    },
                }
            ).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["headers"] = dict(request.header_items())
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = StructuredGroqClient(
        api_key="test-key",
        timeout_seconds=7,
    ).generate_triage_decision(request=_request(), fallback_finding_id="F-001")

    assert captured["url"] == f"{GROQ_OPENAI_BASE_URL}/chat/completions"
    assert captured["timeout"] == 7
    assert captured["headers"]["Authorization"] == "Bearer test-key"
    assert captured["headers"]["User-agent"] == DEFAULT_USER_AGENT
    assert captured["headers"]["Accept"] == "application/json"
    assert captured["payload"]["response_format"] == {"type": "json_object"}
    assert captured["payload"]["messages"][1]["role"] == "user"
    assert result.parsed.status.value == "confirmed"
    assert result.metadata.token_usage.total_tokens == 15


def test_groq_http_errors_are_normalized(monkeypatch):
    def fake_urlopen(_request, timeout):
        raise urllib.error.HTTPError(
            url="https://api.groq.com/openai/v1/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = StructuredGroqClient(api_key="bad-key").generate_triage_decision(
        request=_request(),
        fallback_finding_id="F-001",
    )

    assert result.parsed.status.value == "needs-review"
    assert "Groq API HTTP 401" in result.parsed.limitations[0]


def test_groq_cloudflare_1010_error_has_actionable_message(monkeypatch):
    class FakeErrorBody:
        def read(self):
            return b"error code: 1010\n"

        def close(self):
            return None

    def fake_urlopen(_request, timeout):
        raise urllib.error.HTTPError(
            url="https://api.groq.com/openai/v1/chat/completions",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=FakeErrorBody(),
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = StructuredGroqClient(api_key="test-key").generate_triage_decision(
        request=_request(),
        fallback_finding_id="F-001",
    )

    assert result.parsed.status.value == "needs-review"
    assert "Cloudflare 1010" in result.parsed.limitations[0]
    assert "network/VPN/proxy" in result.parsed.limitations[0]

"""Groq structured-output client for AI triage."""

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Optional

from aegis_sast.ai.retry import (
    StructuredOutputError,
    parse_structured_output,
    retry_structured_call,
)
from aegis_sast.ai.schemas import StructuredAIRequest, StructuredAIResult, TokenUsage
from aegis_sast.ai.token_tracker import NodeTimer, build_execution_metadata
from aegis_sast.triage.schema import TriageDecision


GROQ_OPENAI_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "llama-3.1-8b-instant"


class StructuredGroqClient:
    """Structured-output Groq client using the OpenAI-compatible chat API."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        base_url: str = GROQ_OPENAI_BASE_URL,
        max_attempts: int = 3,
        timeout_seconds: float = 30.0,
        transport: Optional[Callable[[StructuredAIRequest], str]] = None,
    ):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model_name = model_name or os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL)
        self.base_url = base_url.rstrip("/")
        self.max_attempts = max_attempts
        self.timeout_seconds = timeout_seconds
        self.transport = transport
        self._last_usage: Optional[TokenUsage] = None

    def generate_triage_decision(
        self,
        *,
        request: StructuredAIRequest,
        fallback_finding_id: str,
    ) -> StructuredAIResult:
        """Generate and validate a structured triage decision."""
        prompt = request.prompt
        self._last_usage = None

        with NodeTimer() as timer:
            try:
                parsed, raw_text, attempts, invalid_count = retry_structured_call(
                    call=lambda: self._call_transport(request),
                    parser=lambda text: parse_structured_output(TriageDecision, text),
                    max_attempts=self.max_attempts,
                )
                if parsed.model_name is None:
                    parsed.model_name = self.model_name
                metadata = build_execution_metadata(
                    node_name=request.node_name,
                    model_name=self.model_name,
                    latency_ms=timer.latency_ms,
                    prompt=prompt,
                    completion=raw_text,
                    attempts=attempts,
                    invalid_output_count=invalid_count,
                    api_error_count=0,
                )
                if self._last_usage is not None:
                    metadata.token_usage = self._last_usage
                parsed.token_usage = metadata.token_usage.to_dict()
                parsed.latency_ms = metadata.latency_ms
                return StructuredAIResult(parsed=parsed, raw_text=raw_text, metadata=metadata)
            except Exception as exc:
                is_structured_error = isinstance(exc, StructuredOutputError)
                fallback = self._fallback_decision(fallback_finding_id, str(exc))
                metadata = build_execution_metadata(
                    node_name=request.node_name,
                    model_name=self.model_name,
                    latency_ms=timer.latency_ms,
                    prompt=prompt,
                    completion="",
                    attempts=self.max_attempts,
                    invalid_output_count=self.max_attempts if is_structured_error else 0,
                    api_error_count=0 if is_structured_error else 1,
                    error=str(exc),
                )
                fallback.token_usage = metadata.token_usage.to_dict()
                fallback.latency_ms = metadata.latency_ms
                fallback.model_name = self.model_name
                return StructuredAIResult(parsed=fallback, raw_text="", metadata=metadata)

    def _call_transport(self, request: StructuredAIRequest) -> str:
        """Call mock transport when present, otherwise call Groq."""
        if self.transport is not None:
            return self.transport(request)
        return self._call_groq_chat_completion(request)

    def _call_groq_chat_completion(self, request: StructuredAIRequest) -> str:
        """Call Groq's OpenAI-compatible chat completions endpoint."""
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY is not set")

        payload = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return only a valid JSON object matching the requested schema. "
                        "Do not include markdown fences."
                    ),
                },
                {"role": "user", "content": request.prompt},
            ],
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }
        http_request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self.timeout_seconds) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Groq API HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Groq API request failed: {exc.reason}") from exc

        self._last_usage = _usage_from_response(response_data)
        try:
            return response_data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"Groq response missing message content: {response_data}") from exc

    @staticmethod
    def _fallback_decision(finding_id: str, error: str) -> TriageDecision:
        """Return conservative fallback when Groq output fails."""
        return TriageDecision(
            finding_id=finding_id,
            status="needs-review",
            confidence=0.0,
            vulnerability_explanation="Groq structured-output validation failed.",
            remediation_note="Manual security review required before triage.",
            supporting_evidence=[],
            limitations=[error],
            route_taken=["judge", "groq-fallback"],
        )


def _usage_from_response(response_data: dict) -> Optional[TokenUsage]:
    """Extract OpenAI-compatible usage metadata from a Groq response."""
    usage = response_data.get("usage")
    if not isinstance(usage, dict):
        return None
    return TokenUsage(
        prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
        completion_tokens=int(usage.get("completion_tokens", 0) or 0),
        total_tokens=int(usage.get("total_tokens", 0) or 0),
    )

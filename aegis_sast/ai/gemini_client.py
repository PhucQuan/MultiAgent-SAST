"""
Gemini API client for vulnerability verification.

Handles communication with Google's Gemini API for AI-based analysis.
"""

import asyncio
import json
from typing import Dict, Any, Optional
from collections.abc import Callable

from tenacity import retry, stop_after_attempt, wait_exponential

from aegis_sast.core.config import get_config
from aegis_sast.core.models import AIVerification, VulnerabilityType
from aegis_sast.ai.prompts import get_verification_prompt
from aegis_sast.ai.cache_manager import CacheManager
from aegis_sast.ai.retry import (
    StructuredOutputError,
    parse_structured_output,
    retry_structured_call,
)
from aegis_sast.ai.schemas import StructuredAIRequest, StructuredAIResult
from aegis_sast.ai.token_tracker import NodeTimer, build_execution_metadata
from aegis_sast.triage.schema import TriageDecision

try:
    from google import genai
    from google.genai import types
except ImportError:  # pragma: no cover - depends on optional AI install
    genai = None
    types = None


class GeminiClient:
    """Client for Gemini API with retry logic and caching."""

    def __init__(self):
        """Initialize Gemini client."""
        self.config = get_config()
        self.cache = CacheManager()
        self.client = None

        # Configure Gemini API
        if self.config.enable_ai_verification:
            self.config.validate_ai_config()
            if self.config.enable_ai_verification:
                if genai is None or types is None:
                    raise RuntimeError(
                        "AI verification requires the optional package "
                        "'google-genai'. Install 'requirements-ai.txt' "
                        "or run with '--no-ai'."
                    )
                self.client = genai.Client(api_key=self.config.gemini_api_key)

        # Semaphore to limit concurrent API calls
        self.semaphore = asyncio.Semaphore(10)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _call_api(self, prompt: str) -> str:
        """
        Call Gemini API with retry logic.

        Args:
            prompt: The prompt to send

        Returns:
            API response text
        """
        if not self.config.enable_ai_verification or not self.client:
            raise RuntimeError("AI verification is disabled")

        response = self.client.models.generate_content(
            model=self.config.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,  # Low temperature for more deterministic analysis
                response_mime_type="application/json",
            ),
        )
        return response.text

    async def async_verify_vulnerability(
        self, vuln_type: VulnerabilityType, source_code: str, dataflow_path: list, sink_code: str
    ) -> Optional[AIVerification]:
        """Async version of verify_vulnerability."""
        async with self.semaphore:
            # Check cache first (still synchronous is fine for diskcache)
            cached_result = self.cache.get(source_code, dataflow_path, sink_code)
            if cached_result:
                return self._parse_verification_result(cached_result, from_cache=True)

            # Generate prompt
            prompt = get_verification_prompt(
                vuln_type=vuln_type,
                source_code=source_code,
                dataflow_path=dataflow_path,
                sink_code=sink_code,
            )

            try:
                # Call API in a thread pool since genai is currently blocking
                if hasattr(asyncio, "to_thread"):
                    response_text = await asyncio.to_thread(self._call_api, prompt)
                else:
                    loop = asyncio.get_event_loop()
                    response_text = await loop.run_in_executor(None, self._call_api, prompt)

                # Parse JSON response
                import re

                # Check if it's wrapped in a json codeblock
                json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
                if json_match:
                    response_text = json_match.group(1).strip()
                else:
                    # Try to extract anything looking like a JSON object if markdown blocks are missing or wrong
                    obj_match = re.search(r"(\{.*?\})", response_text, re.DOTALL)
                    if obj_match:
                        response_text = obj_match.group(1).strip()
                    else:
                        response_text = response_text.strip()

                # If still not starting with {, there's an issue
                if not response_text.startswith("{"):
                    raise ValueError(f"Gemini did not return JSON: {response_text[:50]}")

                result = json.loads(response_text)
                self.cache.set(source_code, dataflow_path, sink_code, result)
                return self._parse_verification_result(result)

            except Exception as e:
                return AIVerification(
                    is_vulnerable=True,
                    confidence=0.5,
                    explanation=f"AI verification failed: {str(e)}",
                    recommendation="Manual review required",
                    model_used=self.config.gemini_model,
                )

    def verify_vulnerability(
        self, vuln_type: VulnerabilityType, source_code: str, dataflow_path: list, sink_code: str
    ) -> Optional[AIVerification]:
        """
        Verify if a potential vulnerability is real using AI.

        Args:
            vuln_type: Type of vulnerability
            source_code: Source code snippet
            dataflow_path: List of dataflow steps
            sink_code: Sink code snippet

        Returns:
            AIVerification object or None if AI is disabled
        """
        if not self.config.enable_ai_verification:
            return None

        # Check cache first
        cached_result = self.cache.get(source_code, dataflow_path, sink_code)
        if cached_result:
            return self._parse_verification_result(cached_result, from_cache=True)

        # Generate prompt
        prompt = get_verification_prompt(
            vuln_type=vuln_type,
            source_code=source_code,
            dataflow_path=dataflow_path,
            sink_code=sink_code,
        )

        try:
            # Call API
            response_text = self._call_api(prompt)

            # Parse JSON response
            import re

            # Check if it's wrapped in a json codeblock
            json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
            if json_match:
                response_text = json_match.group(1).strip()
            else:
                # Try to extract anything looking like a JSON object if markdown blocks are missing or wrong
                obj_match = re.search(r"(\{.*?\})", response_text, re.DOTALL)
                if obj_match:
                    response_text = obj_match.group(1).strip()
                else:
                    response_text = response_text.strip()

            # If still not starting with {, there's an issue
            if not response_text.startswith("{"):
                raise ValueError(f"Gemini did not return JSON: {response_text[:50]}")

            result = json.loads(response_text)

            # Cache result
            self.cache.set(source_code, dataflow_path, sink_code, result)

            return self._parse_verification_result(result)

        except Exception as e:
            # Fallback to unknown if API fails
            return AIVerification(
                is_vulnerable=True,  # Assume vulnerable to be safe
                confidence=0.5,
                explanation=f"AI verification failed: {str(e)}",
                recommendation="Manual review required",
                model_used=self.config.gemini_model,
            )

    def _parse_verification_result(
        self, result: Dict[str, Any], from_cache: bool = False
    ) -> AIVerification:
        """
        Parse API response into AIVerification object.

        Args:
            result: Parsed JSON response
            from_cache: Whether result came from cache

        Returns:
            AIVerification object
        """
        return AIVerification(
            is_vulnerable=result.get("is_vulnerable", True),
            confidence=float(result.get("confidence", 0.8)),
            explanation=result.get("explanation", "No explanation provided"),
            recommendation=result.get("recommendation", "Review manually"),
            model_used=self.config.gemini_model + (" (cached)" if from_cache else ""),
        )


class StructuredGeminiClient:
    """Structured-output Gemini wrapper for AI triage nodes."""

    def __init__(
        self,
        *,
        model_name: str = "gemini-structured-test",
        max_attempts: int = 3,
        transport: Optional[Callable[[StructuredAIRequest], str]] = None,
    ):
        self.model_name = model_name
        self.max_attempts = max_attempts
        self.transport = transport

    def generate_triage_decision(
        self,
        *,
        request: StructuredAIRequest,
        fallback_finding_id: str,
    ) -> StructuredAIResult:
        """Generate and validate a structured triage decision."""
        prompt = request.prompt
        api_error_count = 0

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
                    api_error_count=api_error_count,
                )
                parsed.token_usage = metadata.token_usage.to_dict()
                parsed.latency_ms = metadata.latency_ms
                return StructuredAIResult(
                    parsed=parsed,
                    raw_text=raw_text,
                    metadata=metadata,
                )
            except Exception as exc:
                api_error_count = 0 if isinstance(exc, StructuredOutputError) else 1
                raw_text = ""
                fallback = self._fallback_decision(fallback_finding_id, str(exc))
                metadata = build_execution_metadata(
                    node_name=request.node_name,
                    model_name=self.model_name,
                    latency_ms=timer.latency_ms,
                    prompt=prompt,
                    completion=raw_text,
                    attempts=self.max_attempts,
                    invalid_output_count=(
                        self.max_attempts if isinstance(exc, StructuredOutputError) else 0
                    ),
                    api_error_count=api_error_count,
                    error=str(exc),
                )
                fallback.token_usage = metadata.token_usage.to_dict()
                fallback.latency_ms = metadata.latency_ms
                fallback.model_name = self.model_name
                return StructuredAIResult(
                    parsed=fallback,
                    raw_text=raw_text,
                    metadata=metadata,
                )

    def _call_transport(self, request: StructuredAIRequest) -> str:
        """Call the configured transport or raise a normalized setup error."""
        if self.transport is None:
            raise RuntimeError("Structured Gemini transport is not configured")
        return self.transport(request)

    @staticmethod
    def _fallback_decision(finding_id: str, error: str) -> TriageDecision:
        """Return a conservative fallback when structured output fails."""
        return TriageDecision(
            finding_id=finding_id,
            status="needs-review",
            confidence=0.0,
            vulnerability_explanation="AI structured-output validation failed.",
            remediation_note="Manual security review required before triage.",
            supporting_evidence=[],
            limitations=[error],
            route_taken=["judge", "fallback"],
        )

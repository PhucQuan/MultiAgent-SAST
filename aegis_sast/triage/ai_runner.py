"""AI-assisted triage overlay built on the stable triage_input contract."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Callable, Dict, Optional

from aegis_sast.core.models import NormalizedFinding, TriageStatus
from aegis_sast.triage.schema import TriageDecision, TriageRecord


ResponseProvider = Callable[[str], Any]


class AITriageRunner:
    """Run an optional AI review over normalized findings and triage records."""

    def __init__(
        self,
        response_provider: Optional[ResponseProvider] = None,
        model_name: Optional[str] = None,
        reviewer: str = "ai-triage-runner-v1",
    ):
        self.response_provider = response_provider
        self.model_name = model_name
        self.reviewer = reviewer
        self._default_client = None

    def review_finding(self, finding: NormalizedFinding) -> TriageDecision:
        """Review one normalized finding using its stable triage_input payload."""
        return self.review_triage_input(
            finding.to_triage_input(),
            fallback_status=finding.triage_status,
            fallback_confidence=finding.confidence,
            fallback_explanation=finding.explanation or finding.message,
            fallback_recommendation=finding.recommendation,
        )

    def review_record(self, record: TriageRecord) -> TriageRecord:
        """Apply AI review to an existing triage record without mutating the input."""
        decision = self.review_finding(record.finding)
        updated_finding = deepcopy(record.finding)

        triage_metadata = updated_finding.metadata.setdefault("triage", {})
        triage_metadata.setdefault("deterministic_review", record.decision.to_dict())
        triage_metadata["ai_triage_applied"] = True
        triage_metadata["ai_reviewer"] = decision.reviewer
        triage_metadata["ai_review"] = decision.to_dict()
        triage_metadata["final_status"] = decision.status.value
        triage_metadata["final_confidence"] = decision.confidence
        triage_metadata["reason_codes"] = decision.reason_codes
        triage_metadata["evidence_summary"] = decision.evidence_summary
        triage_metadata["manual_review_required"] = decision.manual_review_required
        if decision.metadata.get("model_used"):
            triage_metadata["ai_model"] = decision.metadata["model_used"]

        updated_finding.triage_status = decision.status
        updated_finding.confidence = decision.confidence
        if decision.explanation:
            updated_finding.explanation = decision.explanation
        if decision.recommendation:
            updated_finding.recommendation = decision.recommendation
        updated_finding.metadata["reason_codes"] = decision.reason_codes
        updated_finding.metadata["manual_review_required"] = decision.manual_review_required

        return TriageRecord(finding=updated_finding, decision=decision)

    def review_triage_input(
        self,
        triage_input: Dict[str, Any],
        *,
        fallback_status: Optional[TriageStatus] = None,
        fallback_confidence: Optional[float] = None,
        fallback_explanation: Optional[str] = None,
        fallback_recommendation: Optional[str] = None,
    ) -> TriageDecision:
        """Review a raw triage_input payload and return a structured decision."""
        prompt = self.build_prompt(triage_input)
        provider = self.response_provider or self._call_default_provider

        try:
            payload = self._parse_response(provider(prompt))
            return self._build_decision(payload, triage_input)
        except Exception as exc:
            return self._build_fallback_decision(
                triage_input,
                error=str(exc),
                fallback_status=fallback_status,
                fallback_confidence=fallback_confidence,
                fallback_explanation=fallback_explanation,
                fallback_recommendation=fallback_recommendation,
            )

    @staticmethod
    def build_prompt(triage_input: Dict[str, Any]) -> str:
        """Build a conservative prompt around the stable triage_input contract."""
        payload = json.dumps(triage_input, indent=2, ensure_ascii=False)
        return f"""You are reviewing one static-analysis finding after deterministic detection.

Use only the evidence in triage_input. Do not invent missing source code, sanitizers, or exploitability facts.
If the evidence is ambiguous, return "needs-review".

Return ONLY valid JSON in this exact shape:
{{
  "status": "confirmed" | "likely" | "needs-review" | "suppressed",
  "confidence": 0.0 to 1.0,
  "explanation": "short technical justification",
  "recommendation": "short remediation or manual-review guidance"
}}

Decision guidance:
- confirmed: strong evidence of a real vulnerability
- likely: suspicious and mostly convincing, but still somewhat ambiguous
- needs-review: insufficient evidence to decide safely
- suppressed: strong evidence of effective mitigation or false positive

triage_input:
{payload}
"""

    def _call_default_provider(self, prompt: str) -> Any:
        """Lazily call the default Gemini-backed provider when configured."""
        from aegis_sast.llm import GeminiClient

        if self._default_client is None:
            self._default_client = GeminiClient()
        if self.model_name is None:
            self.model_name = self._default_client.config.gemini_model
        return self._default_client._call_api(prompt)

    def _build_decision(
        self,
        payload: Dict[str, Any],
        triage_input: Dict[str, Any],
    ) -> TriageDecision:
        """Convert parsed AI JSON into the shared triage decision schema."""
        confidence = self._coerce_confidence(payload.get("confidence", 0.5))
        raw_status = payload.get("status")
        status = self._coerce_status(raw_status, payload, confidence)
        explanation = (
            str(payload.get("explanation", "")).strip()
            or "AI triage did not provide an explanation."
        )
        recommendation = str(payload.get("recommendation", "")).strip() or None
        evidence_summary = self._extract_evidence_summary(triage_input)
        reason_codes = self._build_reason_codes(
            status,
            triage_input,
            fallback_used=False,
        )
        manual_review_required = self._manual_review_required(
            status,
            triage_input,
            fallback_used=False,
        )

        return TriageDecision(
            status=status,
            confidence=confidence,
            explanation=explanation,
            recommendation=recommendation,
            reviewer=self.reviewer,
            reason_codes=reason_codes,
            evidence_summary=evidence_summary,
            manual_review_required=manual_review_required,
            evidence_notes=[
                f"triage_input_schema={triage_input.get('schema_version', 'unknown')}",
                f"ai_status={status.value}",
                f"ai_confidence={confidence:.2f}",
            ],
            metadata={
                "triage_input_schema": triage_input.get("schema_version"),
                "model_used": self.model_name or "custom-provider",
                "provider": (
                    "gemini-default"
                    if self.response_provider is None
                    else "custom-response-provider"
                ),
                "fallback_used": False,
                "raw_status": raw_status,
                "reason_codes": reason_codes,
                "evidence_summary": evidence_summary,
                "manual_review_required": manual_review_required,
            },
        )

    def _build_fallback_decision(
        self,
        triage_input: Dict[str, Any],
        *,
        error: str,
        fallback_status: Optional[TriageStatus],
        fallback_confidence: Optional[float],
        fallback_explanation: Optional[str],
        fallback_recommendation: Optional[str],
    ) -> TriageDecision:
        """Return a conservative fallback when AI review fails or is unavailable."""
        status = fallback_status or TriageStatus.NEEDS_REVIEW
        confidence = self._coerce_confidence(
            0.5 if fallback_confidence is None else fallback_confidence
        )
        explanation = (
            fallback_explanation
            or "AI triage returned an invalid structured response. Keep the current review result."
        )
        recommendation = fallback_recommendation or "Manual review recommended."
        evidence_summary = self._extract_evidence_summary(triage_input)
        reason_codes = self._build_reason_codes(
            status,
            triage_input,
            fallback_used=True,
        )
        manual_review_required = self._manual_review_required(
            status,
            triage_input,
            fallback_used=True,
        )

        return TriageDecision(
            status=status,
            confidence=confidence,
            explanation=explanation,
            recommendation=recommendation,
            reviewer="ai-triage-fallback-v1",
            reason_codes=reason_codes,
            evidence_summary=evidence_summary,
            manual_review_required=manual_review_required,
            evidence_notes=[
                f"triage_input_schema={triage_input.get('schema_version', 'unknown')}",
                "ai_fallback=true",
            ],
            metadata={
                "triage_input_schema": triage_input.get("schema_version"),
                "model_used": self.model_name or "custom-provider",
                "provider": (
                    "gemini-default"
                    if self.response_provider is None
                    else "custom-response-provider"
                ),
                "fallback_used": True,
                "error": error,
                "reason_codes": reason_codes,
                "evidence_summary": evidence_summary,
                "manual_review_required": manual_review_required,
            },
        )

    @staticmethod
    def _parse_response(response: Any) -> Dict[str, Any]:
        """Parse a dict or JSON string response from an AI provider."""
        if isinstance(response, dict):
            return response

        if not isinstance(response, str):
            raise TypeError("AI triage response must be a dict or JSON string.")

        text = response.strip()
        fenced_json = re.search(r"```json\s*(.*?)\s*```", text, re.IGNORECASE | re.DOTALL)
        if fenced_json:
            text = fenced_json.group(1).strip()
        elif text.startswith("```"):
            fenced_block = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
            if fenced_block:
                text = fenced_block.group(1).strip()

        if not text.startswith("{"):
            json_object = re.search(r"(\{.*\})", text, re.DOTALL)
            if json_object:
                text = json_object.group(1).strip()

        if not text.startswith("{"):
            raise ValueError("AI triage returned an invalid structured response.")

        return json.loads(text)

    @staticmethod
    def _coerce_confidence(raw_value: Any) -> float:
        """Clamp confidence into a stable 0.0-1.0 range."""
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            value = 0.5
        return max(0.0, min(value, 1.0))

    @staticmethod
    def _coerce_status(
        raw_status: Any,
        payload: Dict[str, Any],
        confidence: float,
    ) -> TriageStatus:
        """Map AI output into the normalized triage status enum."""
        normalized = (
            str(raw_status or "")
            .strip()
            .lower()
            .replace("_", "-")
            .replace(" ", "-")
        )
        aliases = {
            "confirmed": TriageStatus.CONFIRMED,
            "true-positive": TriageStatus.CONFIRMED,
            "tp": TriageStatus.CONFIRMED,
            "likely": TriageStatus.LIKELY,
            "needs-review": TriageStatus.NEEDS_REVIEW,
            "needsreview": TriageStatus.NEEDS_REVIEW,
            "review": TriageStatus.NEEDS_REVIEW,
            "suppressed": TriageStatus.SUPPRESSED,
            "false-positive": TriageStatus.SUPPRESSED,
            "fp": TriageStatus.SUPPRESSED,
        }
        if normalized in aliases:
            return aliases[normalized]

        if "is_vulnerable" in payload:
            raw_is_vulnerable = payload.get("is_vulnerable")
            if isinstance(raw_is_vulnerable, str):
                is_vulnerable = raw_is_vulnerable.strip().lower() in {
                    "1",
                    "true",
                    "yes",
                    "y",
                }
            else:
                is_vulnerable = bool(raw_is_vulnerable)
            if not is_vulnerable:
                return TriageStatus.SUPPRESSED
            return (
                TriageStatus.CONFIRMED
                if confidence >= 0.85
                else TriageStatus.LIKELY
            )

        raise ValueError(f"Unsupported AI triage status: {raw_status!r}")

    @staticmethod
    def _extract_evidence_summary(triage_input: Dict[str, Any]) -> Dict[str, Any]:
        """Project the triage_input evidence summary into a stable decision field."""
        evidence = triage_input.get("evidence", {})
        summary = dict(evidence.get("summary", {}))
        graph_slice = evidence.get("graph_slice")
        if isinstance(graph_slice, dict) and graph_slice:
            summary["graph_slice"] = graph_slice
        return summary

    @staticmethod
    def _build_reason_codes(
        status: TriageStatus,
        triage_input: Dict[str, Any],
        *,
        fallback_used: bool,
    ) -> list[str]:
        """Attach compact reason codes for downstream dashboards and reporting."""
        evidence_summary = triage_input.get("evidence", {}).get("summary", {})
        codes = [f"ai-status:{status.value}"]
        if fallback_used:
            codes.append("ai-fallback")
        if evidence_summary.get("has_sanitizers"):
            codes.append("has-sanitizers")
        if evidence_summary.get("intermediate_step_count", 0) > 0:
            codes.append("multi-step-dataflow")
        if triage_input.get("evidence", {}).get("graph_slice"):
            codes.append("graph-context-available")
        return list(dict.fromkeys(code for code in codes if code))

    @staticmethod
    def _manual_review_required(
        status: TriageStatus,
        triage_input: Dict[str, Any],
        *,
        fallback_used: bool,
    ) -> bool:
        """Keep manual-review escalation conservative for UI and report consumers."""
        severity = str(
            triage_input.get("finding", {}).get("severity", "")
        ).upper()
        high_risk = severity in {"CRITICAL", "HIGH"}
        return (
            status == TriageStatus.NEEDS_REVIEW
            or fallback_used
            or (status == TriageStatus.SUPPRESSED and high_risk)
        )

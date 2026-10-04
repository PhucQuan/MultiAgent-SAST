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
        self._default_provider_name = None

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
        if decision.metadata.get("agent_reviews"):
            triage_metadata["agent_reviews"] = decision.metadata["agent_reviews"]
            updated_finding.metadata["agent_reviews"] = decision.metadata["agent_reviews"]
        if decision.metadata.get("remediation_patch"):
            triage_metadata["remediation_patch"] = decision.metadata["remediation_patch"]
            updated_finding.metadata["remediation_patch"] = decision.metadata["remediation_patch"]

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
        """Build a conservative prompt using the Multi-Agent debate protocol."""
        payload = json.dumps(triage_input, indent=2, ensure_ascii=False)
        return f"""You are an advanced AI Security Engine performing Multi-Agent Triage on a static analysis finding.

Simulate three specialized security agents debating this finding:
1. Auditor Agent (Offensive Penetration Tester): Analyzes data flow reachability, exploit scenario, and payload feasibility.
2. Skeptic Agent (Defensive Code Reviewer): Searches for sanitizers, type guards, allowlists, or early returns that render the finding a False Positive.
3. Judge Agent (Security Lead): Evaluates the debate between Auditor and Skeptic, assigns the final verdict status, and generates a concrete remediation patch.

Return ONLY valid JSON in this exact shape:
{{
  "status": "confirmed" | "likely" | "needs-review" | "suppressed",
  "confidence": 0.0 to 1.0,
  "explanation": "concise technical justification summarizing the verdict",
  "recommendation": "actionable remediation guidance",
  "auditor_analysis": {{
    "attack_vector": "how untrusted data travels from source to sink",
    "hypothesized_payload": "example payload that triggers the issue",
    "security_impact": "impact on application and infrastructure"
  }},
  "skeptic_analysis": {{
    "sanitizer_detected": false,
    "defense_evaluation": "analysis of validation, type casts, or lack thereof",
    "objections": ["any reasons why this might be a false positive"]
  }},
  "remediation_patch": {{
    "vulnerable_snippet": "vulnerable line of code",
    "secure_snippet": "secure replacement line(s)",
    "explanation": "why this fix prevents exploitation"
  }}
}}

Decision guidance:
- confirmed: strong evidence of an unmitigated vulnerability reaching sink
- likely: suspicious flow with high likelihood of exploitability
- needs-review: ambiguous context or incomplete call graph
- suppressed: verified sanitizer, type cast, or safe constant in dataflow (False Positive)

triage_input:
{payload}
"""

    def _call_default_provider(self, prompt: str) -> Any:
        """Lazily call the configured default provider when AI is enabled."""
        from aegis_sast.llm import create_llm_client

        if self._default_client is None:
            self._default_client = create_llm_client()
            self._default_provider_name = getattr(
                self._default_client,
                "provider_name",
                "default-client",
            )
        if self.model_name is None:
            self.model_name = getattr(self._default_client, "model_name", None) or getattr(
                getattr(self._default_client, "config", None),
                "active_llm_model",
                None,
            )
        return self._default_client._call_api(prompt)

    def _provider_label(self) -> str:
        """Return the active provider label for metadata emission."""
        if self.response_provider is None:
            return self._default_provider_name or "default-client"
        return "custom-response-provider"

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

        metadata: Dict[str, Any] = {
            "triage_input_schema": triage_input.get("schema_version"),
            "model_used": self.model_name or "custom-provider",
            "provider": self._provider_label(),
            "fallback_used": False,
            "raw_status": raw_status,
            "reason_codes": reason_codes,
            "evidence_summary": evidence_summary,
            "manual_review_required": manual_review_required,
        }

        # Multi-Agent Triage debate extraction
        auditor_data = payload.get("auditor_analysis") or payload.get("auditor")
        skeptic_data = payload.get("skeptic_analysis") or payload.get("skeptic")
        remediation_data = payload.get("remediation_patch") or payload.get("patch")

        if auditor_data or skeptic_data or remediation_data:
            metadata["ai_multi_agent"] = True
            agent_reviews: Dict[str, Any] = {}
            if auditor_data:
                auditor_notes = []
                if isinstance(auditor_data, dict):
                    if auditor_data.get("attack_vector"):
                        auditor_notes.append(f"Attack vector: {auditor_data['attack_vector']}")
                    if auditor_data.get("hypothesized_payload"):
                        auditor_notes.append(f"Hypothesized payload: {auditor_data['hypothesized_payload']}")
                    if auditor_data.get("security_impact"):
                        auditor_notes.append(f"Security impact: {auditor_data['security_impact']}")
                elif isinstance(auditor_data, list):
                    auditor_notes.extend([str(item) for item in auditor_data])
                elif isinstance(auditor_data, str):
                    auditor_notes.append(auditor_data)
                agent_reviews["auditor_review"] = {
                    "summary": (
                        auditor_data.get("summary", "AI Auditor validated offensive attack reachability.")
                        if isinstance(auditor_data, dict)
                        else "AI Auditor validated offensive attack reachability."
                    ),
                    "notes": auditor_notes,
                }

            if skeptic_data:
                skeptic_notes = []
                objections = []
                if isinstance(skeptic_data, dict):
                    if skeptic_data.get("defense_evaluation"):
                        skeptic_notes.append(f"Defense check: {skeptic_data['defense_evaluation']}")
                    if skeptic_data.get("sanitizer_detected"):
                        skeptic_notes.append("Sanitizer detected in code context.")
                    for obj in skeptic_data.get("objections", []):
                        objections.append(str(obj))
                elif isinstance(skeptic_data, str):
                    skeptic_notes.append(skeptic_data)
                agent_reviews["skeptic_review"] = {
                    "summary": (
                        skeptic_data.get("summary", "AI Skeptic evaluated defensive context.")
                        if isinstance(skeptic_data, dict)
                        else "AI Skeptic evaluated defensive context."
                    ),
                    "notes": skeptic_notes,
                    "objections": objections,
                }

            agent_reviews["judge_review"] = {
                "summary": explanation,
                "final_status": status.value,
                "final_confidence": confidence,
                "notes": [
                    f"AI Judge finalized status as {status.value}.",
                    f"Confidence score evaluated at {confidence:.2f}.",
                ],
            }
            metadata["agent_reviews"] = agent_reviews

            if remediation_data and isinstance(remediation_data, dict):
                metadata["remediation_patch"] = remediation_data

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
            metadata=metadata,
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
                "provider": self._provider_label(),
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

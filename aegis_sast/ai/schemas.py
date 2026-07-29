"""Schemas for structured AI provider calls."""

from typing import Any, Dict, List, Optional

from pydantic import Field

from aegis_sast.triage.schema import StrictContractModel, TriageDecision


class TokenUsage(StrictContractModel):
    """Token accounting for one model call."""

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)


class AIExecutionMetadata(StrictContractModel):
    """Provider execution metadata captured for benchmarks."""

    node_name: str
    model_name: str
    latency_ms: float = Field(ge=0.0)
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    attempts: int = Field(default=1, ge=1)
    invalid_output_count: int = Field(default=0, ge=0)
    api_error_count: int = Field(default=0, ge=0)
    error: Optional[str] = None


class StructuredAIRequest(StrictContractModel):
    """Provider-agnostic structured AI request."""

    node_name: str
    model_name: str
    prompt: str
    response_schema_name: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StructuredAIResult(StrictContractModel):
    """Provider-agnostic structured AI response."""

    parsed: TriageDecision
    raw_text: str
    metadata: AIExecutionMetadata


class AIExecutionSummary(StrictContractModel):
    """Batch-level execution summary for AI runs."""

    total_findings: int = 0
    confirmed_count: int = 0
    likely_count: int = 0
    needs_review_count: int = 0
    suppressed_count: int = 0
    route_distribution: Dict[str, int] = Field(default_factory=dict)
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    invalid_output_count: int = 0
    api_error_count: int = 0
    errors: List[str] = Field(default_factory=list)

    def add_decision(
        self,
        decision: TriageDecision,
        metadata: Optional[AIExecutionMetadata] = None,
    ) -> None:
        """Update summary counters from one decision."""
        self.total_findings += 1
        if decision.status.value == "confirmed":
            self.confirmed_count += 1
        elif decision.status.value == "likely":
            self.likely_count += 1
        elif decision.status.value == "needs-review":
            self.needs_review_count += 1
        elif decision.status.value == "suppressed":
            self.suppressed_count += 1

        route_id = " -> ".join(decision.route_taken) if decision.route_taken else "unknown"
        self.route_distribution[route_id] = self.route_distribution.get(route_id, 0) + 1

        if metadata:
            self.total_tokens += metadata.token_usage.total_tokens
            self.total_latency_ms += metadata.latency_ms
            self.invalid_output_count += metadata.invalid_output_count
            self.api_error_count += metadata.api_error_count
            if metadata.error:
                self.errors.append(metadata.error)

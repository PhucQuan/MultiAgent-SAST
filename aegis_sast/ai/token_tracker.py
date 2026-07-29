"""Token and latency tracking for AI calls."""

from time import perf_counter
from typing import Optional

from aegis_sast.ai.schemas import AIExecutionMetadata, TokenUsage


class NodeTimer:
    """Small context manager that records elapsed milliseconds."""

    def __init__(self) -> None:
        self.started_at = 0.0
        self.latency_ms = 0.0

    def __enter__(self) -> "NodeTimer":
        self.started_at = perf_counter()
        return self

    def __exit__(self, *_exc_info) -> None:
        self.latency_ms = (perf_counter() - self.started_at) * 1000


def estimate_token_usage(prompt: str, completion: str) -> TokenUsage:
    """Estimate token usage when the provider does not return usage metadata."""
    prompt_tokens = _rough_token_count(prompt)
    completion_tokens = _rough_token_count(completion)
    return TokenUsage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )


def build_execution_metadata(
    *,
    node_name: str,
    model_name: str,
    latency_ms: float,
    prompt: str,
    completion: str,
    attempts: int,
    invalid_output_count: int = 0,
    api_error_count: int = 0,
    error: Optional[str] = None,
) -> AIExecutionMetadata:
    """Create normalized execution metadata for one node call."""
    return AIExecutionMetadata(
        node_name=node_name,
        model_name=model_name,
        latency_ms=latency_ms,
        token_usage=estimate_token_usage(prompt, completion),
        attempts=attempts,
        invalid_output_count=invalid_output_count,
        api_error_count=api_error_count,
        error=error,
    )


def _rough_token_count(text: str) -> int:
    """Return a deterministic rough token count for tests and local runs."""
    if not text:
        return 0
    return max(1, len(text.split()))

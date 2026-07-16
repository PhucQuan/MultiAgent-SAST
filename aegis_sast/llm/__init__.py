"""Provider-oriented access layer for LLM integrations."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_sast.ai.gemini_client import GeminiClient

__all__ = ["GeminiClient"]


def __getattr__(name):
    """Lazily load LLM providers so no-AI mode can run with fewer deps."""
    if name == "GeminiClient":
        from aegis_sast.ai.gemini_client import GeminiClient

        return GeminiClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""Compatibility wrapper exposing the current Gemini client via the new LLM package."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_sast.ai.gemini_client import GeminiClient

__all__ = ["GeminiClient"]


def __getattr__(name):
    """Lazily expose GeminiClient so core installs do not require AI deps."""
    if name == "GeminiClient":
        from aegis_sast.ai.gemini_client import GeminiClient

        return GeminiClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""Provider-oriented access layer for LLM integrations."""

from typing import TYPE_CHECKING

from aegis_sast.core.config import AegisConfig, get_config

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_sast.ai.gemini_client import GeminiClient
    from aegis_sast.llm.openai_compatible_client import OpenAICompatibleClient

__all__ = ["GeminiClient", "OpenAICompatibleClient", "create_llm_client"]


def create_llm_client(config: AegisConfig | None = None):
    """Create the configured default LLM client for the active runtime."""
    active_config = config or get_config()
    provider = active_config.llm_provider

    if provider == "gemini":
        from aegis_sast.ai.gemini_client import GeminiClient

        return GeminiClient(config=active_config)

    if provider in {"openai-compatible", "ollama"}:
        from aegis_sast.llm.openai_compatible_client import OpenAICompatibleClient

        return OpenAICompatibleClient(config=active_config)

    raise ValueError(f"Unsupported LLM provider: {provider}")


def __getattr__(name):
    """Lazily load LLM providers so no-AI mode can run with fewer deps."""
    if name == "GeminiClient":
        from aegis_sast.ai.gemini_client import GeminiClient

        return GeminiClient
    if name == "OpenAICompatibleClient":
        from aegis_sast.llm.openai_compatible_client import OpenAICompatibleClient

        return OpenAICompatibleClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

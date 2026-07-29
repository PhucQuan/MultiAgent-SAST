"""AI integration package.

New provider-oriented imports should prefer ``aegis_sast.llm``.
"""

from aegis_sast.ai.gemini_client import GeminiClient, StructuredGeminiClient
from aegis_sast.ai.schemas import (
    AIExecutionMetadata,
    AIExecutionSummary,
    StructuredAIRequest,
    StructuredAIResult,
    TokenUsage,
)

__all__ = [
    "AIExecutionMetadata",
    "AIExecutionSummary",
    "GeminiClient",
    "StructuredAIRequest",
    "StructuredAIResult",
    "StructuredGeminiClient",
    "TokenUsage",
]

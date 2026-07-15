"""Compatibility wrapper exposing prompt helpers via the new LLM package."""

from aegis_sast.ai.prompts import (
    get_batch_verification_prompt,
    get_verification_prompt,
)

__all__ = ["get_verification_prompt", "get_batch_verification_prompt"]

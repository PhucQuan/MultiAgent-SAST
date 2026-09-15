"""Prompt template cho từng vai trò agent."""

from .auditor import SYSTEM_PROMPT_AUDITOR, build_auditor_prompt
from .hypothesis_builder import SYSTEM_PROMPT, build_hypothesis_prompt
from .judge import SENSITIVE_CWES, SYSTEM_PROMPT_JUDGE, build_judge_prompt
from .skeptic import (
    SYSTEM_PROMPT_ADVERSARIAL,
    SYSTEM_PROMPT_NEUTRAL,
    build_skeptic_prompt,
)

__all__ = [
    "SYSTEM_PROMPT",
    "build_hypothesis_prompt",
    "SYSTEM_PROMPT_AUDITOR",
    "build_auditor_prompt",
    "SYSTEM_PROMPT_NEUTRAL",
    "SYSTEM_PROMPT_ADVERSARIAL",
    "build_skeptic_prompt",
    "SENSITIVE_CWES",
    "SYSTEM_PROMPT_JUDGE",
    "build_judge_prompt",
]

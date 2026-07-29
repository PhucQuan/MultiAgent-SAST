"""Retry and parsing helpers for structured AI output."""

import json
import re
from typing import Any, Callable, TypeVar

from pydantic import BaseModel, ValidationError


class StructuredOutputError(ValueError):
    """Raised when a provider response cannot be parsed into the target schema."""


ModelT = TypeVar("ModelT", bound=BaseModel)


def extract_json_object(text: str) -> dict:
    """Extract a JSON object from plain text or a fenced markdown block."""
    stripped = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", stripped, re.DOTALL)
    if fenced:
        stripped = fenced.group(1).strip()
    elif not stripped.startswith("{"):
        match = re.search(r"(\{.*\})", stripped, re.DOTALL)
        if not match:
            raise StructuredOutputError("AI response did not contain a JSON object")
        stripped = match.group(1).strip()

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise StructuredOutputError(f"AI response was not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise StructuredOutputError("AI response JSON root must be an object")
    return parsed


def parse_structured_output(model: type[ModelT], text: str) -> ModelT:
    """Parse provider text into a Pydantic model."""
    try:
        return model.model_validate(extract_json_object(text))
    except ValidationError as exc:
        raise StructuredOutputError(f"AI response failed schema validation: {exc}") from exc


def retry_structured_call(
    *,
    call: Callable[[], str],
    parser: Callable[[str], Any],
    max_attempts: int,
) -> tuple[Any, str, int, int]:
    """Retry a provider call when output is invalid."""
    invalid_output_count = 0
    last_text = ""
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        last_text = call()
        try:
            return parser(last_text), last_text, attempt, invalid_output_count
        except StructuredOutputError as exc:
            invalid_output_count += 1
            last_error = exc

    raise StructuredOutputError(
        f"AI structured output invalid after {max_attempts} attempts: {last_error}"
    )

"""OpenAI-compatible client for local LLM adapters such as Ollama or LM Studio."""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib import error, request

from tenacity import retry, stop_after_attempt, wait_exponential

from aegis_sast.core.config import AegisConfig, get_config


class OpenAICompatibleClient:
    """Call a local or self-hosted OpenAI-compatible chat-completions endpoint."""

    def __init__(self, config: Optional[AegisConfig] = None):
        self.config = config or get_config()
        self.provider_name = self.config.llm_provider
        self.model_name = self.config.active_llm_model
        self.base_url = self.config.openai_compatible_base_url.rstrip("/")
        self.timeout_seconds = self.config.openai_compatible_timeout_seconds
        self.endpoint = self._build_endpoint(self.base_url)
        self.client = None

        if self.config.enable_ai_verification:
            self.config.validate_ai_config()
            if self.config.enable_ai_verification:
                self.client = {
                    "provider": self.provider_name,
                    "base_url": self.base_url,
                    "endpoint": self.endpoint,
                    "model": self.model_name,
                }

    @staticmethod
    def _build_endpoint(base_url: str) -> str:
        """Normalize either a base URL or a full chat-completions endpoint."""
        if base_url.endswith("/chat/completions"):
            return base_url
        return f"{base_url}/chat/completions"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    def _call_api(self, prompt: str) -> str:
        """Submit one prompt and return the model content field."""
        if not self.config.enable_ai_verification or self.client is None:
            raise RuntimeError("AI verification is disabled")

        payload = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a careful security triage assistant. "
                        "Return strict JSON when the prompt asks for JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "stream": False,
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        api_key = self.config.openai_compatible_api_key.strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        http_request = request.Request(
            self.endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with request.urlopen(http_request, timeout=self.timeout_seconds) as response:
                response_body = response.read().decode("utf-8", errors="replace")
        except error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"OpenAI-compatible request failed with HTTP {exc.code}: {error_body}"
            ) from exc
        except error.URLError as exc:
            raise RuntimeError(
                f"OpenAI-compatible request failed: {exc.reason}"
            ) from exc

        return self._extract_content(response_body)

    @staticmethod
    def _extract_content(response_body: str) -> str:
        """Extract the textual content from compatible chat-completion payloads."""
        try:
            payload: dict[str, Any] = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "OpenAI-compatible endpoint did not return valid JSON."
            ) from exc

        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message", {})
            content = OpenAICompatibleClient._normalize_content(
                message.get("content")
            )
            if content:
                return content

        message = payload.get("message")
        if isinstance(message, dict):
            content = OpenAICompatibleClient._normalize_content(message.get("content"))
            if content:
                return content

        response_text = payload.get("response")
        if isinstance(response_text, str) and response_text.strip():
            return response_text

        raise RuntimeError(
            "OpenAI-compatible response did not contain a usable assistant message."
        )

    @staticmethod
    def _normalize_content(content: Any) -> str:
        """Normalize string or structured content blocks into plain text."""
        if isinstance(content, str):
            return content

        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                    continue
                if not isinstance(item, dict):
                    continue
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                    continue
                if item.get("type") == "text" and isinstance(item.get("content"), str):
                    parts.append(item["content"])
            return "\n".join(part for part in parts if part).strip()

        return ""

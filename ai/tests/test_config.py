"""Test Task 1 — config."""

import pytest
from pydantic import ValidationError

from ai import config as config_module
from ai.config import Settings, get_settings, settings


def test_settings_load_from_env():
    s = get_settings(reload=True)
    assert s.nvidia_api_key.startswith("nvapi-")
    assert s.model_judge == "nvidia/llama-3.3-nemotron-super-49b-v1.5"
    assert s.debate_round_max == 3


def test_fallback_parsed_into_list():
    s = get_settings(reload=True)
    assert isinstance(s.model_fallback, list)
    assert s.model_fallback == [
        "meta/llama-3.1-405b-instruct",
        "mistralai/mistral-large-3-675b-instruct-2512",
    ]


def test_api_key_prefix_is_validated(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "sk-wrong-prefix")
    config_module.reset_settings()
    with pytest.raises(ValidationError):
        get_settings(reload=True)


def test_lazy_proxy_forwards_attributes():
    """`settings` là proxy nên import module không cần API key sẵn."""
    config_module.reset_settings()
    assert settings.max_tokens == 2048
    assert settings.temp_skeptic == 0.0


def test_extra_env_keys_are_ignored(monkeypatch):
    """`.env` của Core SAST còn chứa GEMINI_API_KEY... không được làm hỏng load."""
    monkeypatch.setenv("GEMINI_API_KEY", "irrelevant")
    config_module.reset_settings()
    assert Settings().model_auditor.startswith("qwen/")

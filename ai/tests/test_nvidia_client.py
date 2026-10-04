"""Test Task 2 — NVIDIA NIM client (cache, fallback, structured, usage)."""

import httpx
import pytest
from pydantic import ValidationError
from openai import APITimeoutError

from ai.llm.nvidia_client import extract_json, llm_client, strict_json_schema
from ai.schemas.verdict import AgentVerdict
from conftest import FakeMessage, FakeResponse, FakeUsage

VALID_VERDICT_JSON = (
    '{"reasoning": "Ghép chuỗi trực tiếp", "grounded_citations": ["app.php:20"], '
    '"exploitable": true, "confidence": 0.9, "fp_indicators_found": []}'
)


# --- strict_json_schema ---------------------------------------------------
def test_strict_schema_marks_all_fields_required():
    schema = strict_json_schema(AgentVerdict.model_json_schema())
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])


def test_strict_schema_drops_unsupported_keywords():
    raw = AgentVerdict.model_json_schema()
    assert "maximum" in raw["properties"]["confidence"]
    schema = strict_json_schema(raw)
    assert "maximum" not in schema["properties"]["confidence"]
    assert "default" not in schema["properties"]["fp_indicators_found"]


# --- extract_json ---------------------------------------------------------
def test_extract_json_plain():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_from_code_fence():
    assert extract_json('Đây là kết quả:\n```json\n{"a": 2}\n```') == {"a": 2}


def test_extract_json_embedded_in_prose():
    text = 'Kết luận: {"reasoning": "x", "exploitable": true} — hết.'
    assert extract_json(text)["exploitable"] is True


def test_extract_json_returns_none_when_absent():
    assert extract_json("không có json ở đây") is None
    assert extract_json("") is None


# --- cache ----------------------------------------------------------------
def test_second_identical_call_is_served_from_cache(monkeypatch):
    calls = []

    def fake_call(model, messages, temperature, response_format, max_tokens=None):
        calls.append(model)
        return {"content": "hi", "model": model, "usage": {}, "latency_sec": 0.1}

    monkeypatch.setattr(llm_client, "_call", fake_call)
    msgs = [{"role": "user", "content": "ping"}]

    first = llm_client.call("m1", msgs)
    second = llm_client.call("m1", msgs)

    assert first["from_cache"] is False
    assert second["from_cache"] is True
    assert calls == ["m1"]  # chỉ gọi API một lần


def test_cache_can_be_bypassed(monkeypatch):
    calls = []
    monkeypatch.setattr(
        llm_client,
        "_call",
        lambda model, messages, temperature, response_format, max_tokens=None: (
            calls.append(model),
            {"content": "hi", "model": model, "usage": {}, "latency_sec": 0.0},
        )[1],
    )
    msgs = [{"role": "user", "content": "ping"}]
    llm_client.call("m1", msgs, use_cache=False)
    llm_client.call("m1", msgs, use_cache=False)
    assert len(calls) == 2


# --- fallback chain -------------------------------------------------------
def test_fallback_moves_to_next_model(monkeypatch):
    tried = []

    def fake_call(model, messages, temperature, response_format, max_tokens=None):
        tried.append(model)
        if model == "primary":
            raise RuntimeError("model down")
        return {"content": "ok", "model": model, "usage": {}, "latency_sec": 0.0}

    monkeypatch.setattr(llm_client, "_call", fake_call)
    result = llm_client.call_with_fallback("primary", [{"role": "user", "content": "x"}])

    assert result["model"] == "meta/llama-3.1-405b-instruct"
    assert tried[0] == "primary"


def test_fallback_exhausted_returns_llm_failed(monkeypatch):
    def always_fail(model, messages, temperature, response_format, max_tokens=None):
        raise RuntimeError("nvidia down")

    monkeypatch.setattr(llm_client, "_call", always_fail)
    result = llm_client.call_with_fallback("primary", [{"role": "user", "content": "x"}])

    assert result["llm_failed"] is True
    assert result["content"] is None
    assert "nvidia down" in result["error"]


# --- structured output ----------------------------------------------------
def test_call_structured_parses_valid_json(monkeypatch):
    monkeypatch.setattr(
        llm_client,
        "_call",
        lambda model, messages, temperature, response_format, max_tokens=None: {
            "content": VALID_VERDICT_JSON,
            "model": model,
            "usage": {},
            "latency_sec": 0.0,
        },
    )
    v = llm_client.call_structured("m", [{"role": "user", "content": "x"}], AgentVerdict)
    assert isinstance(v, AgentVerdict)
    assert v.exploitable is True


def test_call_structured_falls_back_to_json_object_mode(monkeypatch):
    """Nấc 1 (json_schema) hỏng thì nấc 2 (json_object) phải cứu được."""
    seen = []

    def fake_call(model, messages, temperature, response_format, max_tokens=None):
        seen.append(response_format)
        if response_format and response_format.get("type") == "json_schema":
            raise RuntimeError("model không hỗ trợ json_schema")
        return {
            "content": f"Kết quả:\n```json\n{VALID_VERDICT_JSON}\n```",
            "model": model,
            "usage": {},
            "latency_sec": 0.0,
        }

    monkeypatch.setattr(llm_client, "_call", fake_call)
    v = llm_client.call_structured("m", [{"role": "user", "content": "x"}], AgentVerdict)

    assert isinstance(v, AgentVerdict)
    assert any(rf and rf.get("type") == "json_object" for rf in seen)


def test_call_structured_returns_none_when_everything_fails(monkeypatch):
    monkeypatch.setattr(
        llm_client,
        "_call",
        lambda model, messages, temperature, response_format, max_tokens=None: {
            "content": "xin lỗi, tôi không thể",
            "model": model,
            "usage": {},
            "latency_sec": 0.0,
        },
    )
    assert (
        llm_client.call_structured("m", [{"role": "user", "content": "x"}], AgentVerdict)
        is None
    )


# --- retry + usage --------------------------------------------------------
def test_retry_then_success_and_usage_logged(monkeypatch):
    attempts = {"n": 0}
    request = httpx.Request("POST", "https://integrate.api.nvidia.com/v1/chat/completions")

    class Completions:
        def create(self, **kwargs):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise APITimeoutError(request=request)
            return FakeResponse(FakeMessage(content="pong"), FakeUsage(11, 22))

    fake_client = type(
        "C", (), {"chat": type("Chat", (), {"completions": Completions()})()}
    )()
    monkeypatch.setattr(llm_client, "_client", fake_client)

    result = llm_client.call("m", [{"role": "user", "content": "ping"}], use_cache=False)

    assert attempts["n"] == 3
    assert result["content"] == "pong"
    assert result["usage"] == {"input_tokens": 11, "output_tokens": 22}


def test_usage_summary_aggregates(monkeypatch):
    class Completions:
        def create(self, **kwargs):
            return FakeResponse(FakeMessage(content="x"), FakeUsage(10, 5))

    fake_client = type(
        "C", (), {"chat": type("Chat", (), {"completions": Completions()})()}
    )()
    monkeypatch.setattr(llm_client, "_client", fake_client)

    assert llm_client.get_usage_summary() == {"total_calls": 0}
    llm_client.call("m", [{"role": "user", "content": "a"}], use_cache=False)
    llm_client.call("m", [{"role": "user", "content": "b"}], use_cache=False)

    summary = llm_client.get_usage_summary()
    assert summary["total_calls"] == 2
    assert summary["total_input_tokens"] == 20
    assert summary["total_output_tokens"] == 10
    assert summary["avg_latency_sec"] >= 0


def test_transient_5xx_is_retried(monkeypatch):
    """503 'Service temporarily overloaded' phải được retry, không rơi fail-open ngay.

    Đo thực tế 2026-09-10: NVIDIA NIM trả 503 hàng loạt; vì InternalServerError
    không nằm trong RETRYABLE nên 5/5 finding rơi vào fail-open.
    """
    from openai import InternalServerError

    attempts = {"n": 0}
    request = httpx.Request("POST", "https://integrate.api.nvidia.com/v1/chat/completions")
    response = httpx.Response(503, request=request)

    class Completions:
        def create(self, **kwargs):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise InternalServerError(
                    "Service temporarily overloaded", response=response, body=None
                )
            return FakeResponse(FakeMessage(content="pong"), FakeUsage(5, 5))

    fake_client = type(
        "C", (), {"chat": type("Chat", (), {"completions": Completions()})()}
    )()
    monkeypatch.setattr(llm_client, "_client", fake_client)

    result = llm_client.call("m", [{"role": "user", "content": "x"}], use_cache=False)

    assert attempts["n"] == 3
    assert result["content"] == "pong"


def test_seed_is_sent_and_affects_cache_key(monkeypatch):
    """Seed phải đi kèm mọi request và phải nằm trong cache key.

    Thiếu seed trong cache key thì đổi seed vẫn trả về kết quả cũ trong cache.
    """
    from ai import config as config_module

    sent = []

    class Completions:
        def create(self, **kwargs):
            sent.append(kwargs)
            return FakeResponse(FakeMessage(content="ok"), FakeUsage())

    fake_client = type(
        "C", (), {"chat": type("Chat", (), {"completions": Completions()})()}
    )()
    monkeypatch.setattr(llm_client, "_client", fake_client)
    monkeypatch.setenv("AEGIS_SEED", "7")
    config_module.reset_settings()

    msgs = [{"role": "user", "content": "x"}]
    key_seed7 = llm_client._cache_key("m", msgs, 0.0, None)
    llm_client.call("m", msgs, use_cache=False)
    assert sent[0]["seed"] == 7

    monkeypatch.setenv("AEGIS_SEED", "8")
    config_module.reset_settings()
    assert llm_client._cache_key("m", msgs, 0.0, None) != key_seed7


def test_client_pool_rotates_across_keys(monkeypatch):
    """Nhiều key thì client phải xoay vòng, để 4 worker không dội hết vào 1 key."""
    from ai import config as config_module

    monkeypatch.setenv("NVIDIA_API_KEYS", "nvapi-aaa,nvapi-bbb")
    config_module.reset_settings()
    llm_client._client = None
    llm_client._clients = []

    keys = [llm_client.client.api_key for _ in range(4)]
    assert set(keys) == {"nvapi-aaa", "nvapi-bbb"}
    assert keys[0] != keys[1]        # xoay vòng thật, không dính một key


def test_single_key_still_works(monkeypatch):
    """Không đặt NVIDIA_API_KEYS thì dùng NVIDIA_API_KEY như cũ."""
    from ai import config as config_module

    monkeypatch.delenv("NVIDIA_API_KEYS", raising=False)
    config_module.reset_settings()
    llm_client._client = None
    llm_client._clients = []

    assert config_module.get_settings().api_keys == ["nvapi-test-key"]
    assert llm_client.client.api_key == "nvapi-test-key"


def test_invalid_key_in_list_is_rejected(monkeypatch):
    from ai import config as config_module

    monkeypatch.setenv("NVIDIA_API_KEYS", "nvapi-ok,sk-wrong")
    config_module.reset_settings()
    with pytest.raises(ValidationError):
        config_module.get_settings()


def test_truncated_output_retries_with_bigger_budget(monkeypatch):
    """finish_reason='length' phải được gọi lại với trần token lớn hơn.

    Đo 2026-09-11: 5.8% call bị cắt, và đó là chế độ hỏng còn lại của Auditor —
    JSON dở dang nên mọi nấc thoái lui đều trượt rồi finding rơi fail-open.
    """
    budgets = []

    def fake_call(model, messages, temperature, response_format, max_tokens=None):
        budgets.append(max_tokens)
        if len(budgets) == 1:
            return {"content": '{"reasoning": "x"', "finish_reason": "length",
                    "model": model, "usage": {}, "latency_sec": 0.0}
        return {"content": VALID_VERDICT_JSON, "finish_reason": "stop",
                "model": model, "usage": {}, "latency_sec": 0.0}

    monkeypatch.setattr(llm_client, "_call", fake_call)
    v = llm_client.call_structured("m", [{"role": "user", "content": "x"}], AgentVerdict)

    assert isinstance(v, AgentVerdict)
    assert budgets[1] == budgets[0] * 2      # đã nới gấp đôi


def test_time_budget_stops_calls_after_deadline(monkeypatch):
    """Hết ngân sách của finding thì dừng ngay, không thử tiếp fallback chain."""
    from ai.llm.nvidia_client import DeadlineExceeded, time_budget

    calls = {"n": 0}

    class Completions:
        def create(self, **kwargs):
            calls["n"] += 1
            return FakeResponse(FakeMessage(content="ok"), FakeUsage())

    fake_client = type(
        "C", (), {"chat": type("Chat", (), {"completions": Completions()})()}
    )()
    monkeypatch.setattr(llm_client, "_client", fake_client)

    with time_budget(-1):   # ngân sách đã hết ngay từ đầu
        with pytest.raises(DeadlineExceeded):
            llm_client.call("m", [{"role": "user", "content": "x"}], use_cache=False)
        result = llm_client.call_with_fallback("m", [{"role": "user", "content": "x"}])

    assert calls["n"] == 0            # không lời gọi mạng nào được phát
    assert result["llm_failed"] is True


def test_extract_json_recovers_from_duplicated_opening_brace():
    """Guided decoding của NIM đôi khi phát dấu mở thừa; vẫn phải bóc được."""
    assert extract_json('{\n{"assumptions": [], "trigger_path": []}') == {
        "assumptions": [],
        "trigger_path": [],
    }

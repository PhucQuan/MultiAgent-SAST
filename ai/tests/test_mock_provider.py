"""Test các chế độ hỏng của provider bằng mock, không gọi API thật.

Toàn bộ test trong tệp này chạy được khi máy không có mạng và không có API
key. Đó là điều kiện để CI không tiêu quota free tier của người dùng, và để
một test đỏ luôn có nghĩa là code sai chứ không phải mạng chập.

Trọng tâm không phải đường thành công mà là các kiểu hỏng: JSON bị cắt vì
chạm max_tokens, provider trả 429, request quá deadline. Đây mới là những
tình huống quyết định một finding rơi vào fail-open đúng cách hay biến mất
âm thầm.
"""

from __future__ import annotations

import json

import pytest

from ai.llm.mock_provider import (
    MockProvider,
    MockRateLimitError,
    MockResponse,
    MockTimeoutError,
    install_mock,
)
from ai.llm.nvidia_client import NvidiaLLMClient, extract_json


@pytest.fixture
def client():
    return NvidiaLLMClient()


def test_mock_returns_scripted_json(client):
    provider = MockProvider.always({"reasoning": "ok", "exploitable": True})
    provider.install(client)

    resp = client.client.chat.completions.create(model="m", messages=[])
    payload = json.loads(resp.choices[0].message.content)

    assert payload["exploitable"] is True
    assert provider.call_count == 1


def test_truncated_json_is_detected_not_silently_accepted(client):
    """JSON cắt giữa chừng phải parse hỏng, không được nuốt lặng lẽ.

    `finish_reason == "length"` là dấu hiệu duy nhất phân biệt "mô hình trả
    lời xong" với "mô hình bị cắt giữa câu". Bỏ qua nó là cách một verdict dở
    dang lọt vào báo cáo.
    """
    MockProvider.truncated_json().install(client)
    resp = client.client.chat.completions.create(model="m", messages=[])

    assert resp.choices[0].finish_reason == "length"
    assert extract_json(resp.choices[0].message.content) is None


def test_rate_limit_is_raised_to_caller(client):
    MockProvider.rate_limited().install(client)
    with pytest.raises(MockRateLimitError):
        client.client.chat.completions.create(model="m", messages=[])


def test_rate_limit_then_success_sequence(client):
    """Kịch bản 429 rồi thành công, để kiểm thử logic retry một cách tất định."""
    provider = MockProvider.rate_limited(then={"reasoning": "ok"})
    provider.install(client)

    with pytest.raises(MockRateLimitError):
        client.client.chat.completions.create(model="m", messages=[])

    resp = client.client.chat.completions.create(model="m", messages=[])
    assert json.loads(resp.choices[0].message.content)["reasoning"] == "ok"
    assert provider.call_count == 2


def test_timeout_is_raised(client):
    MockProvider.timing_out().install(client)
    with pytest.raises(MockTimeoutError):
        client.client.chat.completions.create(model="m", messages=[])


def test_usage_is_logged_for_cost_accounting(client):
    """Mọi lời gọi phải vào usage log, nếu không báo cáo chi phí sẽ đếm thiếu."""
    MockProvider.always({"a": 1}).install(client)
    resp = client.client.chat.completions.create(model="m", messages=[])
    client.log_usage("m", resp, latency=0.5)

    assert len(client.usage_log) == 1
    entry = client.usage_log[0]
    assert entry["input_tokens"] == 100
    assert entry["output_tokens"] == 50
    assert entry["finish_reason"] == "stop"


def test_mock_records_request_arguments(client):
    """Mock giữ lại tham số gửi đi, để kiểm tra seed/temperature có được truyền."""
    provider = install_mock(client, [MockResponse('{"ok": true}')])
    client.client.chat.completions.create(
        model="m", messages=[], temperature=0.0, seed=7
    )

    assert provider.calls[0]["temperature"] == 0.0
    assert provider.calls[0]["seed"] == 7


def test_running_out_of_scripted_responses_fails_loudly(client):
    """Hết kịch bản thì báo lỗi rõ, không im lặng trả None."""
    install_mock(client, [MockResponse('{"ok": true}')])
    client.client.chat.completions.create(model="m", messages=[])
    with pytest.raises(AssertionError, match="hết kịch bản"):
        client.client.chat.completions.create(model="m", messages=[])

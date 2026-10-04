"""Provider giả lập — dùng trong test và khi chạy thử không có API key.

Tồn tại để hai việc không bao giờ xảy ra: CI gọi ra NVIDIA và tiêu quota của
người dùng, và test bị đỏ vì mạng chập chờn chứ không phải vì code sai.

Provider này cố tình mô phỏng cả các kiểu hỏng thật, không chỉ đường thành
công. Phần lớn lỗi nghiêm trọng của một tầng LLM không nằm ở lúc mô hình trả
lời đúng, mà ở lúc nó trả JSON dở dang vì chạm `max_tokens`, hoặc provider trả
429 giữa chừng — nên những tình huống đó phải kiểm thử được một cách tất định.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable


class MockRateLimitError(Exception):
    """Mô phỏng 429 từ provider."""


class MockTimeoutError(Exception):
    """Mô phỏng request treo quá deadline."""


@dataclass
class MockResponse:
    """Response đủ hình dạng để code đọc như response thật của OpenAI SDK."""

    content: str | None
    finish_reason: str = "stop"
    prompt_tokens: int = 100
    completion_tokens: int = 50
    tool_calls: list = field(default_factory=list)

    @property
    def choices(self):
        message = type(
            "Message",
            (),
            {"content": self.content, "tool_calls": self.tool_calls or None},
        )()
        choice = type(
            "Choice", (), {"message": message, "finish_reason": self.finish_reason}
        )()
        return [choice]

    @property
    def usage(self):
        return type(
            "Usage",
            (),
            {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
            },
        )()


class MockProvider:
    """Trả lần lượt các response đã kịch bản hoá, đếm số lần được gọi."""

    def __init__(self, responses: list[Any] | None = None):
        self.responses: list[Any] = list(responses or [])
        self.calls: list[dict] = []

    # -- kịch bản dựng sẵn ---------------------------------------------
    @classmethod
    def always(cls, payload: dict, finish_reason: str = "stop") -> "MockProvider":
        """Luôn trả cùng một JSON hợp lệ."""
        return cls([MockResponse(json.dumps(payload), finish_reason)] * 32)

    @classmethod
    def truncated_json(cls) -> "MockProvider":
        """JSON bị cắt giữa chừng vì chạm max_tokens.

        Đây là chế độ hỏng âm thầm nguy hiểm nhất: response có vẻ hợp lệ cho
        tới khi parse, và nếu code nuốt lỗi thì finding rơi vào fail-open mà
        không ai biết.
        """
        return cls([MockResponse('{"reasoning": "phân tích chưa xo', "length")] * 32)

    @classmethod
    def rate_limited(cls, then: dict | None = None) -> "MockProvider":
        """429 ở lần đầu, thành công ở lần sau nếu `then` được cấp."""
        seq: list[Any] = [MockRateLimitError("429 Too Many Requests")]
        if then is not None:
            seq.extend([MockResponse(json.dumps(then))] * 8)
        return cls(seq)

    @classmethod
    def timing_out(cls) -> "MockProvider":
        return cls([MockTimeoutError("deadline exceeded")] * 32)

    # -- giao diện gọi --------------------------------------------------
    def create(self, **kwargs) -> MockResponse:
        """Tương thích chữ ký `client.chat.completions.create`."""
        self.calls.append(kwargs)
        if not self.responses:
            raise AssertionError("MockProvider hết kịch bản response")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(**kwargs)
        return item

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def install(self, client) -> "MockProvider":
        """Gắn vào `NvidiaLLMClient`, thay toàn bộ pool client thật."""
        provider = self

        class _Completions:
            @staticmethod
            def create(**kwargs):
                return provider.create(**kwargs)

        class _Chat:
            completions = _Completions()

        client._client = type("FakeOpenAI", (), {"chat": _Chat()})()
        return self


def install_mock(client, responses: list[Any] | Callable | None = None) -> MockProvider:
    """Tiện ích một dòng cho test: gắn mock vào client và trả về nó."""
    return MockProvider(responses if isinstance(responses, list) else None).install(
        client
    )

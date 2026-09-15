"""Provider gateway — lối duy nhất mà tầng AI chạm tới một mô hình ngôn ngữ.

Trước đây có hai đường song song: `orchestration` gọi client Gemini, còn lớp
multi-agent gọi client NVIDIA. Hệ quả là đổi provider phải sửa code ở nhiều
nơi, và một báo cáo không nói được nó đến từ mô hình nào — hai điều đều hỏng
cho một công trình cần tái lập kết quả.

Gateway giải quyết bằng cách hạ cả hai xuống thành adapter sau một Protocol.
`gemini_legacy` giữ lại đúng một vai trò: chạy A/B đối chứng trong benchmark.
Nó không còn là đường chạy chính và không được gọi trực tiếp từ core nữa.

`mock` là adapter mặc định khi chưa cấu hình gì — chọn như vậy để một lần
chạy nhầm trong CI không tiêu quota thật.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class ModelPolicy:
    """Tham số sinh cho một lượt gọi."""

    model: str
    temperature: float = 0.0
    max_tokens: int = 2048
    seed: int | None = 0
    fallback_models: list[str] = field(default_factory=list)


@dataclass
class ModelResponse:
    """Response kèm đủ metadata để tái lập và tính chi phí."""

    data: dict
    provider: str
    model: str
    prompt_version: str = ""
    request_hash: str = ""
    response_hash: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    cache_hit: bool = False
    retry_count: int = 0
    fallback_used: bool = False
    finish_reason: str | None = None

    @property
    def truncated(self) -> bool:
        """Output bị cắt vì chạm max_tokens — JSON sau đó gần như chắc chắn hỏng."""
        return self.finish_reason == "length"


@runtime_checkable
class AIModelGateway(Protocol):
    """Giao diện mà mọi provider phải thoả."""

    name: str

    def complete_json(
        self,
        *,
        task: str,
        system_prompt: str,
        payload: dict,
        response_model: type,
        model_policy: ModelPolicy,
        deadline_ms: int,
    ) -> ModelResponse:
        ...


class MockGateway:
    """Gateway không gọi mạng. Mặc định của hệ thống khi chưa cấu hình."""

    name = "mock"

    def __init__(self, responses: dict[str, dict] | None = None):
        # Khoá theo `task` để mỗi vai trò agent trả về một payload riêng.
        self.responses = responses or {}
        self.calls: list[dict] = []

    def complete_json(
        self,
        *,
        task: str,
        system_prompt: str,
        payload: dict,
        response_model: type,
        model_policy: ModelPolicy,
        deadline_ms: int,
    ) -> ModelResponse:
        self.calls.append({"task": task, "payload": payload})
        return ModelResponse(
            data=self.responses.get(task, {}),
            provider=self.name,
            model=model_policy.model or "mock-model",
            input_tokens=0,
            output_tokens=0,
        )


class NvidiaGateway:
    """Adapter quanh `ai.llm.nvidia_client`, đường chạy chính hiện nay."""

    name = "nvidia_nim"

    def __init__(self, client=None):
        self._client = client

    @property
    def client(self):
        if self._client is None:
            from ai.llm.nvidia_client import llm_client

            self._client = llm_client
        return self._client

    def complete_json(
        self,
        *,
        task: str,
        system_prompt: str,
        payload: dict,
        response_model: type,
        model_policy: ModelPolicy,
        deadline_ms: int,
    ) -> ModelResponse:
        import time

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": str(payload)},
        ]
        start = time.perf_counter()
        result = self.client.call_structured(
            model=model_policy.model,
            messages=messages,
            schema=response_model,
            temperature=model_policy.temperature,
        )
        latency = int((time.perf_counter() - start) * 1000)

        # `call_structured` trả None khi mọi nấc parse đều hỏng. Đây là trạng
        # thái hợp lệ, không phải exception: phía trên cần biết để fail-open.
        data = result.model_dump() if result is not None else {}
        return ModelResponse(
            data=data,
            provider=self.name,
            model=model_policy.model,
            latency_ms=latency,
        )


class GeminiLegacyGateway:
    """Adapter Gemini, CHỈ dùng để đối chứng A/B trong benchmark.

    Giữ lại vì so sánh hai provider trên cùng một tập finding là dữ liệu có
    giá trị cho phần đánh giá. Không dùng cho đường chạy chính: nó không đi
    qua graph multi-agent nên không sinh evidence ledger, và một verdict
    không có evidence thì policy suppression sẽ chặn lại.
    """

    name = "gemini_legacy"

    def __init__(self, client=None):
        self._client = client

    @property
    def client(self):
        if self._client is None:
            from aegis_sast.ai.gemini_client import GeminiClient

            self._client = GeminiClient()
        return self._client

    def complete_json(
        self,
        *,
        task: str,
        system_prompt: str,
        payload: dict,
        response_model: type,
        model_policy: ModelPolicy,
        deadline_ms: int,
    ) -> ModelResponse:
        import time

        start = time.perf_counter()
        raw = self.client._call_api(f"{system_prompt}\n\n{payload}")
        latency = int((time.perf_counter() - start) * 1000)

        from ai.llm.nvidia_client import extract_json

        return ModelResponse(
            data=extract_json(raw) or {},
            provider=self.name,
            model=model_policy.model or "gemini-legacy",
            latency_ms=latency,
        )


_REGISTRY: dict[str, Any] = {
    "mock": MockGateway,
    "nvidia_nim": NvidiaGateway,
    "gemini_legacy": GeminiLegacyGateway,
}


def get_gateway(name: str = "mock", **kwargs) -> AIModelGateway:
    """Lấy gateway theo tên cấu hình.

    Tên lạ bị từ chối thay vì lặng lẽ lùi về mặc định: một lỗi chính tả trong
    config mà vẫn chạy được sẽ khiến cả một lần benchmark ghi sai provider.
    """
    if name not in _REGISTRY:
        raise ValueError(
            f"provider không hỗ trợ: {name!r}. Chọn một trong {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name](**kwargs)


def register_gateway(name: str, factory) -> None:
    """Đăng ký provider mới, dùng cho test và cho provider nội bộ."""
    _REGISTRY[name] = factory


def available_gateways() -> list[str]:
    return sorted(_REGISTRY)

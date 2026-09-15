"""Client NVIDIA NIM (OpenAI-compatible) cho multi-agent layer.

Trách nhiệm:
- Retry (tenacity, exponential backoff) cho timeout / rate-limit.
- Cache trên đĩa (diskcache) theo hash(model + messages + temperature + schema).
- Fallback chain khi model chính hỏng.
- Structured output với 3 nấc thoái lui: json_schema -> json_object -> trích JSON.
- Ghi token usage cho mọi call để báo cáo chi phí.

Mọi lỗi đều trả về `llm_failed=True` thay vì raise: chính sách fail-open
(quy tắc 2, mục 0) yêu cầu finding không bao giờ bị SUPPRESSED vì LLM hỏng.
"""

import hashlib
import itertools
import json
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
from typing import Any, Type

import diskcache
from openai import (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    OpenAI,
    RateLimitError,
)
from pydantic import BaseModel
from tenacity import (
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..config import get_settings

# 5xx (503 'Service temporarily overloaded') là lỗi tạm thời và PHẢI retry.
# Thiếu InternalServerError ở đây thì mỗi 503 nhảy thẳng sang fallback chain;
# khi cả dịch vụ quá tải thì mọi model đều trượt và finding rơi fail-open.
class DeadlineExceeded(Exception):
    """Hết ngân sách thời gian của finding hiện tại."""


_deadline: ContextVar[float | None] = ContextVar("aegis_llm_deadline", default=None)


@contextmanager
def time_budget(seconds: float | None):
    """Giới hạn tổng thời gian LLM cho một finding.

    Không có trần này thì một model xếp hàng phía server có thể đốt hàng giờ cho
    MỘT finding: đo 2026-09-11, lần chạy G có 4 finding mất hơn 8000 giây mỗi cái.
    """
    token = _deadline.set(time.time() + seconds if seconds else None)
    try:
        yield
    finally:
        _deadline.reset(token)


def check_deadline() -> None:
    d = _deadline.get()
    if d is not None and time.time() > d:
        raise DeadlineExceeded("hết ngân sách thời gian cho finding này")


RETRYABLE = (
    APITimeoutError,
    RateLimitError,
    APIConnectionError,
    InternalServerError,
)
_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
# Nới trần token khi output bị cắt: gấp đôi, tối đa 2 lần, không vượt trần cứng.
TRUNCATION_RETRIES = 1
TRUNCATION_CEILING = 16384


def strict_json_schema(schema: dict) -> dict:
    """Chuẩn hoá JSON Schema của Pydantic cho constrained decoding.

    Backend guided-decoding (OpenAI strict, NVIDIA NIM/xgrammar) không chấp nhận
    một số keyword của JSON Schema và đòi mọi object phải liệt kê đủ `required`
    kèm `additionalProperties: false`.
    """
    unsupported = {
        "default", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
        "maxLength", "minLength", "maxItems", "minItems", "format", "examples",
    }

    def walk(node: Any) -> Any:
        if isinstance(node, list):
            return [walk(n) for n in node]
        if not isinstance(node, dict):
            return node
        out = {k: walk(v) for k, v in node.items() if k not in unsupported}
        if out.get("type") == "object" and isinstance(out.get("properties"), dict):
            out["required"] = list(out["properties"].keys())
            out["additionalProperties"] = False
        return out

    return walk(schema)


def extract_json(text: str) -> dict | None:
    """Bóc object JSON đầu tiên khỏi câu trả lời có thể lẫn văn xuôi."""
    if not text:
        return None
    for candidate in (text, *(m.strip() for m in _JSON_FENCE.findall(text))):
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    # Quét từ MỌI vị trí '{'. Guided decoding của NIM đôi khi phát ra dấu mở
    # thừa (`{\n{\n "assumptions"...`); nếu chỉ quét từ dấu '{' đầu tiên thì
    # object hợp lệ nằm bên trong sẽ không bao giờ bóc được.
    for start in (i for i, ch in enumerate(text) if ch == "{"):
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(parsed, dict):
                        return parsed
                    break
    return None


class NvidiaLLMClient:
    """Wrapper OpenAI SDK trỏ vào endpoint NVIDIA NIM."""

    def __init__(self):
        self._client: OpenAI | None = None
        self._clients: list[OpenAI] = []
        self._rr = itertools.count()
        self._lock = Lock()
        self._cache: diskcache.Cache | None = None
        self._cache_scope: dict[str, str] = {}
        self.usage_log: list[dict] = []

    # -- lazy init: không đụng tới API key cho tới lần gọi thật đầu tiên ----
    @property
    def client(self) -> OpenAI:
        """Một client trong pool, xoay vòng theo từng lời gọi.

        Test có thể gán thẳng `_client` để ghi đè cả pool.
        """
        if self._client is not None:
            return self._client
        with self._lock:
            if not self._clients:
                self._clients = [self._build(k) for k in get_settings().api_keys]
        return self._clients[next(self._rr) % len(self._clients)]

    def _build(self, api_key: str) -> OpenAI:
        s = get_settings()
        return OpenAI(
                base_url=s.nvidia_base_url,
                api_key=api_key,
                timeout=s.timeout_sec,
                # SDK mặc định tự retry 2 lần; chồng lên retry của tenacity và
                # fallback chain thì một bước LLM hỏng có thể ngốn hàng chục phút.
                # Đo thực tế: một call timeout mất 525.9s dù timeout đặt 60s.
                max_retries=0,
        )

    @property
    def cache(self) -> diskcache.Cache:
        if self._cache is None:
            self._cache = diskcache.Cache(get_settings().cache_dir)
        return self._cache

    @staticmethod
    def finish_reason(resp) -> str | None:
        try:
            return resp.choices[0].finish_reason
        except (AttributeError, IndexError):
            return None

    def log_usage(self, model: str, resp, latency: float) -> None:
        """Ghi usage cho một response thô.

        Vòng tool-use của Auditor gọi thẳng `client.chat.completions.create`,
        không đi qua `_call`, nên phải ghi usage ở đây; nếu không, báo cáo chi
        phí sẽ đếm thiếu đúng những call tốn kém nhất.
        """
        usage = getattr(resp, "usage", None)
        self.usage_log.append(
            {
                "model": model,
                "input_tokens": getattr(usage, "prompt_tokens", 0) or 0,
                "output_tokens": getattr(usage, "completion_tokens", 0) or 0,
                "latency_sec": latency,
                # 'length' = output bị cắt vì chạm max_tokens. JSON sẽ dở dang và
                # mọi nấc parse đều hỏng, finding rơi vào fail-open một cách âm thầm.
                "finish_reason": self.finish_reason(resp),
            }
        )

    def _cache_key(self, model, messages, temperature, response_format, max_tokens=None) -> str:
        """Khoá cache gồm cả provenance, không chỉ nội dung prompt.

        Nội dung prompt một mình là không đủ. Sửa prompt template, đổi luật
        định tuyến trong graph, hay cập nhật knowledge card đều làm câu trả
        lời đúng thay đổi trong khi chuỗi message gửi đi có thể gần như y
        nguyên — cache theo prompt sẽ trả về verdict của phiên bản cũ và
        benchmark ghi nhận sai nguyên nhân thay đổi.

        `commit_sha` do phía gọi đặt qua `set_cache_scope`: khi mã nguồn đổi,
        mọi verdict đã cache cho commit trước phải hết hiệu lực, vì bằng chứng
        dẫn tới verdict đó có thể đã biến mất.
        """
        s = get_settings()
        payload = json.dumps(
            {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "seed": s.seed,
                "max_tokens": max_tokens or s.max_tokens,
                "response_format": str(response_format) if response_format else None,
                # --- provenance ---
                "provider": "nvidia_nim",
                "base_url": s.nvidia_base_url,
                "prompt_version": s.prompt_version,
                "graph_version": s.graph_version,
                "knowledge_version": s.knowledge_version,
                "policy_version": s.policy_version,
                "commit_sha": self._cache_scope.get("commit_sha", ""),
                "evidence_hash": self._cache_scope.get("evidence_hash", ""),
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def set_cache_scope(self, commit_sha: str = "", evidence_hash: str = "") -> None:
        """Gắn phạm vi cache cho các lời gọi tiếp theo.

        Gọi trước khi triage một finding, để verdict cache lại đúng với commit
        và bộ bằng chứng đã sinh ra nó.
        """
        self._cache_scope = {
            "commit_sha": commit_sha,
            "evidence_hash": evidence_hash,
        }

    def clear_cache_scope(self) -> None:
        self._cache_scope = {}

    def _call(self, model, messages, temperature, response_format, max_tokens=None) -> dict:
        """Một lần gọi API, có retry. Raise nếu hết lượt retry."""
        s = get_settings()
        start = time.time()
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens or s.max_tokens,
        }
        if s.seed is not None:
            kwargs["seed"] = s.seed
        if response_format:
            kwargs["response_format"] = response_format

        retryer = Retrying(
            stop=stop_after_attempt(s.max_retries),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            retry=retry_if_exception_type(RETRYABLE),
            reraise=True,
        )
        def attempt(**kw):
            check_deadline()
            return self.client.chat.completions.create(**kw)

        resp = retryer(attempt, **kwargs)
        latency = time.time() - start

        self.log_usage(model, resp, latency)
        usage = getattr(resp, "usage", None)
        in_tok = getattr(usage, "prompt_tokens", 0) or 0
        out_tok = getattr(usage, "completion_tokens", 0) or 0
        return {
            "content": resp.choices[0].message.content,
            "finish_reason": self.finish_reason(resp),
            "model": model,
            "usage": {"input_tokens": in_tok, "output_tokens": out_tok},
            "latency_sec": latency,
        }

    def call_raw(
        self, model, messages, temperature=0.0, tools=None, tool_choice="auto"
    ):
        """Gọi API trả về response THÔ, dùng cho vòng tool-use của Auditor.

        Vòng tool-use cần đọc `message.tool_calls` nên không dùng `_call` được,
        nhưng vẫn phải có retry: client đặt `max_retries=0`, nếu gọi thẳng SDK
        thì một lỗi 503 thoáng qua sẽ giết cả finding.
        """
        s = get_settings()
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": s.max_tokens,
        }
        if s.seed is not None:
            kwargs["seed"] = s.seed
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice

        retryer = Retrying(
            stop=stop_after_attempt(s.max_retries),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            retry=retry_if_exception_type(RETRYABLE),
            reraise=True,
        )
        def attempt(**kw):
            check_deadline()
            return self.client.chat.completions.create(**kw)

        started = time.time()
        resp = retryer(attempt, **kwargs)
        self.log_usage(model, resp, time.time() - started)
        return resp

    def call(
        self,
        model,
        messages,
        temperature=0.0,
        response_format=None,
        use_cache=True,
        max_tokens=None,
    ) -> dict:
        key = self._cache_key(model, messages, temperature, response_format, max_tokens)
        if use_cache and key in self.cache:
            return {**self.cache[key], "from_cache": True}
        result = self._call(model, messages, temperature, response_format, max_tokens)
        result["from_cache"] = False
        if use_cache:
            self.cache[key] = result
        return result

    def call_with_fallback(
        self,
        model,
        messages,
        temperature=0.0,
        response_format=None,
        use_cache=True,
        max_tokens=None,
    ) -> dict:
        """Thử model chính, rồi lần lượt các model trong fallback chain."""
        models = [model] + list(get_settings().model_fallback)
        last_err: Exception | None = None
        for m in models:
            try:
                return self.call(
                    m, messages, temperature, response_format, use_cache, max_tokens
                )
            except DeadlineExceeded as e:
                # Hết giờ thì đừng thử tiếp model khác, trả fail-open ngay.
                last_err = e
                break
            except Exception as e:  # fail-open: không cho lỗi LLM thoát ra ngoài
                last_err = e
                continue
        return {
            "content": None,
            "model": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
            "latency_sec": 0,
            "error": str(last_err),
            "llm_failed": True,
        }

    def call_structured(
        self,
        model,
        messages,
        schema: Type[BaseModel],
        temperature=0.0,
        use_cache=True,
    ) -> BaseModel | None:
        """Gọi LLM và ép về Pydantic model. Trả None nếu mọi nấc đều hỏng."""
        raw_schema = schema.model_json_schema()
        attempts = [
            {
                "type": "json_schema",
                "json_schema": {
                    "name": schema.__name__,
                    "schema": strict_json_schema(raw_schema),
                    "strict": True,
                },
            },
            {"type": "json_object"},
            None,
        ]

        base_tokens = get_settings().max_tokens
        for i, response_format in enumerate(attempts):
            msgs = messages
            if i > 0:  # nấc thoái lui: nhắc schema thẳng trong prompt
                msgs = list(messages) + [
                    {
                        "role": "system",
                        "content": (
                            "Chỉ trả về MỘT object JSON hợp lệ theo schema sau, "
                            "không kèm bất kỳ text nào khác:\n"
                            f"{json.dumps(raw_schema, ensure_ascii=False)}"
                        ),
                    }
                ]

            budget = base_tokens
            for _ in range(TRUNCATION_RETRIES + 1):
                result = self.call_with_fallback(
                    model, msgs, temperature, response_format, use_cache, budget
                )
                if result.get("llm_failed"):
                    break
                # Output bị cắt thì JSON chắc chắn dở dang; nới trần rồi gọi lại
                # thay vì rơi xuống nấc sau với đúng trần cũ. Đo 2026-09-11:
                # 5.8% call bị cắt, và đó là chế độ hỏng còn lại của Auditor.
                if result.get("finish_reason") == "length" and budget < TRUNCATION_CEILING:
                    budget = min(budget * 2, TRUNCATION_CEILING)
                    continue
                break

            if result.get("llm_failed"):
                continue
            parsed = extract_json(result.get("content") or "")
            if parsed is None:
                continue
            try:
                return schema.model_validate(parsed)
            except Exception:
                continue
        return None

    def get_usage_summary(self) -> dict:
        if not self.usage_log:
            return {"total_calls": 0}
        truncated = sum(
            1 for u in self.usage_log if u.get("finish_reason") == "length"
        )
        return {
            "total_calls": len(self.usage_log),
            "total_input_tokens": sum(u["input_tokens"] for u in self.usage_log),
            "total_output_tokens": sum(u["output_tokens"] for u in self.usage_log),
            "avg_latency_sec": sum(u["latency_sec"] for u in self.usage_log)
            / len(self.usage_log),
            "truncated_calls": truncated,
        }


llm_client = NvidiaLLMClient()

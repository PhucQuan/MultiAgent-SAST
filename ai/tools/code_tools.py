"""Interface tool-use giữa multi-agent layer và Core SAST.

Core implement backend thật (call graph, AST, taint engine); ở đây chỉ định
nghĩa interface. Khi một tool chưa được gắn backend, nó trả
`ToolResult(success=False)` kèm lý do — KHÔNG trả dữ liệu rỗng trông như thật,
vì `[]` từ một tool chưa gắn sẽ bị agent đọc thành "không có caller nào" và
dẫn thẳng tới kết luận không khai thác được. Dùng `make_mock_tools()` khi cần
dữ liệu giả lập tường minh. Mọi lỗi backend cũng được gói thành
`ToolResult(success=False)` chứ không raise, để tool-use loop không gãy giữa
chừng và finding không âm thầm biến mất.

Ngoài ba tool call-graph ban đầu, lớp này còn cung cấp các semantic tool mà
kết luận TP/FP thực sự phụ thuộc vào: đường dataflow, slice quanh sink,
sanitizer trace, hằng số lan truyền, ngữ cảnh luồng điều khiển. Không có
chúng, agent chỉ còn cách suy đoán từ đoạn code ngắn quanh sink — đúng kiểu
lập luận mà tầng này sinh ra để loại bỏ.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable

from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """Kết quả một lời gọi tool, luôn có metadata chi phí để tính budget."""

    success: bool
    data: dict | str | list | None = None
    error: str | None = None
    tool_name: str = ""
    truncated: bool = False
    elapsed_ms: int = 0
    cache_hit: bool = False
    # Loại artifact mà kết quả này nên được ghi vào ledger dưới dạng đó.
    artifact_type: str = "tool_result"
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None


# Giới hạn kích thước payload trả về LLM. Một backward slice trong file lớn có
# thể dài hàng nghìn dòng; đẩy nguyên vào prompt là cách nhanh nhất để đốt hết
# quota free tier trong vài finding.
MAX_RESULT_CHARS = 6000


def _truncate(value: Any) -> tuple[Any, bool]:
    """Cắt payload quá dài, báo rõ đã cắt thay vì im lặng làm mất bằng chứng."""
    if isinstance(value, str) and len(value) > MAX_RESULT_CHARS:
        return value[:MAX_RESULT_CHARS] + "\n... [truncated]", True
    if isinstance(value, list) and len(value) > 100:
        return value[:100], True
    return value, False


class CodeToolsInterface:
    """Interface tool static. Backend thật được `bind` từ phía Core."""

    # Mỗi tool: (tên thuộc tính backend, artifact_type tương ứng)
    _BACKEND_SPECS: dict[str, str] = {
        "get_callers": "call_graph",
        "get_callees": "call_graph",
        "get_function_body": "source_snippet",
        "get_dataflow_path": "dataflow_path",
        "get_backward_slice": "backward_slice",
        "get_forward_slice": "forward_slice",
        "get_sanitizer_trace": "sanitizer_trace",
        "resolve_symbol": "symbol_resolution",
        "get_control_flow_context": "cfg_context",
        "get_constant_propagation": "constant_propagation",
        "read_config_context": "config",
        "run_targeted_rule": "tool_result",
    }

    def __init__(
        self,
        get_callers: Callable[[str], list] | None = None,
        get_callees: Callable[[str], list] | None = None,
        get_body: Callable[[str], str] | None = None,
    ):
        self._backends: dict[str, Callable | None] = {
            name: None for name in self._BACKEND_SPECS
        }
        # Ba tham số cũ giữ nguyên chữ ký để code gọi sẵn không phải sửa.
        if get_callers is not None:
            self._backends["get_callers"] = get_callers
        if get_callees is not None:
            self._backends["get_callees"] = get_callees
        if get_body is not None:
            self._backends["get_function_body"] = get_body

    # ------------------------------------------------------------------
    # Gắn backend
    # ------------------------------------------------------------------
    def bind(self, get_callers=None, get_callees=None, get_body=None, **extra) -> None:
        """Gắn backend thật vào singleton `code_tools`.

        Ba tham số đầu giữ tên cũ cho tương thích ngược; các tool mới truyền
        qua `extra` theo đúng tên tool, ví dụ `get_dataflow_path=...`.
        """
        if get_callers is not None:
            self._backends["get_callers"] = get_callers
        if get_callees is not None:
            self._backends["get_callees"] = get_callees
        if get_body is not None:
            self._backends["get_function_body"] = get_body
        for name, fn in extra.items():
            if name not in self._BACKEND_SPECS:
                raise ValueError(f"tool không nằm trong allowlist: {name}")
            self._backends[name] = fn

    def is_bound(self, tool_name: str) -> bool:
        """Backend thật đã được gắn chưa — phân biệt với mock/chưa hỗ trợ."""
        return self._backends.get(tool_name) is not None

    def bound_tools(self) -> list[str]:
        return [n for n, fn in self._backends.items() if fn is not None]

    # ------------------------------------------------------------------
    # Thực thi
    # ------------------------------------------------------------------
    @staticmethod
    def _invoke(backend: Callable, kwargs: dict) -> Any:
        """Gọi backend, chịu được cả chữ ký đặt tên khác lẫn chữ ký vị trí.

        Backend do phía Core viết có thể là `lambda n: ...` hay
        `def get_callers(self, function_name)`. Ép một quy ước đặt tên duy
        nhất sẽ phá mọi backend đã gắn sẵn, nên ở đây khớp theo chữ ký thật
        và chỉ lùi về truyền theo vị trí khi tên tham số không khớp.
        """
        try:
            params = inspect.signature(backend).parameters
        except (TypeError, ValueError):
            return backend(**kwargs)

        accepts_kwargs = any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
        )
        if accepts_kwargs or all(k in params for k in kwargs):
            return backend(**kwargs)
        return backend(*kwargs.values())

    def call(self, tool_name: str, **kwargs) -> ToolResult:
        """Gọi một tool trong allowlist, luôn trả ToolResult."""
        import time

        if tool_name not in self._BACKEND_SPECS:
            return ToolResult(
                success=False,
                tool_name=tool_name,
                error=f"tool ngoài allowlist: {tool_name}",
            )

        artifact_type = self._BACKEND_SPECS[tool_name]
        backend = self._backends.get(tool_name)
        if backend is None:
            # Chưa có backend là trạng thái hợp lệ, không phải crash: agent cần
            # biết để chuyển sang action khác thay vì lặp lại tool này.
            return ToolResult(
                success=False,
                tool_name=tool_name,
                error=f"backend chưa được gắn cho '{tool_name}'",
                artifact_type=artifact_type,
            )

        start = time.perf_counter()
        try:
            raw = self._invoke(backend, kwargs)
        except TypeError as e:
            return ToolResult(
                success=False,
                tool_name=tool_name,
                error=f"sai tham số: {e}",
                artifact_type=artifact_type,
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        except Exception as e:  # backend lỗi không được làm sập graph
            return ToolResult(
                success=False,
                tool_name=tool_name,
                error=str(e),
                artifact_type=artifact_type,
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )

        data, truncated = _truncate(raw)
        file_path = line_start = line_end = None
        if isinstance(raw, dict):
            file_path = raw.get("file") or raw.get("file_path")
            line_start = raw.get("line") or raw.get("line_start")
            line_end = raw.get("line_end")

        return ToolResult(
            success=True,
            data=data,
            tool_name=tool_name,
            truncated=truncated,
            elapsed_ms=int((time.perf_counter() - start) * 1000),
            artifact_type=artifact_type,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
        )

    # ------------------------------------------------------------------
    # Các tool cụ thể — chữ ký tường minh để IDE và test bắt lỗi sớm
    # ------------------------------------------------------------------
    def get_callers(self, function_name: str) -> ToolResult:
        return self.call("get_callers", function_name=function_name)

    def get_callees(self, function_name: str) -> ToolResult:
        return self.call("get_callees", function_name=function_name)

    def get_function_body(self, function_name: str) -> ToolResult:
        return self.call("get_function_body", function_name=function_name)

    def get_dataflow_path(self, file: str, line: int) -> ToolResult:
        """Đường source -> trung gian -> sink mà taint engine dựng được."""
        return self.call("get_dataflow_path", file=file, line=line)

    def get_backward_slice(self, file: str, line: int, variable: str = "") -> ToolResult:
        """Các câu lệnh ảnh hưởng tới đối số tại sink."""
        return self.call("get_backward_slice", file=file, line=line, variable=variable)

    def get_forward_slice(self, file: str, line: int, variable: str = "") -> ToolResult:
        """Input lan tới đâu kể từ source."""
        return self.call("get_forward_slice", file=file, line=line, variable=variable)

    def get_sanitizer_trace(self, file: str, line: int) -> ToolResult:
        """Sanitizer có tồn tại trên mọi đường tới sink và có đúng ngữ cảnh không."""
        return self.call("get_sanitizer_trace", file=file, line=line)

    def resolve_symbol(self, symbol: str, file: str = "") -> ToolResult:
        """Phân biệt hàm/module trùng tên."""
        return self.call("resolve_symbol", symbol=symbol, file=file)

    def get_control_flow_context(self, file: str, line: int) -> ToolResult:
        """Guard, allowlist, early return bao quanh sink."""
        return self.call("get_control_flow_context", file=file, line=line)

    def get_constant_propagation(self, file: str, line: int, variable: str = "") -> ToolResult:
        """Giá trị tại sink có bị ràng buộc về hằng số/allowlist hữu hạn không."""
        return self.call(
            "get_constant_propagation", file=file, line=line, variable=variable
        )

    def read_config_context(self, key: str) -> ToolResult:
        """Đọc route/config/ORM setup trong allowlist."""
        return self.call("read_config_context", key=key)

    def run_targeted_rule(self, rule_id: str, file: str, line: int) -> ToolResult:
        """Chạy một rule static hẹp để kiểm chứng lại vùng code liên quan."""
        return self.call("run_targeted_rule", rule_id=rule_id, file=file, line=line)


def make_mock_tools(**overrides) -> CodeToolsInterface:
    """Bộ tool giả lập cho test và demo.

    Tách hẳn khỏi mặc định của `CodeToolsInterface`: khi chưa gắn backend,
    tool phải báo lỗi rõ chứ không được trả dữ liệu rỗng trông như thật. Một
    `get_callers` trả `[]` vì backend chưa gắn sẽ bị agent đọc thành "hàm này
    không ai gọi" và dẫn thẳng tới kết luận không khai thác được.
    """
    tools = CodeToolsInterface()
    defaults = {
        "get_callers": lambda function_name: [],
        "get_callees": lambda function_name: [],
        "get_function_body": lambda function_name: f"// mock: {function_name}",
    }
    defaults.update(overrides)
    tools.bind(**defaults)
    return tools


code_tools = CodeToolsInterface()

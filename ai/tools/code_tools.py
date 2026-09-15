"""Interface tool-use giữa multi-agent layer và Core SAST.

Quân implement backend (call graph, AST). Ở đây chỉ định nghĩa interface và
mock mặc định để agent chạy được độc lập. Mọi lỗi backend được gói thành
`ToolResult(success=False)` chứ không raise, để tool-use loop không gãy.
"""

from typing import Callable

from pydantic import BaseModel


class ToolResult(BaseModel):
    success: bool
    data: dict | str | list | None = None
    error: str | None = None


class CodeToolsInterface:
    """Quân implement backend. Ở AI chỉ dùng interface."""

    def __init__(
        self,
        get_callers: Callable[[str], list] | None = None,
        get_callees: Callable[[str], list] | None = None,
        get_body: Callable[[str], str] | None = None,
    ):
        self._get_callers = get_callers or (lambda n: [])
        self._get_callees = get_callees or (lambda n: [])
        self._get_body = get_body or (lambda n: f"// mock: {n}")

    def bind(self, get_callers=None, get_callees=None, get_body=None) -> None:
        """Gắn backend thật vào singleton `code_tools` khi tích hợp với Core."""
        if get_callers is not None:
            self._get_callers = get_callers
        if get_callees is not None:
            self._get_callees = get_callees
        if get_body is not None:
            self._get_body = get_body

    def get_callers(self, function_name: str) -> ToolResult:
        try:
            return ToolResult(success=True, data=self._get_callers(function_name))
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def get_callees(self, function_name: str) -> ToolResult:
        try:
            return ToolResult(success=True, data=self._get_callees(function_name))
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def get_function_body(self, function_name: str) -> ToolResult:
        try:
            return ToolResult(success=True, data=self._get_body(function_name))
        except Exception as e:
            return ToolResult(success=False, error=str(e))


code_tools = CodeToolsInterface()

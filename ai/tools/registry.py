"""Khai báo tool theo định dạng OpenAI function calling cho NVIDIA NIM.

Danh sách ở đây là allowlist cứng: `dispatch_tool_call` chỉ chạy tool có tên
trùng một mục trong `InvestigationAction`, nên model không thể gọi ra ngoài
tập này dù nó sinh tên gì. Không có tool nào chạy shell, mở kết nối mạng hay
ghi file — toàn bộ đều là truy vấn đọc trên mã nguồn đã lập chỉ mục.
"""

import json

from .actions import InvestigationAction
from .code_tools import code_tools

# Trần tool call cho MỘT finding, chặn vòng lặp vô tận.
MAX_TOOL_CALLS = 5


def _fn(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


_FILE_LINE = {
    "file": {"type": "string", "description": "Đường dẫn file chứa sink"},
    "line": {"type": "integer", "description": "Số dòng của sink"},
}

TOOL_DEFINITIONS = [
    _fn(
        "get_callers",
        "Trả về danh sách hàm gọi function_name.",
        {"function_name": {"type": "string"}},
        ["function_name"],
    ),
    _fn(
        "get_callees",
        "Trả về danh sách hàm bị function_name gọi.",
        {"function_name": {"type": "string"}},
        ["function_name"],
    ),
    _fn(
        "get_function_body",
        "Trả về source code của function_name.",
        {"function_name": {"type": "string"}},
        ["function_name"],
    ),
    _fn(
        "get_dataflow_path",
        "Đường dataflow từ source tới câu lệnh tại file:line. Dùng để xác nhận "
        "input của người dùng có thực sự chạm tới sink hay không.",
        dict(_FILE_LINE),
        ["file", "line"],
    ),
    _fn(
        "get_sanitizer_trace",
        "Liệt kê các lời gọi có thể là sanitizer nằm trước sink tại file:line, "
        "kèm việc chúng có tác động lên đúng biến mà sink đọc hay không.",
        dict(_FILE_LINE),
        ["file", "line"],
    ),
    _fn(
        "get_backward_slice",
        "Các câu lệnh phía trên đã ghi vào biến mà sink đọc.",
        {**_FILE_LINE, "variable": {"type": "string"}},
        ["file", "line"],
    ),
    _fn(
        "get_forward_slice",
        "Giá trị tạo ra tại file:line lan tới những câu lệnh nào phía sau.",
        {**_FILE_LINE, "variable": {"type": "string"}},
        ["file", "line"],
    ),
    _fn(
        "get_control_flow_context",
        "Các guard bao quanh sink: điều kiện if/match, vòng lặp, try. Dùng để "
        "kiểm tra sink có nằm trong nhánh chỉ đạt tới với giá trị an toàn không.",
        dict(_FILE_LINE),
        ["file", "line"],
    ),
    _fn(
        "get_constant_propagation",
        "Kiểm tra biến tại sink có bị ràng buộc về hằng số hoặc tập giá trị "
        "hữu hạn hay không. constant_bound=true là bằng chứng false positive.",
        {**_FILE_LINE, "variable": {"type": "string"}},
        ["file", "line"],
    ),
    _fn(
        "resolve_symbol",
        "Mọi định nghĩa trùng tên symbol, để phân biệt hàm cùng tên khác module.",
        {"symbol": {"type": "string"}, "file": {"type": "string"}},
        ["symbol"],
    ),
]

# Tên tool -> tham số bắt buộc, dùng để kiểm tra trước khi dispatch.
_REQUIRED_ARGS = {
    t["function"]["name"]: t["function"]["parameters"]["required"]
    for t in TOOL_DEFINITIONS
}

TOOL_NAMES = frozenset(_REQUIRED_ARGS)


def dispatch_tool_call(name: str, args: dict) -> str:
    """Thực thi một tool call và trả JSON để nhét lại vào message list.

    Mọi nhánh lỗi đều trả JSON hợp lệ chứ không raise: tool-use loop phải đọc
    được lỗi để đổi hướng, và một tham số sai từ model không được phép làm
    hỏng cả lượt triage của finding.
    """
    if name not in TOOL_NAMES:
        # Từ chối thẳng, không đoán tool "gần giống" — đó là chỗ mà một tên
        # bịa ra có thể lọt thành hành động ngoài ý muốn.
        return json.dumps({"success": False, "error": f"unknown tool: {name}"})

    missing = [a for a in _REQUIRED_ARGS[name] if a not in args]
    if missing:
        return json.dumps(
            {"success": False, "error": f"missing argument: {', '.join(missing)}"}
        )

    accepted = set(TOOL_DEFINITIONS[0]["function"]["parameters"]["properties"])
    for t in TOOL_DEFINITIONS:
        if t["function"]["name"] == name:
            accepted = set(t["function"]["parameters"]["properties"])
            break
    clean_args = {k: v for k, v in args.items() if k in accepted}

    result = code_tools.call(name, **clean_args)
    return json.dumps(result.model_dump(), ensure_ascii=False, default=str)


__all__ = [
    "InvestigationAction",
    "MAX_TOOL_CALLS",
    "TOOL_DEFINITIONS",
    "TOOL_NAMES",
    "dispatch_tool_call",
]

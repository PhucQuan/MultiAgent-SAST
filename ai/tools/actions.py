"""Vốn từ action đóng cho Planner.

Planner chỉ được chọn action trong enum này. Enum đóng là ranh giới an toàn
quan trọng nhất của tầng agent: model không thể sinh ra một action mới bằng
cách viết tên khác vào JSON, nên không có đường nào dẫn tới thực thi shell,
mở kết nối mạng, hay ghi vào source code. Mọi giá trị lạ đều bị từ chối ở
`coerce`, không phải bị diễn giải "gần đúng".

Enum này cũng là action space cố định cho contextual bandit sau này — nếu tập
action thay đổi giữa các lần chạy thì trajectory log không so sánh được.
"""

from __future__ import annotations

from enum import Enum


class InvestigationAction(str, Enum):
    """Toàn bộ hành động điều tra mà Planner được phép yêu cầu."""

    GET_DATAFLOW_PATH = "get_dataflow_path"
    GET_BACKWARD_SLICE = "get_backward_slice"
    GET_FORWARD_SLICE = "get_forward_slice"
    GET_CALLERS = "get_callers"
    GET_CALLEES = "get_callees"
    GET_FUNCTION_BODY = "get_function_body"
    RESOLVE_SYMBOL = "resolve_symbol"
    GET_SANITIZER_TRACE = "get_sanitizer_trace"
    GET_CONTROL_FLOW_CONTEXT = "get_control_flow_context"
    GET_CONSTANT_PROPAGATION = "get_constant_propagation"
    READ_CONFIG_CONTEXT = "read_config_context"
    RUN_TARGETED_RULE = "run_targeted_rule"
    REQUEST_HUMAN_REVIEW = "request_human_review"
    STOP = "stop"


# Action kết thúc điều tra, không sinh evidence mới.
TERMINAL_ACTIONS = {
    InvestigationAction.STOP,
    InvestigationAction.REQUEST_HUMAN_REVIEW,
}

# Action thực sự gọi tool static và tiêu tool_call_budget.
EVIDENCE_ACTIONS = frozenset(set(InvestigationAction) - TERMINAL_ACTIONS)


def coerce(value: str | InvestigationAction) -> InvestigationAction | None:
    """Ép chuỗi do LLM sinh về action hợp lệ, trả None nếu ngoài allowlist.

    Trả None thay vì raise: một action lạ là dữ liệu xấu từ model, không phải
    lỗi lập trình, và nó không được phép làm sập cả graph.
    """
    if isinstance(value, InvestigationAction):
        return value
    if not isinstance(value, str):
        return None
    try:
        return InvestigationAction(value.strip().lower())
    except ValueError:
        return None

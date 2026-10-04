"""Tool executor — chạy kế hoạch điều tra, ghi kết quả vào evidence ledger.

Không gọi LLM. Mỗi action được kiểm tra lại một lần nữa ở đây trước khi chạy,
kể cả khi planner đã kiểm: planner có thể được thay bằng bản dùng LLM sau này,
và ranh giới allowlist không nên phụ thuộc vào việc ai gọi nó.

Tool thất bại không làm hỏng lượt triage — lỗi được ghi vào `errors` để agent
biết câu hỏi nào chưa trả lời được, rồi graph đi tiếp.
"""

from __future__ import annotations

from ..config import get_settings
from ..schemas.state import GraphState
from ..tools.actions import EVIDENCE_ACTIONS, coerce
from ..tools.code_tools import code_tools


def tool_executor_node(state: GraphState) -> GraphState:
    """Chạy từng action trong `state.plan`, tiêu tool budget tương ứng."""
    new_state = state.model_copy(deep=True)
    s = get_settings()

    for planned in state.plan:
        if new_state.tool_calls_used >= s.tool_call_budget:
            new_state.record_policy("tool_budget_exhausted")
            break

        action = coerce(planned.action)
        if action is None or action not in EVIDENCE_ACTIONS:
            # Action ngoài allowlist bị chặn tại đây, không bao giờ tới backend.
            new_state.blocked_actions.append(
                {"action": planned.action, "reason": "ngoài allowlist"}
            )
            new_state.record_policy("action_rejected_not_in_allowlist")
            continue

        result = code_tools.call(action.value, **planned.arguments)
        new_state.tool_calls_used += 1

        record = {
            "action": action.value,
            "arguments": planned.arguments,
            "success": result.success,
            "elapsed_ms": result.elapsed_ms,
            "source": planned.source,
        }

        if not result.success:
            new_state.errors.append(
                {"action": action.value, "error": result.error}
            )
            record["error"] = result.error
            new_state.completed_actions.append(record)
            continue

        payload = result.data if isinstance(result.data, dict) else {"data": result.data}
        ref = new_state.evidence.add(
            artifact_type=result.artifact_type,
            producer=f"tool/{action.value}",
            payload=payload,
            file_path=result.file_path or planned.arguments.get("file"),
            line_start=result.line_start or planned.arguments.get("line"),
        )
        record["artifact_id"] = ref.artifact_id
        record["truncated"] = result.truncated
        new_state.completed_actions.append(record)

    new_state.plan = []
    return new_state

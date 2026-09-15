"""Investigation planner — chọn bước thu thập bằng chứng tiếp theo.

Đây là node thay thế vòng debate cũ. Trước đây, khi Auditor và Skeptic bất
đồng, graph gọi lại Auditor thêm một vòng với đúng ngữ cảnh cũ — tốn thêm một
lượt API để nhận lại cùng thiên kiến, vì không có dữ liệu nào mới xuất hiện
giữa hai vòng. Bất đồng giữa hai mô hình không được giải quyết bằng cách hỏi
lại to hơn, mà bằng cách đi tìm dữ kiện còn thiếu.

Planner ở đây là rule-based, không gọi LLM: nó đọc câu hỏi chưa trả lời được
trong state rồi ánh xạ sang tool static tương ứng. Rule-based có ba cái lợi
cụ thể — không tốn quota, tái lập được giữa các lần chạy benchmark, và không
thể yêu cầu một action ngoài allowlist.

Thứ tự ưu tiên phản ánh chi phí và sức nặng của bằng chứng: câu hỏi "input có
thật sự tới sink không" phải trả lời trước, vì nếu câu trả lời là không thì
mọi câu hỏi còn lại đều không cần hỏi nữa.
"""

from __future__ import annotations

from ..config import get_settings
from ..schemas.state import GraphState, PlannedAction
from ..tools.actions import InvestigationAction
from ..tools.code_tools import code_tools


def _already_tried(state: GraphState, action: str, args: dict) -> bool:
    """Action này với đúng tham số này đã chạy chưa.

    Chặn vòng lặp tốn kém nhất: gọi lại cùng một tool với cùng tham số sẽ cho
    cùng kết quả, nên lặp lại chỉ đốt budget mà không thêm bằng chứng.
    """
    for done in state.completed_actions:
        if done.get("action") == action and done.get("arguments") == args:
            return True
    return False


def plan_next_actions(state: GraphState, limit: int = 2) -> list[PlannedAction]:
    """Chọn tối đa `limit` bước điều tra kế tiếp cho state hiện tại."""
    finding = state.finding
    sink = finding.evidence.sink
    source = finding.evidence.source
    validator = state.validator_assessment
    candidates: list[PlannedAction] = []

    def propose(action: InvestigationAction, rationale: str, **arguments) -> None:
        if len(candidates) >= limit:
            return
        if _already_tried(state, action.value, arguments):
            return
        if not code_tools.is_bound(action.value):
            # Tool chưa có backend: ghi nhận là bị chặn chứ không âm thầm bỏ,
            # để báo cáo cho thấy câu hỏi nào không trả lời được vì thiếu tool.
            state.blocked_actions.append(
                {"action": action.value, "reason": "backend chưa gắn"}
            )
            return
        candidates.append(
            PlannedAction(
                action=action.value,
                arguments=arguments,
                rationale=rationale,
                source="heuristic_policy",
            )
        )

    # 1. Đường dataflow là câu hỏi gốc: không có nó thì không có finding.
    if not state.evidence.has_type("dataflow_path") or (
        validator and not validator.dataflow_confirmed
    ):
        propose(
            InvestigationAction.GET_DATAFLOW_PATH,
            "Xác nhận input của người dùng có thực sự chạm tới sink",
            file=sink.file,
            line=sink.line,
        )

    # 2. Sanitizer: nguyên nhân false positive phổ biến nhất.
    if not state.evidence.has_type("sanitizer_trace"):
        propose(
            InvestigationAction.GET_SANITIZER_TRACE,
            "Kiểm tra có sanitizer tác động đúng lên biến mà sink đọc không",
            file=sink.file,
            line=sink.line,
        )

    # 3. Hằng số ràng buộc: bằng chứng suppress mạnh nhất mà tool tĩnh cho được.
    if not state.evidence.has_type("constant_propagation"):
        propose(
            InvestigationAction.GET_CONSTANT_PROPAGATION,
            "Xem giá trị tại sink có bị giới hạn trong tập hằng số hữu hạn không",
            file=sink.file,
            line=sink.line,
        )

    # 4. Guard bao quanh sink.
    if not state.evidence.has_type("cfg_context"):
        propose(
            InvestigationAction.GET_CONTROL_FLOW_CONTEXT,
            "Xem sink có nằm sau guard hay allowlist không",
            file=sink.file,
            line=sink.line,
        )

    # 5. Chỉ khi hai agent bất đồng mới cần mở rộng ra ngoài hàm hiện tại:
    # đây là nhóm tool đắt nhất và ít khi đổi được kết luận.
    disagreement = (
        state.auditor_verdict
        and state.skeptic_verdict
        and state.auditor_verdict.exploitable != state.skeptic_verdict.exploitable
    )
    if disagreement:
        propose(
            InvestigationAction.GET_BACKWARD_SLICE,
            "Bất đồng chưa giải quyết: truy các câu lệnh ghi vào biến ở sink",
            file=sink.file,
            line=sink.line,
        )
        if source.symbol:
            propose(
                InvestigationAction.GET_CALLERS,
                "Bất đồng chưa giải quyết: xem hàm chứa source được gọi từ đâu",
                function_name=source.symbol,
            )

    return candidates


def investigation_planner_node(state: GraphState) -> GraphState:
    """Ghi kế hoạch điều tra vào state; không gọi LLM, không tốn token."""
    new_state = state.model_copy(deep=True)
    s = get_settings()

    remaining = max(s.tool_call_budget - new_state.tool_calls_used, 0)
    if remaining <= 0:
        new_state.plan = []
        new_state.record_policy("tool_budget_exhausted")
        return new_state

    new_state.plan = plan_next_actions(new_state, limit=min(2, remaining))
    if not new_state.plan:
        new_state.record_policy("no_further_investigation_possible")
    else:
        new_state.record_policy(
            "planned:" + ",".join(a.action for a in new_state.plan)
        )
    return new_state

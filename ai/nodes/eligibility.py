"""Eligibility gate — node đầu graph, không gọi LLM.

Chạy trước mọi thứ khác để một finding không đủ điều kiện thoát khỏi graph
trước khi tốn bất kỳ token nào. Lý do từ chối được ghi vào `policy_events`,
nên báo cáo trả lời được câu hỏi "vì sao AI không xem finding này" thay vì để
người đọc đoán.
"""

from __future__ import annotations

from ..config import get_settings
from ..policies.eligibility import check_eligibility
from ..schemas.state import GraphState
from ..schemas.verdict import TriageState


def eligibility_gate_node(state: GraphState) -> GraphState:
    """Chốt sớm finding không đáng gửi sang LLM."""
    new_state = state.model_copy(deep=True)
    s = get_settings()

    decision = check_eligibility(state.finding, s)
    new_state.model_metadata["eligibility"] = decision.to_dict()
    new_state.record_policy(f"eligibility:{decision.reason}")

    if decision.eligible:
        return new_state

    # Không đủ điều kiện KHÔNG có nghĩa là an toàn. Finding vẫn ở lại báo cáo
    # dưới trạng thái cần người xem; chỉ có điều AI không xét nó.
    new_state.triage_state = TriageState.NEEDS_REVIEW
    return new_state

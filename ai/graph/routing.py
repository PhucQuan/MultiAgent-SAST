"""Conditional edge cho LangGraph.

Quy tắc chung của mọi hàm ở đây: khi nghi ngờ thì đi về phía tốn ít quota hơn
và giữ lại cảnh báo, không đi về phía tranh luận thêm. Một vòng lặp không sinh
bằng chứng mới là vòng lặp vô ích — nó chỉ lặp lại cùng thiên kiến với chi phí
gấp đôi, nên mọi nhánh quay lại đều có điều kiện "đã có gì mới chưa".
"""

from ..config import get_settings, settings
from ..schemas.state import GraphState


def route_after_eligibility(state: GraphState) -> str:
    """Finding bị gate loại thì ra thẳng, không tốn token nào."""
    return "end" if state.triage_state else "evidence_inventory"


def route_after_planner(state: GraphState) -> str:
    """Có việc để làm thì chạy tool, không thì sang bước lập giả thuyết."""
    if state.triage_state:
        return "end"
    return "tool_executor" if state.plan else "hypothesis_builder"


def route_after_tools(state: GraphState) -> str:
    """Sau khi thu bằng chứng, luôn đi tiếp — không quay lại planner ngay.

    Quay lại planner ở đây sẽ tạo vòng tool chạy liên tục mà chưa ai đọc kết
    quả. Bằng chứng phải được đưa qua Auditor/Skeptic rồi mới biết còn thiếu gì.
    """
    return "hypothesis_builder"


def route_after_hypothesis(state: GraphState) -> str:
    return "judge" if state.llm_failed else "knowledge_loader"


def route_after_auditor(state: GraphState) -> str:
    if state.llm_failed:
        return "judge"
    # Confidence cao rõ ràng → skip Skeptic (tiết kiệm token).
    # Ngưỡng lấy từ cấu hình: confidence LLM tự chấm không được hiệu chỉnh nên
    # hằng số 0.8 của guide làm nhánh Skeptic chết hoàn toàn.
    if (
        state.auditor_verdict
        and state.auditor_verdict.confidence >= settings.skip_skeptic_confidence
    ):
        return "validator"
    return "skeptic"


def route_after_skeptic(state: GraphState) -> str:
    """Sau Skeptic luôn qua validator — không ai được tự xác nhận chính mình."""
    return "validator"


def route_after_validator(state: GraphState) -> str:
    """Quyết định điều tra thêm hay chốt.

    Chỉ quay lại planner khi hội đủ BA điều kiện: còn bất đồng hoặc thiếu
    bằng chứng, còn ngân sách, và vòng vừa rồi thực sự đã thu được artifact
    mới. Thiếu điều kiện thứ ba là cách vòng lặp cũ đốt quota mà không tiến
    triển.
    """
    s = get_settings()

    if state.llm_failed:
        return "judge"

    if state.debate_round >= s.debate_round_max:
        return "judge"  # hard-stop

    if state.tool_calls_used >= s.tool_call_budget:
        return "judge"

    validator = state.validator_assessment
    disagreement = (
        state.auditor_verdict
        and state.skeptic_verdict
        and state.auditor_verdict.exploitable != state.skeptic_verdict.exploitable
    )
    missing_evidence = validator is not None and validator.insufficient_evidence

    if not (disagreement or missing_evidence):
        return "judge"

    # Còn câu hỏi mở: chỉ đáng điều tra tiếp nếu vòng trước có tiến triển.
    evidence_at_round_start = state.model_metadata.get("evidence_count_at_round_start")
    if evidence_at_round_start is not None and len(state.evidence) <= evidence_at_round_start:
        return "judge"

    return "reinvestigate"

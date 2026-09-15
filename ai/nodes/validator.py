"""Deterministic validator — kiểm chứng bằng tool static, không hỏi LLM.

Đây là mắt xích khiến kết luận của tầng AI có thể phản biện được. Auditor và
Skeptic đều là mô hình ngôn ngữ: chúng nêu giả thuyết, nhưng không được phép
tự xác nhận giả thuyết của chính mình. Node này chạy lại các tool static trên
đúng sink đang xét và trả lời bốn câu hỏi bằng dữ liệu chương trình:

1. Đường dataflow từ source tới sink có thật không?
2. Sink có đạt tới được không, hay nằm sau một guard?
3. Có sanitizer tác động đúng lên biến mà sink đọc không?
4. Giá trị tại sink có bị ràng buộc về một tập hằng số hữu hạn không?

Chỉ câu trả lời ở đây mới đủ tư cách làm căn cứ suppress. Một verdict "false
positive" của LLM mà validator không xác nhận được thì bị hạ xuống cần người
xem — thà giữ lại một cảnh báo thừa còn hơn giấu đi một lỗ hổng thật.

Node không gọi LLM nên không tốn token, và chạy được cả ở mode `heuristic`.
"""

from __future__ import annotations

from typing import Any

from ..schemas.state import GraphState, ValidatorAssessment
from ..tools.code_tools import code_tools


def _payload(result: Any) -> dict:
    """Lấy phần dict trong ToolResult, trả {} nếu tool thất bại."""
    if result is None or not result.success:
        return {}
    return result.data if isinstance(result.data, dict) else {}


def validator_node(state: GraphState) -> GraphState:
    """Chạy tool static trên sink của finding và ghi kết luận vào state."""
    new_state = state.model_copy(deep=True)
    finding = state.finding
    sink = finding.evidence.sink
    file, line = sink.file, sink.line

    notes: list[str] = []
    evidence_ids: list[str] = []
    tools_unavailable: list[str] = []

    def run(tool_name: str, **kwargs) -> dict:
        if not code_tools.is_bound(tool_name):
            tools_unavailable.append(tool_name)
            return {}
        result = code_tools.call(tool_name, **kwargs)
        if not result.success:
            notes.append(f"{tool_name}: {result.error}")
            return {}
        data = _payload(result)
        ref = new_state.evidence.add(
            artifact_type=result.artifact_type,
            producer=f"validator/{tool_name}",
            payload=data,
            file_path=result.file_path or file,
            line_start=result.line_start or line,
        )
        evidence_ids.append(ref.artifact_id)
        return data

    dataflow = run("get_dataflow_path", file=file, line=line)
    sanitizer = run("get_sanitizer_trace", file=file, line=line)
    constants = run("get_constant_propagation", file=file, line=line)
    control_flow = run("get_control_flow_context", file=file, line=line)

    # ---- 1. Đường dataflow ------------------------------------------------
    # Ưu tiên kết quả tool; nếu tool không chạy được thì dùng evidence mà
    # chính Core SAST đã sinh ra cùng finding, chứ không coi là "không có".
    if dataflow:
        dataflow_confirmed = bool(dataflow.get("reaches_sink"))
    else:
        path = finding.evidence.data_flow_path
        kinds = {step.kind for step in path}
        dataflow_confirmed = "source" in kinds and "sink" in kinds

    # ---- 2. Sanitizer -----------------------------------------------------
    # Chỉ tính là xác nhận khi sanitizer tác động đúng lên biến sink đọc.
    # Một lời gọi `escape()` ở chỗ khác trong hàm không chứng minh được gì.
    sanitizer_confirmed = bool(sanitizer.get("any_guards_sink_variable"))
    if not sanitizer and finding.evidence.sanitizers_seen:
        # Không có tool: hạ xuống mức "ghi nhận", không phải xác nhận.
        notes.append(
            "sanitizers_seen từ Core SAST không được validator kiểm chứng độc lập"
        )

    # ---- 3. Hằng số ràng buộc --------------------------------------------
    constant_bound = bool(constants.get("constant_bound"))

    # ---- 4. Guard ---------------------------------------------------------
    guards = control_flow.get("guards") or []
    guarded = bool(guards)

    # ---- Tổng hợp ---------------------------------------------------------
    # `proved_safe` là điều kiện DUY NHẤT cho phép suppress tự động. Cố ý hẹp:
    # phải có bằng chứng dương tính cụ thể, không phải "không tìm thấy gì".
    proved_safe = constant_bound or sanitizer_confirmed

    # Evidence coi là đủ khi trả lời được câu hỏi dataflow bằng tool thật.
    insufficient_evidence = not evidence_ids and not finding.evidence.data_flow_path

    if tools_unavailable:
        notes.append(
            "tool chưa gắn backend: " + ", ".join(sorted(set(tools_unavailable)))
        )

    new_state.validator_assessment = ValidatorAssessment(
        dataflow_confirmed=dataflow_confirmed,
        sink_reachable=dataflow_confirmed and not constant_bound,
        sanitizer_confirmed=sanitizer_confirmed,
        constant_bound=constant_bound,
        guarded_by_control_flow=guarded,
        proved_safe_pattern=proved_safe,
        insufficient_evidence=insufficient_evidence,
        evidence_ids=evidence_ids,
        notes=notes,
        tools_unavailable=sorted(set(tools_unavailable)),
    )
    return new_state

"""Evidence inventory — nạp bằng chứng mà Core SAST đã có vào ledger.

Không gọi LLM và không thêm bất cứ thứ gì không có nguồn gốc: mọi artifact ở
đây đều đến thẳng từ `NormalizedFinding` mà detector sinh ra. Mục đích là để
các node sau trích `evidence_id` ngay từ vòng đầu, thay vì phải gọi tool mới
biết source và sink nằm ở đâu.
"""

from __future__ import annotations

from ..schemas.state import GraphState

PRODUCER = "aegis_sast.core.detector"


def evidence_inventory_node(state: GraphState) -> GraphState:
    """Chuyển evidence của finding thành artifact có định danh."""
    new_state = state.model_copy(deep=True)
    ev = state.finding.evidence

    new_state.evidence.add(
        artifact_type="source_snippet",
        producer=PRODUCER,
        payload={
            "role": "source",
            "symbol": ev.source.symbol,
            "code": ev.source.code_slice,
        },
        file_path=ev.source.file,
        line_start=ev.source.line,
    )
    new_state.evidence.add(
        artifact_type="source_snippet",
        producer=PRODUCER,
        payload={
            "role": "sink",
            "symbol": ev.sink.symbol,
            "code": ev.sink.code_slice,
        },
        file_path=ev.sink.file,
        line_start=ev.sink.line,
    )

    if ev.data_flow_path:
        new_state.evidence.add(
            artifact_type="dataflow_path",
            producer=PRODUCER,
            payload={
                "steps": [step.model_dump() for step in ev.data_flow_path],
                "sanitizers_seen": list(ev.sanitizers_seen),
                "evidence_quality": ev.evidence_quality,
            },
            file_path=ev.sink.file,
            line_start=ev.sink.line,
            # Đường dẫn do detector dựng là bằng chứng khởi điểm, nhưng chính
            # nó đang bị nghi ngờ — nên không cho điểm liên quan tối đa.
            relevance=0.8,
        )

    new_state.record_policy("evidence_inventory_loaded")
    return new_state

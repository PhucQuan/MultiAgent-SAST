"""Biên dịch workflow multi-agent thành LangGraph.

Hình dạng graph:

    eligibility_gate
        |
    evidence_inventory
        |
    investigation_planner <-------------------+
        |                                     |
    tool_executor                             |
        |                                     |
    hypothesis_builder                        |
        |                                     |
    knowledge_loader                          |
        |                                     |
    auditor ----> skeptic                     |
        |            |                        |
        +----> validator --- còn câu hỏi mở --+
                     |
                   judge

Khác biệt cốt lõi so với bản đầu: nhánh quay lại không dẫn về Auditor mà về
`investigation_planner`. Khi hai agent bất đồng, graph đi thu thêm bằng chứng
rồi mới hỏi lại — thay vì hỏi lại cùng một câu trên cùng một ngữ cảnh. Nhánh
này còn bị chặn ba lớp (số vòng, tool budget, và "vòng trước có sinh artifact
mới không"), nên không thể quay vòng vô ích.

Toàn bộ node trước `hypothesis_builder` đều không gọi LLM, nên một finding bị
gate loại hoặc được tool static giải quyết sẽ không tốn token nào.
"""

from typing import Callable

from langgraph.graph import END, StateGraph

from ..nodes.auditor import auditor_node
from ..nodes.eligibility import eligibility_gate_node
from ..nodes.evidence_inventory import evidence_inventory_node
from ..nodes.hypothesis_builder import hypothesis_builder_node
from ..nodes.investigation_planner import investigation_planner_node
from ..nodes.judge import judge_node
from ..nodes.knowledge_loader import knowledge_loader_node
from ..nodes.planner import planner_node
from ..nodes.skeptic import skeptic_node
from ..nodes.tool_executor import tool_executor_node
from ..nodes.validator import validator_node
from ..schemas.finding import NormalizedFinding
from ..schemas.state import GraphState
from .routing import (
    route_after_auditor,
    route_after_eligibility,
    route_after_hypothesis,
    route_after_planner,
    route_after_skeptic,
    route_after_tools,
    route_after_validator,
)


def reinvestigate_node(state: GraphState) -> GraphState:
    """Mở một vòng điều tra mới.

    Ghi lại số artifact tại thời điểm bắt đầu vòng, để `route_after_validator`
    biết vòng này có thu được gì mới hay không. Không có mốc đó thì không phân
    biệt được "tranh luận có tiến triển" với "tranh luận giậm chân".
    """
    new_state = state.model_copy(deep=True)
    new_state.debate_round += 1
    new_state.model_metadata["evidence_count_at_round_start"] = len(new_state.evidence)
    new_state.record_policy(f"reinvestigate_round_{new_state.debate_round}")
    return investigation_planner_node(new_state)


def _as_update(fn: Callable[[GraphState], GraphState]) -> Callable[[GraphState], dict]:
    """Node trả về GraphState; LangGraph cần dict các kênh cần ghi đè."""

    def wrapped(state: GraphState) -> dict:
        return fn(state).model_dump()

    wrapped.__name__ = fn.__name__
    return wrapped


def build_aegis_graph():
    g = StateGraph(GraphState)

    g.add_node("eligibility_gate", _as_update(eligibility_gate_node))
    g.add_node("evidence_inventory", _as_update(evidence_inventory_node))
    g.add_node("planner", _as_update(planner_node))
    g.add_node("investigation_planner", _as_update(investigation_planner_node))
    g.add_node("tool_executor", _as_update(tool_executor_node))
    g.add_node("hypothesis_builder", _as_update(hypothesis_builder_node))
    g.add_node("knowledge_loader", _as_update(knowledge_loader_node))
    g.add_node("auditor", _as_update(auditor_node))
    g.add_node("skeptic", _as_update(skeptic_node))
    g.add_node("validator", _as_update(validator_node))
    g.add_node("reinvestigate", _as_update(reinvestigate_node))
    g.add_node("judge", _as_update(judge_node))

    g.set_entry_point("eligibility_gate")

    g.add_conditional_edges(
        "eligibility_gate",
        route_after_eligibility,
        {"end": END, "evidence_inventory": "evidence_inventory"},
    )
    # Planner cũ vẫn giữ: nó chốt sớm finding có evidence quá kém.
    g.add_edge("evidence_inventory", "planner")
    g.add_edge("planner", "investigation_planner")

    g.add_conditional_edges(
        "investigation_planner",
        route_after_planner,
        {
            "end": END,
            "tool_executor": "tool_executor",
            "hypothesis_builder": "hypothesis_builder",
        },
    )
    g.add_conditional_edges(
        "tool_executor",
        route_after_tools,
        {"hypothesis_builder": "hypothesis_builder"},
    )
    g.add_conditional_edges(
        "hypothesis_builder",
        route_after_hypothesis,
        {"knowledge_loader": "knowledge_loader", "judge": "judge"},
    )
    g.add_edge("knowledge_loader", "auditor")
    g.add_conditional_edges(
        "auditor",
        route_after_auditor,
        {"skeptic": "skeptic", "judge": "judge", "validator": "validator"},
    )
    g.add_conditional_edges(
        "skeptic",
        route_after_skeptic,
        {"validator": "validator"},
    )
    g.add_conditional_edges(
        "validator",
        route_after_validator,
        {"judge": "judge", "reinvestigate": "reinvestigate"},
    )
    # Vòng điều tra mới quay về đúng chỗ chạy tool, không quay về Auditor.
    g.add_conditional_edges(
        "reinvestigate",
        route_after_planner,
        {
            "end": END,
            "tool_executor": "tool_executor",
            "hypothesis_builder": "hypothesis_builder",
        },
    )
    g.add_edge("judge", END)

    return g.compile()


aegis_graph = build_aegis_graph()


def run_triage(finding: NormalizedFinding, graph=None, **state_kwargs) -> GraphState:
    """Chạy một finding qua workflow, trả về GraphState đã validate."""
    compiled = graph or aegis_graph
    result = compiled.invoke(GraphState(finding=finding, **state_kwargs))
    if isinstance(result, GraphState):
        return result
    return GraphState.model_validate(result)

"""Biên dịch workflow multi-agent thành LangGraph."""

from typing import Callable

from langgraph.graph import END, StateGraph

from ..nodes.auditor import auditor_node
from ..nodes.hypothesis_builder import hypothesis_builder_node
from ..nodes.judge import judge_node
from ..nodes.knowledge_loader import knowledge_loader_node
from ..nodes.planner import planner_node
from ..nodes.skeptic import skeptic_node
from ..schemas.finding import NormalizedFinding
from ..schemas.state import GraphState
from .routing import (
    route_after_auditor,
    route_after_hypothesis,
    route_after_planner,
    route_after_skeptic,
)


def auditor_reround_node(state: GraphState) -> GraphState:
    new_state = state.model_copy(deep=True)
    new_state.debate_round += 1
    return auditor_node(new_state)


def _as_update(fn: Callable[[GraphState], GraphState]) -> Callable[[GraphState], dict]:
    """Node trả về GraphState; LangGraph cần dict các kênh cần ghi đè."""

    def wrapped(state: GraphState) -> dict:
        return fn(state).model_dump()

    wrapped.__name__ = fn.__name__
    return wrapped


def build_aegis_graph():
    g = StateGraph(GraphState)
    g.add_node("planner", _as_update(planner_node))
    g.add_node("hypothesis_builder", _as_update(hypothesis_builder_node))
    g.add_node("knowledge_loader", _as_update(knowledge_loader_node))
    g.add_node("auditor", _as_update(auditor_node))
    g.add_node("skeptic", _as_update(skeptic_node))
    g.add_node("auditor_reround", _as_update(auditor_reround_node))
    g.add_node("judge", _as_update(judge_node))

    g.set_entry_point("planner")
    g.add_conditional_edges(
        "planner",
        route_after_planner,
        {"end": END, "hypothesis_builder": "hypothesis_builder"},
    )
    g.add_conditional_edges(
        "hypothesis_builder",
        route_after_hypothesis,
        {"knowledge_loader": "knowledge_loader", "judge": "judge"},
    )
    g.add_edge("knowledge_loader", "auditor")
    g.add_conditional_edges(
        "auditor", route_after_auditor, {"skeptic": "skeptic", "judge": "judge"}
    )
    g.add_conditional_edges(
        "skeptic",
        route_after_skeptic,
        {"auditor_reround": "auditor_reround", "judge": "judge"},
    )
    g.add_conditional_edges(
        "auditor_reround",
        route_after_auditor,
        {"skeptic": "skeptic", "judge": "judge"},
    )
    g.add_edge("judge", END)

    return g.compile()


aegis_graph = build_aegis_graph()


def run_triage(finding: NormalizedFinding, graph=None) -> GraphState:
    """Chạy một finding qua workflow, trả về GraphState đã validate."""
    compiled = graph or aegis_graph
    result = compiled.invoke(GraphState(finding=finding))
    if isinstance(result, GraphState):
        return result
    return GraphState.model_validate(result)

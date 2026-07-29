"""Optional LangGraph adapter for the AI triage workflow."""

from typing import Any

from aegis_sast.orchestration.ai_workflow import AITriageWorkflow


class LangGraphUnavailable(RuntimeError):
    """Raised when LangGraph is requested but not installed."""


def build_langgraph_workflow(workflow: AITriageWorkflow | None = None) -> Any:
    """
    Build a minimal LangGraph app when langgraph is installed.

    The default tests do not require langgraph. This adapter keeps the workflow
    importable and gives deployments a single place to compile a graph later.
    """
    try:
        from langgraph.graph import END, StateGraph
    except ImportError as exc:  # pragma: no cover - depends on optional install
        raise LangGraphUnavailable(
            "LangGraph is not installed. Install langgraph to compile the graph."
        ) from exc

    workflow = workflow or AITriageWorkflow()

    def run_batch(state: dict) -> dict:
        result = workflow.run_batch(state.get("triage_inputs", []))
        return result.to_dict()

    graph = StateGraph(dict)
    graph.add_node("ai_triage_workflow", run_batch)
    graph.set_entry_point("ai_triage_workflow")
    graph.add_edge("ai_triage_workflow", END)
    return graph.compile()

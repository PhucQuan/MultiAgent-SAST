"""Minimal LangGraph bridge for staged workflow orchestration.

This module does not replace the current deterministic workflow. Instead, it
wraps the existing ScanWorkflow in a LangGraph-compatible graph so the project
can begin using LangGraph without rewriting the surrounding contracts.
"""

from __future__ import annotations

from typing import Any, Callable, NotRequired, TypedDict

from aegis_sast.core.models import ScanResult
from aegis_sast.orchestration.state import RepoProfile, ScanWorkflowState
from aegis_sast.orchestration.workflow import ScanWorkflow

try:  # pragma: no cover - exercised via smoke test when dependency exists
    from langgraph.graph import END, START, StateGraph
except ImportError:  # pragma: no cover - lightweight compatibility shim
    START = "__start__"
    END = "__end__"

    class _CompiledStateGraph:
        """Small invoke-only graph shim for environments missing langgraph.graph."""

        def __init__(
            self,
            nodes: dict[str, Callable[[WorkflowGraphInput], WorkflowGraphInput]],
            edges: dict[str, list[str]],
            conditional_edges: dict[
                str,
                tuple[
                    Callable[[WorkflowGraphInput], str],
                    dict[str, str],
                ],
            ],
        ) -> None:
            self._nodes = nodes
            self._edges = edges
            self._conditional_edges = conditional_edges

        def invoke(self, state: WorkflowGraphInput) -> WorkflowGraphInput:
            """Execute the staged workflow with START/END semantics."""
            current = self._edges.get(START, [END])[0]
            current_state = dict(state)

            while current != END:
                node = self._nodes[current]
                current_state = node(current_state)

                if current in self._conditional_edges:
                    router, mapping = self._conditional_edges[current]
                    current = mapping[router(current_state)]
                    continue

                current = self._edges.get(current, [END])[0]

            return current_state

    class StateGraph:
        """Compatibility subset of the LangGraph StateGraph API used by Aegis."""

        def __init__(self, _state_type: type[TypedDict]) -> None:
            self._nodes: dict[str, Callable[[WorkflowGraphInput], WorkflowGraphInput]] = {}
            self._edges: dict[str, list[str]] = {}
            self._conditional_edges: dict[
                str,
                tuple[
                    Callable[[WorkflowGraphInput], str],
                    dict[str, str],
                ],
            ] = {}

        def add_node(
            self,
            name: str,
            func: Callable[[WorkflowGraphInput], WorkflowGraphInput],
        ) -> None:
            self._nodes[name] = func

        def add_edge(self, source: str, target: str) -> None:
            self._edges.setdefault(source, []).append(target)

        def add_conditional_edges(
            self,
            source: str,
            router: Callable[[WorkflowGraphInput], str],
            mapping: dict[str, str],
        ) -> None:
            self._conditional_edges[source] = (router, mapping)

        def compile(self) -> _CompiledStateGraph:
            return _CompiledStateGraph(
                nodes=dict(self._nodes),
                edges={key: list(value) for key, value in self._edges.items()},
                conditional_edges=dict(self._conditional_edges),
            )


class WorkflowGraphInput(TypedDict):
    """Input and output state for the minimal LangGraph bridge."""

    scan_result: ScanResult
    repo_profile: NotRequired[RepoProfile | None]
    workflow_state: NotRequired[ScanWorkflowState]
    ai_client: NotRequired[Any | None]


def build_scan_workflow_graph(
    workflow: ScanWorkflow | None = None,
    ai_client: Any | None = None,
):
    """Compile a minimal LangGraph wrapper around the current ScanWorkflow.

    The current repository already has node-like reviewer roles and stable
    workflow state. This bridge keeps that deterministic implementation intact
    while exposing a real LangGraph entrypoint for future expansion into a
    richer multi-node graph. When an AI client is provided, the bridge also
    applies the existing structured AI triage overlay inside the graph.
    """

    workflow = workflow or ScanWorkflow()
    graph = StateGraph(WorkflowGraphInput)

    def run_workflow_node(state: WorkflowGraphInput) -> WorkflowGraphInput:
        repo_profile = state.get("repo_profile")
        workflow_state = workflow.run(
            state["scan_result"],
            repo_profile=repo_profile,
        )
        return {
            **state,
            "workflow_state": workflow_state,
        }

    def apply_ai_triage_node(state: WorkflowGraphInput) -> WorkflowGraphInput:
        workflow_state = state["workflow_state"]
        ai_backend = state.get("ai_client")
        if ai_backend is None or not workflow_state.triage_records:
            return state

        from aegis_sast.orchestration.service import ScanPipelineService

        reviewed_records, workflow_metadata = (
            ScanPipelineService._apply_ai_triage_overlay(
                ai_backend,
                list(workflow_state.triage_records),
                dict(workflow_state.metadata),
            )
        )
        workflow_state.triage_records = list(reviewed_records)
        workflow_state.findings = [record.finding for record in reviewed_records]
        workflow_state.metadata = dict(workflow_metadata)
        workflow_state.add_trace(
            "ai_triage_overlay",
            "Applied AI triage overlay inside the LangGraph workflow.",
            metadata={
                "provider": ScanPipelineService._resolve_ai_provider_name(ai_backend),
                "model": ScanPipelineService._resolve_ai_model_name(ai_backend),
            },
        )
        return {
            **state,
            "workflow_state": workflow_state,
        }

    graph.add_node("run_workflow", run_workflow_node)
    graph.add_node("apply_ai_triage", apply_ai_triage_node)
    graph.add_edge(START, "run_workflow")

    def route_after_workflow(state: WorkflowGraphInput):
        if state.get("ai_client") is not None:
            return "apply_ai_triage"
        return END

    graph.add_conditional_edges(
        "run_workflow",
        route_after_workflow,
        {
            "apply_ai_triage": "apply_ai_triage",
            END: END,
        },
    )
    graph.add_edge("apply_ai_triage", END)
    return graph.compile()


def run_scan_workflow_graph(
    scan_result: ScanResult,
    repo_profile: RepoProfile | None = None,
    workflow: ScanWorkflow | None = None,
    ai_client: Any | None = None,
) -> ScanWorkflowState:
    """Run the current workflow through a compiled LangGraph wrapper."""

    compiled_graph = build_scan_workflow_graph(
        workflow=workflow,
        ai_client=ai_client,
    )
    final_state = compiled_graph.invoke(
        {
            "scan_result": scan_result,
            "repo_profile": repo_profile,
            "ai_client": ai_client,
        }
    )
    return final_state["workflow_state"]

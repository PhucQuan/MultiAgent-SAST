"""Workflow-state scaffolding for future agent orchestration."""

from typing import TYPE_CHECKING

from aegis_sast.orchestration.router import WorkflowRoute, route_finding
from aegis_sast.orchestration.state import (
    AgentWorkflowState,
    RepoProfile,
    WorkflowStepTrace,
    ScanWorkflowState,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_sast.orchestration.context import (
        EvidenceContext,
        SourceContextReader,
        SourceContextWindow,
    )
    from aegis_sast.orchestration.contracts import (
        AuditorInput,
        AuditorResult,
        AuditorReview,
        JudgeInput,
        JudgeReview,
        KnowledgeLoaderNodeInput,
        KnowledgeLoaderNodeResult,
        PlannerInput,
        PlannerResult,
        ReporterInput,
        ReportEnrichment,
        SkepticInput,
        SkepticResult,
        SkepticReview,
    )
    from aegis_sast.orchestration.ai_workflow import AITriageWorkflow
    from aegis_sast.orchestration.nodes import (
        AuditorNode,
        JudgeNode,
        SkepticValidatorNode,
    )
    from aegis_sast.orchestration.repo_intake import RepoIntake
    from aegis_sast.orchestration.workflow import ScanWorkflow

__all__ = [
    "AITriageWorkflow",
    "AuditorInput",
    "AuditorNode",
    "AuditorResult",
    "AuditorReview",
    "EvidenceContext",
    "AgentWorkflowState",
    "JudgeInput",
    "JudgeNode",
    "JudgeReview",
    "KnowledgeLoaderNodeInput",
    "KnowledgeLoaderNodeResult",
    "PlannerInput",
    "PlannerResult",
    "ReporterInput",
    "ReportEnrichment",
    "WorkflowRoute",
    "route_finding",
    "RepoProfile",
    "RepoIntake",
    "WorkflowStepTrace",
    "ScanWorkflowState",
    "ScanWorkflow",
    "SkepticInput",
    "SkepticResult",
    "SkepticReview",
    "SkepticValidatorNode",
    "SourceContextReader",
    "SourceContextWindow",
]


def __getattr__(name):
    """Lazily load workflow helpers to avoid package import cycles."""
    if name == "ScanWorkflow":
        from aegis_sast.orchestration.workflow import ScanWorkflow

        return ScanWorkflow
    if name == "AITriageWorkflow":
        from aegis_sast.orchestration.ai_workflow import AITriageWorkflow

        return AITriageWorkflow
    if name == "RepoIntake":
        from aegis_sast.orchestration.repo_intake import RepoIntake

        return RepoIntake
    if name == "SourceContextWindow":
        from aegis_sast.orchestration.context import SourceContextWindow

        return SourceContextWindow
    if name == "EvidenceContext":
        from aegis_sast.orchestration.context import EvidenceContext

        return EvidenceContext
    if name == "SourceContextReader":
        from aegis_sast.orchestration.context import SourceContextReader

        return SourceContextReader
    contract_names = {
        "AuditorInput",
        "JudgeInput",
        "KnowledgeLoaderNodeInput",
        "KnowledgeLoaderNodeResult",
        "PlannerInput",
        "PlannerResult",
        "ReporterInput",
        "ReportEnrichment",
        "SkepticInput",
    }
    if name in contract_names:
        import aegis_sast.orchestration.contracts as contracts

        return getattr(contracts, name)
    if name == "AuditorResult":
        from aegis_sast.orchestration.contracts import AuditorResult

        return AuditorResult
    if name == "AuditorReview":
        from aegis_sast.orchestration.contracts import AuditorReview

        return AuditorReview
    if name == "SkepticResult":
        from aegis_sast.orchestration.contracts import SkepticResult

        return SkepticResult
    if name == "SkepticReview":
        from aegis_sast.orchestration.contracts import SkepticReview

        return SkepticReview
    if name == "JudgeReview":
        from aegis_sast.orchestration.contracts import JudgeReview

        return JudgeReview
    if name == "AuditorNode":
        from aegis_sast.orchestration.nodes import AuditorNode

        return AuditorNode
    if name == "SkepticValidatorNode":
        from aegis_sast.orchestration.nodes import SkepticValidatorNode

        return SkepticValidatorNode
    if name == "JudgeNode":
        from aegis_sast.orchestration.nodes import JudgeNode

        return JudgeNode
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

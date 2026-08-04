"""Workflow-state scaffolding for future agent orchestration."""

from typing import TYPE_CHECKING

from aegis_sast.orchestration.router import WorkflowRoute, route_finding
from aegis_sast.orchestration.state import (
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
        AuditorReview,
        JudgeReview,
        SkepticReview,
    )
    from aegis_sast.orchestration.nodes import (
        AuditorNode,
        JudgeNode,
        SkepticValidatorNode,
    )
    from aegis_sast.orchestration.repo_intake import RepoIntake
    from aegis_sast.orchestration.service import (
        ScanPipelineRequest,
        ScanPipelineResult,
        ScanPipelineService,
    )
    from aegis_sast.orchestration.workflow import ScanWorkflow

__all__ = [
    "AuditorNode",
    "AuditorReview",
    "EvidenceContext",
    "JudgeNode",
    "JudgeReview",
    "WorkflowRoute",
    "route_finding",
    "RepoProfile",
    "RepoIntake",
    "WorkflowStepTrace",
    "ScanWorkflowState",
    "ScanWorkflow",
    "SkepticReview",
    "SkepticValidatorNode",
    "ScanPipelineRequest",
    "ScanPipelineResult",
    "ScanPipelineService",
    "SourceContextReader",
    "SourceContextWindow",
]


def __getattr__(name):
    """Lazily load workflow helpers to avoid package import cycles."""
    if name == "ScanWorkflow":
        from aegis_sast.orchestration.workflow import ScanWorkflow

        return ScanWorkflow
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
    if name == "AuditorReview":
        from aegis_sast.orchestration.contracts import AuditorReview

        return AuditorReview
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
    if name == "ScanPipelineRequest":
        from aegis_sast.orchestration.service import ScanPipelineRequest

        return ScanPipelineRequest
    if name == "ScanPipelineResult":
        from aegis_sast.orchestration.service import ScanPipelineResult

        return ScanPipelineResult
    if name == "ScanPipelineService":
        from aegis_sast.orchestration.service import ScanPipelineService

        return ScanPipelineService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

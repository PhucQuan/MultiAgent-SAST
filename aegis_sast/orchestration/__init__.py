"""Workflow-state scaffolding for future agent orchestration."""

from typing import TYPE_CHECKING

from aegis_sast.orchestration.router import WorkflowRoute, route_finding
from aegis_sast.orchestration.state import (
    RepoProfile,
    WorkflowStepTrace,
    ScanWorkflowState,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_sast.orchestration.repo_intake import RepoIntake
    from aegis_sast.orchestration.workflow import ScanWorkflow

__all__ = [
    "WorkflowRoute",
    "route_finding",
    "RepoProfile",
    "RepoIntake",
    "WorkflowStepTrace",
    "ScanWorkflowState",
    "ScanWorkflow",
]


def __getattr__(name):
    """Lazily load workflow helpers to avoid package import cycles."""
    if name == "ScanWorkflow":
        from aegis_sast.orchestration.workflow import ScanWorkflow

        return ScanWorkflow
    if name == "RepoIntake":
        from aegis_sast.orchestration.repo_intake import RepoIntake

        return RepoIntake
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

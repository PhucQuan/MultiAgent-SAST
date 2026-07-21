"""Pydantic state containers for AI-ready workflow orchestration."""

from typing import Any, Dict, List, Optional

from pydantic import Field

from aegis_sast.core.models import NormalizedFinding as CoreNormalizedFinding
from aegis_sast.triage.schema import (
    AITriageInput,
    StrictContractModel,
    TriageRecord,
)


class RepoProfile(StrictContractModel):
    """Metadata collected during repo intake and language detection."""

    target_path: str
    scan_profile: str = "generic"
    detected_languages: List[str] = Field(default_factory=list)
    framework_hints: List[str] = Field(default_factory=list)
    files_scanned: int = Field(default=0, ge=0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WorkflowStepTrace(StrictContractModel):
    """Captures one step in the orchestration flow for debugging and audits."""

    node_name: str
    summary: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentWorkflowState(StrictContractModel):
    """AI-layer state that only accepts normalized deterministic inputs."""

    triage_inputs: List[AITriageInput] = Field(default_factory=list)
    traces: List[WorkflowStepTrace] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def add_trace(
        self,
        node_name: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append a trace record for workflow inspection."""
        self.traces.append(
            WorkflowStepTrace(
                node_name=node_name,
                summary=summary,
                metadata=metadata or {},
            )
        )


class ScanWorkflowState(StrictContractModel):
    """Shared state between deterministic analysis and structured agent nodes."""

    repo_profile: Optional[RepoProfile] = None
    findings: List[CoreNormalizedFinding] = Field(default_factory=list)
    triage_records: List[TriageRecord] = Field(default_factory=list)
    knowledge_refs: List[str] = Field(default_factory=list)
    traces: List[WorkflowStepTrace] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def add_trace(
        self,
        node_name: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append a trace record for workflow inspection."""
        self.traces.append(
            WorkflowStepTrace(
                node_name=node_name,
                summary=summary,
                metadata=metadata or {},
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert workflow state into a JSON-friendly structure."""
        return {
            "repo_profile": (self.repo_profile.to_dict() if self.repo_profile else None),
            "findings": [finding.to_dict() for finding in self.findings],
            "triage_records": [record.to_dict() for record in self.triage_records],
            "knowledge_refs": self.knowledge_refs,
            "traces": [trace.to_dict() for trace in self.traces],
            "errors": self.errors,
            "metadata": self.metadata,
        }

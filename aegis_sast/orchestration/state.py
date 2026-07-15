"""State containers for a future LangGraph or workflow-based agent loop."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aegis_sast.core.models import NormalizedFinding
from aegis_sast.triage.schema import TriageRecord


@dataclass
class RepoProfile:
    """Metadata collected during repo intake and language detection."""

    target_path: str
    scan_profile: str = "generic"
    detected_languages: List[str] = field(default_factory=list)
    framework_hints: List[str] = field(default_factory=list)
    files_scanned: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert repo profile data to a JSON-friendly dictionary."""
        return {
            "target_path": self.target_path,
            "scan_profile": self.scan_profile,
            "detected_languages": self.detected_languages,
            "framework_hints": self.framework_hints,
            "files_scanned": self.files_scanned,
            "metadata": self.metadata,
        }


@dataclass
class WorkflowStepTrace:
    """Captures one step in the orchestration flow for debugging and audits."""

    node_name: str
    summary: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert trace data to a JSON-friendly dictionary."""
        return {
            "node_name": self.node_name,
            "summary": self.summary,
            "metadata": self.metadata,
        }


@dataclass
class ScanWorkflowState:
    """Shared state between deterministic analysis and future agent nodes."""

    repo_profile: Optional[RepoProfile] = None
    findings: List[NormalizedFinding] = field(default_factory=list)
    triage_records: List[TriageRecord] = field(default_factory=list)
    knowledge_refs: List[str] = field(default_factory=list)
    traces: List[WorkflowStepTrace] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

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
            "repo_profile": (
                self.repo_profile.to_dict() if self.repo_profile else None
            ),
            "findings": [finding.to_dict() for finding in self.findings],
            "triage_records": [record.to_dict() for record in self.triage_records],
            "knowledge_refs": self.knowledge_refs,
            "traces": [trace.to_dict() for trace in self.traces],
            "errors": self.errors,
            "metadata": self.metadata,
        }

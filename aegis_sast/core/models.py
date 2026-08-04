"""
Core data models for Aegis-SAST.

Defines the fundamental data structures for taint analysis, vulnerabilities,
and security findings.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities detected."""
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_INJECTION = "CODE_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    XPATH_INJECTION = "XPATH_INJECTION"
    LDAP_INJECTION = "LDAP_INJECTION"
    XXE = "XXE"
    SSRF = "SSRF"
    XSS = "XSS"
    NOSQL_INJECTION = "NOSQL_INJECTION"
    IDOR = "IDOR"
    SSTI = "SSTI"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    OPEN_REDIRECT = "OPEN_REDIRECT"


class TriageStatus(str, Enum):
    """Normalized triage statuses for downstream agent workflows."""
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    NEEDS_REVIEW = "needs-review"
    SUPPRESSED = "suppressed"


@dataclass
class FunctionEntry:
    """Metadata for an indexed function, used by the Call Graph."""
    name: str
    file_path: str
    line_number: int
    params: List[str]
    return_vars: List[str]          # variable names in return statements
    calls: List[str]                # function names called inside this function
    is_return_tainted: bool = False # set during Pass-2 taint propagation


@dataclass
class CodeLocation:
    """Represents a location in source code."""
    file_path: str
    line_number: int
    column_number: int
    code_snippet: str
    
    def __str__(self) -> str:
        return f"{self.file_path}:{self.line_number}:{self.column_number}"


@dataclass
class TaintSource:
    """Represents a source of untrusted data."""
    location: CodeLocation
    source_type: str  # e.g., "HTTP_PARAM", "USER_INPUT", "FILE_READ"
    variable_name: str
    pattern: str  # The pattern that matched (e.g., "request.args.get")
    
    def __str__(self) -> str:
        return f"{self.source_type} at {self.location}"


@dataclass
class TaintSink:
    """Represents a dangerous function call."""
    location: CodeLocation
    sink_type: VulnerabilityType
    function_name: str
    pattern: str  # The pattern that matched (e.g., "os.system")
    arguments: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return f"{self.sink_type.value} at {self.location}"


@dataclass
class Sanitizer:
    """Represents a data sanitization function."""
    location: CodeLocation
    sanitizer_type: str
    function_name: str
    mitigates: List[VulnerabilityType] = field(default_factory=list)
    
    def is_effective_against(self, vuln_type: VulnerabilityType) -> bool:
        """Check if this sanitizer mitigates the given vulnerability type."""
        return vuln_type in self.mitigates


@dataclass
class EvidenceBundle:
    """Structured evidence attached to a normalized finding."""
    source: CodeLocation
    sink: CodeLocation
    intermediate_steps: List[CodeLocation] = field(default_factory=list)
    sanitizers: List[Sanitizer] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_sanitizers(self) -> bool:
        """Return True when the path contains at least one sanitizer."""
        return bool(self.sanitizers)

    @property
    def detection_metadata(self) -> Dict[str, Any]:
        """Return stable detector metadata carried alongside the evidence."""
        detection = self.metadata.get("detection", {})
        return detection if isinstance(detection, dict) else {}

    @property
    def local_helper_summaries(self) -> List[Dict[str, Any]]:
        """Return local helper summaries when cross-file tracing captured them."""
        helpers = self.metadata.get("local_callee_summaries", [])
        return helpers if isinstance(helpers, list) else []

    @property
    def graph_slice(self) -> Dict[str, Any]:
        """Return a compact graph slice suitable for AI triage prompts."""
        graph_summary = self.metadata.get("graph_summary", {})
        graph_slice: Dict[str, Any] = {}

        if graph_summary:
            graph_slice.update(
                {
                    "node_count": graph_summary.get("node_count", 0),
                    "cfg_edge_count": graph_summary.get("cfg_edge_count", 0),
                    "dfg_edge_count": graph_summary.get("dfg_edge_count", 0),
                }
            )
        if "cfg_path_node_ids" in self.metadata:
            graph_slice["path_node_count"] = len(self.metadata.get("cfg_path_node_ids", []))
        if "dfg_path_edges" in self.metadata:
            graph_slice["path_edge_count"] = len(self.metadata.get("dfg_path_edges", []))
        if self.local_helper_summaries:
            graph_slice["local_helper_count"] = len(self.local_helper_summaries)

        return graph_slice

    @staticmethod
    def _location_to_dict(location: CodeLocation) -> Dict[str, Any]:
        """Serialize one code location into a stable JSON-friendly payload."""
        return {
            "file": location.file_path,
            "line": location.line_number,
            "column": location.column_number,
            "snippet": location.code_snippet,
        }

    @staticmethod
    def _sanitizer_to_dict(sanitizer: Sanitizer) -> Dict[str, Any]:
        """Serialize one sanitizer entry into a stable JSON-friendly payload."""
        return {
            "type": sanitizer.sanitizer_type,
            "function": sanitizer.function_name,
            "location": EvidenceBundle._location_to_dict(sanitizer.location),
            "mitigates": [
                vuln_type.value for vuln_type in sanitizer.mitigates
            ],
        }

    @property
    def path_summary(self) -> List[str]:
        """Return a compact source-to-sink path summary for triage/reporting."""
        source_type = self.detection_metadata.get("source_type")
        sink_function = self.detection_metadata.get("sink_function")

        source_label = (
            f"SOURCE[{source_type}] {self.source}"
            if source_type
            else str(self.source)
        )
        sink_label = (
            f"SINK[{sink_function}] {self.sink}"
            if sink_function
            else str(self.sink)
        )

        steps = [source_label]
        steps.extend(str(step) for step in self.intermediate_steps)
        steps.extend(
            f"[SANITIZER] {sanitizer.function_name} at {sanitizer.location}"
            for sanitizer in self.sanitizers
        )
        steps.append(sink_label)
        return steps

    @property
    def summary(self) -> Dict[str, Any]:
        """Return a small, stable evidence summary for triage consumers."""
        summary = {
            "path_length": len(self.path_summary),
            "intermediate_step_count": len(self.intermediate_steps),
            "sanitizer_count": len(self.sanitizers),
            "has_sanitizers": self.has_sanitizers,
            "path_summary": self.path_summary,
        }

        graph_slice = self.graph_slice
        if graph_slice:
            summary["graph_slice"] = graph_slice

        return summary

    @property
    def evidence_pack(self) -> Dict[str, Any]:
        """Return a stable evidence pack for AI triage and benchmark exports."""
        summary = self.summary
        compact_summary = {
            "path_length": summary.get("path_length", 0),
            "intermediate_step_count": summary.get("intermediate_step_count", 0),
            "sanitizer_count": summary.get("sanitizer_count", 0),
            "has_sanitizers": summary.get("has_sanitizers", False),
        }

        return {
            "source": self._location_to_dict(self.source),
            "sink": self._location_to_dict(self.sink),
            "intermediate_steps": [
                self._location_to_dict(step) for step in self.intermediate_steps
            ],
            "sanitizers": [
                self._sanitizer_to_dict(sanitizer) for sanitizer in self.sanitizers
            ],
            "path_summary": summary.get("path_summary", []),
            "summary": compact_summary,
            "graph_slice": self.graph_slice,
            "detection": self.detection_metadata,
            "local_helper_summaries": self.local_helper_summaries,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert the evidence bundle to a JSON-friendly dictionary."""
        return {
            "source": self._location_to_dict(self.source),
            "sink": self._location_to_dict(self.sink),
            "intermediate_steps": [
                self._location_to_dict(step)
                for step in self.intermediate_steps
            ],
            "sanitizers": [
                self._sanitizer_to_dict(sanitizer)
                for sanitizer in self.sanitizers
            ],
            "metadata": self.metadata,
            "summary": self.summary,
        }


@dataclass
class DataFlowPath:
    """Represents the flow of tainted data from source to sink."""
    source: TaintSource
    sink: TaintSink
    intermediate_steps: List[CodeLocation] = field(default_factory=list)
    sanitizers: List[Sanitizer] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_sanitized(self) -> bool:
        """Check if the dataflow path contains effective sanitization."""
        if not self.sanitizers:
            return False
        
        # Check if any sanitizer is effective against the sink type
        return any(
            sanitizer.is_effective_against(self.sink.sink_type)
            for sanitizer in self.sanitizers
        )
    
    def get_path_summary(self) -> List[str]:
        """Get a human-readable summary of the dataflow path."""
        steps = [str(self.source)]
        steps.extend([str(step) for step in self.intermediate_steps])
        
        # Add sanitizer info if present
        for sanitizer in self.sanitizers:
            steps.append(f"[SANITIZER] {sanitizer.function_name} at {sanitizer.location}")
        
        steps.append(str(self.sink))
        return steps


@dataclass
class AIVerification:
    """Results from AI-based vulnerability verification."""
    is_vulnerable: bool
    confidence: float  # 0.0 to 1.0
    explanation: str
    recommendation: str
    model_used: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class NormalizedFinding:
    """Stable schema for reporting, triage, and future agent workflows."""
    id: str
    tool: str
    language: Optional[str]
    rule_id: str
    vulnerability_type: str
    severity: Severity
    triage_status: TriageStatus
    confidence: float
    file_path: str
    line_number: int
    message: str
    evidence: EvidenceBundle
    explanation: Optional[str] = None
    recommendation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.now)

    @property
    def detection_metadata(self) -> Dict[str, Any]:
        """Return nested detection metadata when available."""
        detection = self.metadata.get("detection", {})
        return detection if isinstance(detection, dict) else {}

    @property
    def triage_metadata(self) -> Dict[str, Any]:
        """Return nested triage metadata when available."""
        triage = self.metadata.get("triage", {})
        return triage if isinstance(triage, dict) else {}

    @property
    def evidence_summary(self) -> Dict[str, Any]:
        """Return the stable evidence summary consumed by triage layers."""
        return self.evidence.summary

    @property
    def is_effectively_sanitized(self) -> bool:
        """Return True when the path contains an effective sanitizer."""
        if "is_sanitized" in self.detection_metadata:
            return bool(self.detection_metadata.get("is_sanitized"))
        return bool(self.metadata.get("is_sanitized", False))

    def to_dict(self) -> Dict[str, Any]:
        """Convert the normalized finding to a JSON-friendly dictionary."""
        return {
            "id": self.id,
            "tool": self.tool,
            "language": self.language,
            "rule_id": self.rule_id,
            "type": self.vulnerability_type,
            "severity": self.severity.value,
            "triage_status": self.triage_status.value,
            "confidence": self.confidence,
            "file": self.file_path,
            "line": self.line_number,
            "message": self.message,
            "evidence": self.evidence.to_dict(),
            "triage_input": self.to_triage_input(),
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }

    def to_triage_input(self) -> Dict[str, Any]:
        """Build a stable AI-ready triage contract from the normalized finding."""
        return {
            "schema_version": "aegis-triage-input-v1",
            "finding": {
                "id": self.id,
                "tool": self.tool,
                "language": self.language,
                "rule_id": self.rule_id,
                "type": self.vulnerability_type,
                "severity": self.severity.value,
                "triage_status": self.triage_status.value,
                "confidence": self.confidence,
                "file": self.file_path,
                "line": self.line_number,
                "message": self.message,
            },
            "evidence": self.evidence.evidence_pack,
            "guidance": {
                "explanation": self.explanation,
                "recommendation": self.recommendation,
            },
            "metadata": {
                "detected_at": self.detected_at.isoformat(),
                "detection": self.detection_metadata,
                "triage": self.triage_metadata,
            },
        }


@dataclass
class Vulnerability:
    """Represents a detected security vulnerability."""
    id: str  # Unique identifier (e.g., "VULN-001")
    vuln_type: VulnerabilityType
    severity: Severity
    dataflow: DataFlowPath
    ai_verification: Optional[AIVerification] = None
    
    # Metadata
    detected_at: datetime = field(default_factory=datetime.now)
    
    @property
    def file_path(self) -> str:
        """Get the file path where the vulnerability was found."""
        return self.dataflow.sink.location.file_path
    
    @property
    def line_number(self) -> int:
        """Get the line number of the vulnerability."""
        return self.dataflow.sink.location.line_number
    
    @property
    def is_confirmed(self) -> bool:
        """Check if vulnerability is confirmed by AI."""
        if not self.ai_verification:
            return True  # Assume true if no AI verification
        return self.ai_verification.is_vulnerable

    def _default_confidence(self) -> float:
        """Return a stable fallback confidence for non-triaged findings."""
        if self.ai_verification:
            return self.ai_verification.confidence
        return 0.5

    def infer_triage_status(self) -> TriageStatus:
        """
        Map the current finding into a normalized triage status.

        This is intentionally conservative:
        - no AI verification -> needs-review
        - AI says not vulnerable -> suppressed
        - AI says vulnerable with high confidence -> confirmed
        - AI says vulnerable with lower confidence -> likely
        """
        if not self.ai_verification:
            return TriageStatus.NEEDS_REVIEW

        if not self.ai_verification.is_vulnerable:
            return TriageStatus.SUPPRESSED

        if self.ai_verification.confidence >= 0.85:
            return TriageStatus.CONFIRMED

        return TriageStatus.LIKELY

    def to_evidence_bundle(self) -> EvidenceBundle:
        """Project the current dataflow into a reusable evidence schema."""
        source = self.dataflow.source
        sink = self.dataflow.sink
        detection_metadata = {
            "source_type": source.source_type,
            "source_pattern": source.pattern,
            "sink_pattern": sink.pattern,
            "sink_function": sink.function_name,
            "is_sanitized": self.dataflow.is_sanitized(),
        }
        evidence_metadata = dict(self.dataflow.metadata)
        evidence_metadata.setdefault("path_summary", self.dataflow.get_path_summary())
        evidence_metadata.setdefault("path_length", len(evidence_metadata["path_summary"]))
        evidence_metadata.setdefault(
            "intermediate_step_count",
            len(self.dataflow.intermediate_steps),
        )
        evidence_metadata.setdefault("sanitizer_count", len(self.dataflow.sanitizers))
        evidence_metadata.setdefault("detection", detection_metadata)

        return EvidenceBundle(
            source=self.dataflow.source.location,
            sink=self.dataflow.sink.location,
            intermediate_steps=list(self.dataflow.intermediate_steps),
            sanitizers=list(self.dataflow.sanitizers),
            metadata=evidence_metadata,
        )

    def to_normalized_finding(
        self,
        tool: str = "aegis-sast",
        language: Optional[str] = None,
    ) -> NormalizedFinding:
        """Convert the current finding into the normalized reporting schema."""
        if language is None:
            language = _infer_language_from_path(self.file_path)

        source = self.dataflow.source
        sink = self.dataflow.sink
        evidence_bundle = self.to_evidence_bundle()
        detection_metadata = {
            "source_type": source.source_type,
            "source_pattern": source.pattern,
            "sink_pattern": sink.pattern,
            "sink_function": sink.function_name,
            "is_sanitized": self.dataflow.is_sanitized(),
            "dataflow_metadata": dict(self.dataflow.metadata),
            "evidence_summary": evidence_bundle.summary,
        }
        triage_metadata = {}
        if self.ai_verification:
            triage_metadata["ai_model"] = self.ai_verification.model_used

        return NormalizedFinding(
            id=self.id,
            tool=tool,
            language=language,
            rule_id=self.vuln_type.value,
            vulnerability_type=self.vuln_type.value,
            severity=self.severity,
            triage_status=self.infer_triage_status(),
            confidence=self._default_confidence(),
            file_path=self.file_path,
            line_number=self.line_number,
            message=(
                f"Potential {self.vuln_type.value} from "
                f"{source.variable_name} to {sink.function_name}"
            ),
            evidence=evidence_bundle,
            explanation=(
                self.ai_verification.explanation
                if self.ai_verification else None
            ),
            recommendation=(
                self.ai_verification.recommendation
                if self.ai_verification else None
            ),
            metadata={
                **detection_metadata,
                "ai_model": (
                    self.ai_verification.model_used
                    if self.ai_verification else None
                ),
                "detection": detection_metadata,
                "triage": triage_metadata,
            },
            detected_at=self.detected_at,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        normalized = self.to_normalized_finding()
        return {
            "id": self.id,
            "type": self.vuln_type.value,
            "severity": self.severity.value,
            "file": self.file_path,
            "line": self.line_number,
            "dataflow": self.dataflow.get_path_summary(),
            "is_sanitized": self.dataflow.is_sanitized(),
            "tool": normalized.tool,
            "language": normalized.language,
            "triage_status": normalized.triage_status.value,
            "confidence": normalized.confidence,
            "message": normalized.message,
            "evidence": normalized.evidence.to_dict(),
            "triage_input": normalized.to_triage_input(),
            "ai_verification": {
                "is_vulnerable": self.ai_verification.is_vulnerable,
                "confidence": self.ai_verification.confidence,
                "explanation": self.ai_verification.explanation,
                "recommendation": self.ai_verification.recommendation,
            } if self.ai_verification else None,
            "detected_at": self.detected_at.isoformat(),
        }


def _infer_language_from_path(file_path: str) -> Optional[str]:
    """Infer the language name from a file extension."""
    suffix = Path(file_path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".php": "php",
    }.get(suffix)


@dataclass
class ScanResult:
    """Results of a complete security scan."""
    target_path: str
    start_time: datetime
    end_time: datetime
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    files_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_vulnerabilities(self) -> int:
        """Total number of vulnerabilities found."""
        return len(self.vulnerabilities)
    
    @property
    def critical_count(self) -> int:
        """Number of critical vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Number of high severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        """Number of medium severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        """Number of low severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)
    
    @property
    def duration(self) -> float:
        """Scan duration in seconds."""
        return (self.end_time - self.start_time).total_seconds()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of scan results."""
        return {
            "target": self.target_path,
            "duration_seconds": self.duration,
            "files_scanned": self.files_scanned,
            "total_vulnerabilities": self.total_vulnerabilities,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "errors": self.errors,
        }

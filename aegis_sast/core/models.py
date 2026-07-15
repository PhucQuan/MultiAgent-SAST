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

    @property
    def has_sanitizers(self) -> bool:
        """Return True when the path contains at least one sanitizer."""
        return bool(self.sanitizers)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the evidence bundle to a JSON-friendly dictionary."""
        return {
            "source": {
                "file": self.source.file_path,
                "line": self.source.line_number,
                "column": self.source.column_number,
                "snippet": self.source.code_snippet,
            },
            "sink": {
                "file": self.sink.file_path,
                "line": self.sink.line_number,
                "column": self.sink.column_number,
                "snippet": self.sink.code_snippet,
            },
            "intermediate_steps": [
                {
                    "file": step.file_path,
                    "line": step.line_number,
                    "column": step.column_number,
                    "snippet": step.code_snippet,
                }
                for step in self.intermediate_steps
            ],
            "sanitizers": [
                {
                    "type": sanitizer.sanitizer_type,
                    "function": sanitizer.function_name,
                    "location": {
                        "file": sanitizer.location.file_path,
                        "line": sanitizer.location.line_number,
                        "column": sanitizer.location.column_number,
                        "snippet": sanitizer.location.code_snippet,
                    },
                    "mitigates": [
                        vuln_type.value for vuln_type in sanitizer.mitigates
                    ],
                }
                for sanitizer in self.sanitizers
            ],
        }


@dataclass
class DataFlowPath:
    """Represents the flow of tainted data from source to sink."""
    source: TaintSource
    sink: TaintSink
    intermediate_steps: List[CodeLocation] = field(default_factory=list)
    sanitizers: List[Sanitizer] = field(default_factory=list)
    
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
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
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
        return EvidenceBundle(
            source=self.dataflow.source.location,
            sink=self.dataflow.sink.location,
            intermediate_steps=list(self.dataflow.intermediate_steps),
            sanitizers=list(self.dataflow.sanitizers),
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
            evidence=self.to_evidence_bundle(),
            explanation=(
                self.ai_verification.explanation
                if self.ai_verification else None
            ),
            recommendation=(
                self.ai_verification.recommendation
                if self.ai_verification else None
            ),
            metadata={
                "source_type": source.source_type,
                "source_pattern": source.pattern,
                "sink_pattern": sink.pattern,
                "sink_function": sink.function_name,
                "is_sanitized": self.dataflow.is_sanitized(),
                "ai_model": (
                    self.ai_verification.model_used
                    if self.ai_verification else None
                ),
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

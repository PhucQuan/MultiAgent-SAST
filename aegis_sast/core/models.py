"""
Core data models for Aegis-SAST.

Defines the fundamental data structures for taint analysis, vulnerabilities,
and security findings.
"""

from dataclasses import dataclass, field
from enum import Enum
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
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "type": self.vuln_type.value,
            "severity": self.severity.value,
            "file": self.file_path,
            "line": self.line_number,
            "dataflow": self.dataflow.get_path_summary(),
            "is_sanitized": self.dataflow.is_sanitized(),
            "ai_verification": {
                "is_vulnerable": self.ai_verification.is_vulnerable,
                "confidence": self.ai_verification.confidence,
                "explanation": self.ai_verification.explanation,
                "recommendation": self.ai_verification.recommendation,
            } if self.ai_verification else None,
            "detected_at": self.detected_at.isoformat(),
        }


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

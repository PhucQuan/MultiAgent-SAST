"""Interface với Core SAST.

KHÔNG được sửa mà không thống nhất với Quân (chủ Core SAST).
Đây là contract duy nhất giữa detector/dataflow engine và multi-agent layer.
"""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    PHP = "php"


class Location(BaseModel):
    file: str
    line: int
    column: int | None = None
    symbol: str | None = None
    code_slice: str  # code quanh location, đánh dấu //potential


class DataFlowStep(BaseModel):
    file: str
    line: int
    kind: Literal["source", "propagate", "sanitizer", "sink"]
    code: str


class EvidenceBundle(BaseModel):
    source: Location
    sink: Location
    data_flow_path: list[DataFlowStep]
    sanitizers_seen: list[str] = Field(default_factory=list)
    evidence_quality: float = Field(ge=0.0, le=1.0)


class NormalizedFinding(BaseModel):
    finding_id: str
    vuln_type: str
    cwe: str
    language: Language
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: EvidenceBundle
    metadata: dict = Field(default_factory=dict)

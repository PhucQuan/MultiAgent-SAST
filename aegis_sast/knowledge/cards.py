"""Structured knowledge cards used by the triage layer."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class KnowledgeCard:
    """A structured security note bound to a language, CWE, and finding type."""

    card_id: str
    title: str
    language: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    finding_type: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    false_positive_patterns: List[str] = field(default_factory=list)
    remediation_notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the card to a JSON-friendly dictionary."""
        return {
            "card_id": self.card_id,
            "title": self.title,
            "language": self.language,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "finding_type": self.finding_type,
            "sources": self.sources,
            "sinks": self.sinks,
            "sanitizers": self.sanitizers,
            "false_positive_patterns": self.false_positive_patterns,
            "remediation_notes": self.remediation_notes,
            "metadata": self.metadata,
        }

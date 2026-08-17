"""Source context helpers for workflow nodes and future agent prompts."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from aegis_sast.core.models import CodeLocation, NormalizedFinding


@dataclass
class SourceContextWindow:
    """A bounded window of source code around one relevant location."""

    file_path: str
    focus_line: int
    start_line: int
    end_line: int
    lines: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Convert the window to a JSON-friendly dictionary."""
        return {
            "file_path": self.file_path,
            "focus_line": self.focus_line,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "lines": self.lines,
        }


@dataclass
class EvidenceContext:
    """Source windows attached to the source and sink sides of a finding."""

    source_window: Optional[SourceContextWindow] = None
    sink_window: Optional[SourceContextWindow] = None

    def to_dict(self) -> Dict[str, object]:
        """Convert the context bundle to a JSON-friendly dictionary."""
        return {
            "source_window": (
                self.source_window.to_dict() if self.source_window else None
            ),
            "sink_window": self.sink_window.to_dict() if self.sink_window else None,
        }


class SourceContextReader:
    """Load small, line-oriented context windows around finding evidence."""

    def __init__(self, radius: int = 15):
        self.radius = radius

    def read_for_finding(
        self,
        finding: NormalizedFinding,
        radius: Optional[int] = None,
    ) -> EvidenceContext:
        """Read source and sink windows for the provided finding."""
        active_radius = radius if radius is not None else self.radius
        return EvidenceContext(
            source_window=self.read_window(finding.evidence.source, active_radius),
            sink_window=self.read_window(finding.evidence.sink, active_radius),
        )

    @staticmethod
    def read_window(
        location: CodeLocation,
        radius: int,
    ) -> Optional[SourceContextWindow]:
        """Read a bounded source window around a code location."""
        path = Path(location.file_path)
        if not path.exists():
            return None

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None

        if not lines:
            return None

        focus_line = max(location.line_number, 1)
        start_line = max(focus_line - radius, 1)
        end_line = min(focus_line + radius, len(lines))
        window_lines = [
            f"{line_no}: {lines[line_no - 1]}"
            for line_no in range(start_line, end_line + 1)
        ]
        return SourceContextWindow(
            file_path=str(path),
            focus_line=focus_line,
            start_line=start_line,
            end_line=end_line,
            lines=window_lines,
        )

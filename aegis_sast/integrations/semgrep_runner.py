"""
Runs semgrep CLI and parses JSON output.
"""
from __future__ import annotations
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional

from aegis_sast.core.models import Severity

@dataclass
class SemgrepMatch:
    check_id: str
    file_path: str
    line: int
    col: int
    end_line: int
    end_col: int
    message: str
    severity: Severity
    metadata: Dict[str, Any] = field(default_factory=dict)
    metavars: Dict[str, Any] = field(default_factory=dict)
    code_snippet: str = ""

class SemgrepRunner:
    """Runner for executing semgrep and parsing its JSON output."""
    
    def __init__(self, rules_path: Optional[str] = None):
        if rules_path:
            self.rules_path = rules_path
        else:
            default_oss_dir = Path("rules/semgrep-oss-full/")
            if default_oss_dir.exists() and default_oss_dir.is_dir():
                self.rules_path = str(default_oss_dir)
            else:
                self.rules_path = "p/python"
                
    def _map_severity(self, semgrep_severity: str) -> Severity:
        semgrep_severity = semgrep_severity.upper()
        if semgrep_severity == "ERROR":
            return Severity.HIGH
        elif semgrep_severity == "WARNING":
            return Severity.MEDIUM
        elif semgrep_severity == "INFO":
            return Severity.LOW
        return Severity.UNKNOWN
        
    def run(self, target_path: str) -> List[SemgrepMatch]:
        """Runs semgrep and returns a list of SemgrepMatch objects."""
        cmd = [
            "semgrep",
            "scan",
            "--config",
            self.rules_path,
            "--json",
            target_path
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if not result.stdout:
                return []
                
            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError:
                return []
                
            matches = []
            results = output.get("results", [])
            for r in results:
                extra = r.get("extra", {})
                sev_str = extra.get("severity", "UNKNOWN")
                matches.append(
                    SemgrepMatch(
                        check_id=r.get("check_id", "unknown"),
                        file_path=r.get("path", "unknown"),
                        line=r.get("start", {}).get("line", 0),
                        col=r.get("start", {}).get("col", 0),
                        end_line=r.get("end", {}).get("line", 0),
                        end_col=r.get("end", {}).get("col", 0),
                        message=extra.get("message", ""),
                        severity=self._map_severity(sev_str),
                        metadata=extra.get("metadata", {}),
                        metavars=extra.get("metavars", {}),
                        code_snippet=extra.get("lines", "")
                    )
                )
            return matches
            
        except FileNotFoundError:
            print("Semgrep not installed or not found in PATH.")
            return []
        except Exception as e:
            print(f"Error running semgrep: {e}")
            return []

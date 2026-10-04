"""
Runs semgrep CLI and parses JSON output.
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
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
    language: str = ""
    fingerprint: str = ""

class SemgrepRunner:
    """Runner for executing semgrep and parsing its JSON output."""

    @staticmethod
    def _resolve_semgrep_executable() -> str:
        """Prefer the active Python venv's Semgrep binary, then PATH."""
        candidates: list[str] = []
        python_bin = Path(sys.executable).resolve()
        venv_dir = python_bin.parent
        for name in ("semgrep.exe", "semgrep"):
            candidate = venv_dir / name
            if candidate.exists():
                candidates.append(str(candidate))
        cwd_candidate = shutil.which("semgrep")
        if cwd_candidate:
            candidates.append(cwd_candidate)
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return candidate
        return "semgrep"

    def __init__(
        self,
        rules_path: Optional[str] = None,
        *,
        rule_profile: str = "auto",
        languages: Optional[List[str]] = None,
    ):
        self.last_error: Optional[str] = None
        self.last_command: List[str] = []
        self.languages = [language.lower() for language in (languages or [])]
        self.rule_profile = (rule_profile or "auto").strip().lower()
        self.semgrep_executable = self._resolve_semgrep_executable()
        if rules_path:
            self.configs = [rules_path]
        else:
            default_oss_dir = Path(__file__).resolve().parents[2] / "rules" / "semgrep-oss-full"
            if default_oss_dir.exists() and default_oss_dir.is_dir():
                self.configs = [str(default_oss_dir)]
            else:
                self.configs = self._registry_configs()

    @property
    def semgrep_version(self) -> str:
        try:
            result = subprocess.run(
                [self.semgrep_executable, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            if result.returncode == 0:
                output = result.stdout.strip() or result.stderr.strip()
                return output.splitlines()[0] if output else "unknown"
        except Exception:
            pass
        return "unknown"

    @property
    def config_description(self) -> str:
        """Return the effective Semgrep configuration for scan metadata."""
        return ",".join(self.configs)

    def _registry_configs(self) -> List[str]:
        """Select Semgrep OSS registry packs from repository language intake."""
        if self.rule_profile not in {"auto", "semgrep-oss", "semgrep-oss-full"}:
            return [self.rule_profile]

        profiles = {
            "python": "p/python",
            "javascript": "p/javascript",
            "typescript": "p/javascript",
            "java": "p/java",
            "php": "p/php",
        }
        configs = [profiles[language] for language in self.languages if language in profiles]
        return list(dict.fromkeys(configs)) or ["p/python"]
                
    def _map_severity(self, semgrep_severity: str) -> Severity:
        semgrep_severity = semgrep_severity.upper()
        if semgrep_severity == "ERROR":
            return Severity.HIGH
        elif semgrep_severity == "WARNING":
            return Severity.MEDIUM
        elif semgrep_severity == "INFO":
            return Severity.LOW
        return Severity.UNKNOWN
        
    def run(
        self,
        target_path: str,
        *,
        exclude_dir_names: Optional[List[str]] = None,
        exclude_globs: Optional[List[str]] = None,
    ) -> List[SemgrepMatch]:
        """Runs semgrep and returns a list of SemgrepMatch objects."""
        if not Path(self.semgrep_executable).exists():
            self.last_error = (
                f"Semgrep executable not found: {self.semgrep_executable}. "
                "Install it in the active Python environment before running scans."
            )
            self.last_command = [self.semgrep_executable, "scan", "--json"]
            return []

        cmd = [
            self.semgrep_executable,
            "scan",
            "--json",
        ]
        for config in self.configs:
            cmd.extend(["--config", config])
        for excluded in [*(exclude_dir_names or []), *(exclude_globs or [])]:
            if excluded.strip():
                cmd.extend(["--exclude", excluded.strip()])
        cmd.append(target_path)
        self.last_command = list(cmd)
        self.last_error = None
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            if not result.stdout:
                if result.returncode != 0:
                    self.last_error = (
                        result.stderr.strip()
                        or f"Semgrep exited with code {result.returncode}."
                    )
                return []

            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError:
                self.last_error = (
                    result.stderr.strip()
                    or "Semgrep returned invalid JSON output."
                )
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
                        code_snippet=extra.get("lines", ""),
                        language=_match_language(r),
                        fingerprint=str(
                            r.get("fingerprint")
                            or extra.get("fingerprint")
                            or ""
                        ),
                    )
                )
            if result.returncode != 0 and not matches:
                self.last_error = (
                    result.stderr.strip()
                    or f"Semgrep exited with code {result.returncode}."
                )
            return matches

        except FileNotFoundError:
            self.last_error = "Semgrep is not installed or was not found in PATH."
            return []
        except Exception as e:
            self.last_error = f"Semgrep execution failed: {e}"
            return []


def _match_language(result: Dict[str, Any]) -> str:
    """Infer the source language from Semgrep metadata without losing the raw match."""
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {}) if isinstance(extra, dict) else {}
    languages = metadata.get("languages", []) if isinstance(metadata, dict) else []
    if isinstance(languages, list) and languages:
        return str(languages[0])
    suffix = Path(str(result.get("path", ""))).suffix.lower()
    return {
        ".py": "python",
        ".pyw": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".php": "php",
    }.get(suffix, "")

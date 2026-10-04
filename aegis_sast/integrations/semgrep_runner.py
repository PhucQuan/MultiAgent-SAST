"""
Runs semgrep CLI and parses JSON output.

Rule resolution priority (first match wins):
1. ``rules_path`` kwarg passed explicitly (e.g. from CLI --rules flag).
2. ``append_rules_paths`` list (e.g. from reviewed rule profile in benchmark).
3. Repo-local offline baseline YAML at
   ``rules/reviewed/semgrep_oss_python_baseline.legacy.yaml``.
4. Semgrep registry shorthand ``p/python`` as last-resort fallback
   (requires internet; results are non-reproducible across machines).
"""
from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis_sast.core.models import Severity

# Absolute path to the repo-local offline rule file.
# This is the single source of truth that guarantees reproducible results
# on any machine that has git-pulled the repo, without needing network access.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_OFFLINE_BASELINE_DIR = _REPO_ROOT / "rules" / "semgrep-oss-full"
_OFFLINE_SECURITY_YAML = _REPO_ROOT / "rules" / "semgrep" / "python_security.yaml"
_OFFLINE_BASELINE_YAML = (
    _REPO_ROOT / "rules" / "reviewed" / "semgrep_oss_python_baseline.legacy.yaml"
)


@dataclass
class SemgrepMatch:
    """One raw finding produced by the Semgrep CLI."""

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
    fingerprint: str = ""
    language: str = ""


class SemgrepRunner:
    """Execute the Semgrep CLI and parse its JSON output into SemgrepMatch objects."""

    def __init__(
        self,
        rules_path: Optional[str] = None,
        append_rules_paths: Optional[List[str]] = None,
        rule_profile: str = "auto",
        languages: Optional[List[str]] = None,
    ) -> None:
        self._explicit_rules_path = rules_path
        self._append_rules_paths: List[str] = [str(p) for p in (append_rules_paths or [])]
        self._rule_profile = rule_profile
        self._languages = languages or []
        self.semgrep_executable = self._find_executable()
        self.last_error: Optional[str] = None
        self.last_command: List[str] = []
        self.last_match_count = 0
        self.config_description = ""

    @staticmethod
    def _find_executable() -> str:
        """Prefer the Semgrep executable installed beside the active Python."""
        candidates = []
        scripts_dir = Path(sys.executable).resolve().parent
        candidates.append(scripts_dir / ("semgrep.exe" if os.name == "nt" else "semgrep"))
        found = shutil.which("semgrep")
        if found:
            candidates.append(Path(found))
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return "semgrep"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_config_args(self) -> List[str]:
        """Return the ordered list of ``--config <path>`` CLI flags.

        All sources are collected, deduplicated in priority order, and validated
        so that file-backed paths actually exist before being passed to Semgrep.
        """
        config_paths: List[str] = []

        # Priority 1 – explicit override from CLI ``--rules`` flag
        if self._explicit_rules_path:
            config_paths.append(str(self._explicit_rules_path))

        # Priority 2 – reviewed profile append_rules_paths (benchmark reproducibility)
        for p in self._append_rules_paths:
            if p not in config_paths:
                config_paths.append(p)

        if config_paths:
            # Validate that every file-backed path actually exists
            for path in list(config_paths):
                p_obj = Path(path)
                if path not in ("p/python", "p/security-audit") and not p_obj.exists():
                    raise FileNotFoundError(
                        f"[SemgrepRunner] Rule file/dir not found: {path}\n"
                        f"  Run `git pull` to ensure the rules/ directory is present."
                    )
            args: List[str] = []
            for path in config_paths:
                args += ["--config", path]
            return args

        if self._rule_profile == "auto" and self._languages:
            return ["--config", f"p/{self._languages[0]}"]

        # Priority 3 – repo-local offline baseline (no network needed)
        # Check full official rules directory first (371 rules)
        if _OFFLINE_BASELINE_DIR.exists() and _OFFLINE_BASELINE_DIR.is_dir():
            return ["--config", str(_OFFLINE_BASELINE_DIR)]

        # Check compiled security rules yaml
        if _OFFLINE_SECURITY_YAML.exists():
            return ["--config", str(_OFFLINE_SECURITY_YAML)]

        # Priority 4 – last-resort online registry (non-reproducible)
        warnings.warn(
            f"[SemgrepRunner] Offline rule directory not found at "
            f"'{_OFFLINE_BASELINE_DIR}'.\n"
            f"  Falling back to 'p/python' from Semgrep registry "
            f"(requires internet; results may differ across machines).\n"
            f"  Fix: run `git pull` to restore the rules/ directory.",
            RuntimeWarning,
            stacklevel=3,
        )
        return ["--config", "p/python"]

    def _map_severity(self, semgrep_severity: str) -> Severity:
        semgrep_severity = semgrep_severity.upper()
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return mapping.get(semgrep_severity, Severity.UNKNOWN)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        target_path: str,
        *,
        exclude_dir_names: Optional[List[str]] = None,
        exclude_globs: Optional[List[str]] = None,
    ) -> List[SemgrepMatch]:
        """Execute Semgrep on ``target_path`` and return parsed matches.

        Raises
        ------
        RuntimeError
            If the ``semgrep`` binary is not found in PATH (helps diagnose
            silent fallback issues on machines where semgrep is not installed).
        """
        self.last_error = None
        config_args = self._resolve_config_args()
        self.config_description = ", ".join(
            config_args[index + 1]
            for index, value in enumerate(config_args[:-1])
            if value == "--config"
        )
        cmd = [
            self.semgrep_executable,
            "scan",
            "--json",
            *config_args,
            "--no-rewrite-rule-ids",
        ]
        for directory in exclude_dir_names or []:
            cmd.extend(["--exclude", directory])
        for pattern in exclude_globs or []:
            cmd.extend(["--exclude", pattern])
        cmd.append(target_path)
        self.last_command = cmd

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            if not result.stdout.strip():
                self.last_error = (
                    result.stderr.strip()
                    or f"Semgrep exited with code {result.returncode} without JSON output."
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

            matches: List[SemgrepMatch] = []
            for r in output.get("results", []):
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
                        fingerprint=str(
                            r.get("fingerprint")
                            or hashlib.sha256(
                                "|".join(
                                    [
                                        str(r.get("check_id", "unknown")),
                                        str(r.get("path", "unknown")),
                                        str(r.get("start", {}).get("line", 0)),
                                        str(extra.get("message", "")),
                                    ]
                                ).encode("utf-8")
                            ).hexdigest()
                        ),
                        language=str(extra.get("metadata", {}).get("technology", "") or ""),
                    )
                )
            self.last_match_count = len(matches)
            return matches

        except FileNotFoundError:
            raise RuntimeError(
                "[SemgrepRunner] 'semgrep' binary not found in PATH.\n"
                "  Install it with: pip install semgrep\n"
                "  Then verify: semgrep --version"
            ) from None
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"[SemgrepRunner] Unexpected error running semgrep: {exc}"
            ) from exc

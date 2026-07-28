"""Dataclasses shared by the reusable rule-workbench backend."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RuleWorkbenchBundlePaths:
    """Concrete artifact paths generated during one review-bundle run."""

    normalized_path: Path
    validation_path: Path
    legacy_path: Optional[Path] = None
    legacy_report_path: Optional[Path] = None


@dataclass
class RuleWorkbenchBundleRequest:
    """Input contract for one review-bundle build."""

    input_path: Path
    output_dir: Path
    language: Optional[str] = None
    family: Optional[str] = None
    limit: Optional[int] = None
    normalized_format: str = "json"
    validation_format: str = "json"
    profile: str = "generic"
    provenance_source: str = "semgrep"
    snapshot_version: str = "manual-seed-v1"
    legacy_format: Optional[str] = None


@dataclass
class RuleWorkbenchBundleResult:
    """Result contract for one review-bundle build."""

    paths: RuleWorkbenchBundlePaths
    valid: bool
    rules_checked: int
    error_count: int
    warning_count: int

    def to_mapping(self) -> dict:
        """Return a test-friendly mapping with Path values preserved."""
        return {
            "normalized_path": self.paths.normalized_path,
            "validation_path": self.paths.validation_path,
            "legacy_path": self.paths.legacy_path,
            "legacy_report_path": self.paths.legacy_report_path,
            "valid": self.valid,
            "rules_checked": self.rules_checked,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
        }

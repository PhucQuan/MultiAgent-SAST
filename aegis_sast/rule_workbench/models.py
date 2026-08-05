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


@dataclass
class RuleWorkbenchDraftPaths:
    """Concrete artifact paths generated during one natural-language draft run."""

    draft_path: Path
    validation_path: Path
    prompt_path: Path
    seed_context_path: Path
    legacy_path: Optional[Path] = None
    legacy_report_path: Optional[Path] = None


@dataclass
class RuleWorkbenchDraftRequest:
    """Input contract for one natural-language draft bundle build."""

    description: str
    seed_input_path: Path
    output_dir: Path
    language: str
    family: str
    profile: str = "generic"
    normalized_format: str = "json"
    validation_format: str = "json"
    provenance_source: str = "ai-adapted"
    snapshot_version: str = "draft-v1"
    legacy_format: Optional[str] = None
    rule_id: Optional[str] = None
    title: Optional[str] = None


@dataclass
class RuleWorkbenchDraftResult:
    """Result contract for one natural-language draft bundle build."""

    paths: RuleWorkbenchDraftPaths
    valid: bool
    rules_checked: int
    error_count: int
    warning_count: int

    def to_mapping(self) -> dict:
        """Return a test-friendly mapping with Path values preserved."""
        return {
            "draft_path": self.paths.draft_path,
            "validation_path": self.paths.validation_path,
            "prompt_path": self.paths.prompt_path,
            "seed_context_path": self.paths.seed_context_path,
            "legacy_path": self.paths.legacy_path,
            "legacy_report_path": self.paths.legacy_report_path,
            "valid": self.valid,
            "rules_checked": self.rules_checked,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
        }

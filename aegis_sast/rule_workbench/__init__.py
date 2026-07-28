"""Reusable backend primitives for the Aegis rule workbench."""

from .models import (
    RuleWorkbenchBundlePaths,
    RuleWorkbenchBundleRequest,
    RuleWorkbenchBundleResult,
)
from .service import (
    RuleWorkbenchService,
    build_review_bundle,
    export_legacy_rules,
    format_validation_report,
    load_normalized_document,
    load_rule_document,
    load_semgrep_document,
    normalize_semgrep_document,
    normalize_semgrep_rule,
    validate_normalized_document,
    write_legacy_document,
    write_normalized_document,
    write_report,
    write_validation_report,
)
from .storage import RuleWorkbenchStorage
from .webapp import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_WORKSPACE_ROOT,
    RuleWorkbenchWebApp,
    serve_rule_workbench,
)

__all__ = [
    "RuleWorkbenchBundlePaths",
    "RuleWorkbenchBundleRequest",
    "RuleWorkbenchBundleResult",
    "RuleWorkbenchService",
    "RuleWorkbenchStorage",
    "build_review_bundle",
    "export_legacy_rules",
    "format_validation_report",
    "load_normalized_document",
    "load_rule_document",
    "load_semgrep_document",
    "normalize_semgrep_document",
    "normalize_semgrep_rule",
    "validate_normalized_document",
    "write_legacy_document",
    "write_normalized_document",
    "write_report",
    "write_validation_report",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_WORKSPACE_ROOT",
    "RuleWorkbenchWebApp",
    "serve_rule_workbench",
]

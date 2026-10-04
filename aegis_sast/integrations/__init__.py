"""Integration adapters for external tooling and CI ecosystems."""

from aegis_sast.integrations.sarif_formatter import SARIFFormatter
from aegis_sast.integrations.semgrep_adapter import (
    ImportedNormalizedVulnerability,
    import_semgrep_report,
    normalized_finding_from_mapping,
    semgrep_report_to_findings,
    semgrep_report_to_repo_profile,
    semgrep_report_to_scan_result,
)
from aegis_sast.integrations.semgrep_runner import SemgrepRunner, SemgrepMatch
from aegis_sast.integrations.taint_bridge import TaintBridge

__all__ = [
    "ImportedNormalizedVulnerability",
    "SARIFFormatter",
    "SemgrepRunner",
    "SemgrepMatch",
    "TaintBridge",
    "import_semgrep_report",
    "normalized_finding_from_mapping",
    "semgrep_report_to_findings",
    "semgrep_report_to_repo_profile",
    "semgrep_report_to_scan_result",
]

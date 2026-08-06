"""Adapters that import Semgrep-shaped reports into Aegis workflow objects."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any

from aegis_sast.core.models import (
    CodeLocation,
    EvidenceBundle,
    NormalizedFinding,
    Sanitizer,
    ScanResult,
    Severity,
    TriageStatus,
    VulnerabilityType,
)
from aegis_sast.orchestration.repo_intake import RepoIntake
from aegis_sast.orchestration.state import RepoProfile


SEVERITY_BY_VALUE = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.UNKNOWN,
}
TRIAGE_STATUS_BY_VALUE = {
    "confirmed": TriageStatus.CONFIRMED,
    "likely": TriageStatus.LIKELY,
    "needs-review": TriageStatus.NEEDS_REVIEW,
    "suppressed": TriageStatus.SUPPRESSED,
}


def import_semgrep_report(
    report: dict[str, Any],
) -> tuple[ScanResult, RepoProfile]:
    """Convert one Semgrep-compatible Aegis report into workflow-ready objects."""
    findings = semgrep_report_to_findings(report)
    scan_result = semgrep_report_to_scan_result(report, findings=findings)
    repo_profile = semgrep_report_to_repo_profile(report, findings=findings)
    return scan_result, repo_profile


def semgrep_report_to_findings(report: dict[str, Any]) -> list[NormalizedFinding]:
    """Convert imported finding mappings into normalized finding objects."""
    raw_findings = report.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("Expected the imported report to contain a top-level 'findings' list.")

    return [
        normalized_finding_from_mapping(item)
        for item in raw_findings
        if isinstance(item, dict)
    ]


def semgrep_report_to_scan_result(
    report: dict[str, Any],
    *,
    findings: list[NormalizedFinding] | None = None,
) -> ScanResult:
    """Rebuild a ScanResult object from a Semgrep-compatible report payload."""
    findings = findings or semgrep_report_to_findings(report)
    scan_metadata = report.get("scan_metadata", {})
    summary = report.get("summary", {})

    start_time = _coerce_datetime(scan_metadata.get("timestamp"))
    duration_seconds = _safe_float(
        scan_metadata.get("duration_seconds"),
        default=_safe_float(summary.get("duration_seconds"), default=0.0),
    )
    end_time = start_time + timedelta(seconds=max(duration_seconds, 0.0))
    target_path = str(
        scan_metadata.get("target")
        or summary.get("target")
        or "<imported-semgrep-report>"
    )
    files_scanned = _safe_int(
        scan_metadata.get("files_scanned"),
        default=_safe_int(
            summary.get("files_scanned"),
            default=len({finding.file_path for finding in findings if finding.file_path}),
        ),
    )

    return ScanResult(
        target_path=target_path,
        start_time=start_time,
        end_time=end_time,
        vulnerabilities=[
            ImportedNormalizedVulnerability(finding=finding)
            for finding in findings
        ],
        files_scanned=files_scanned,
        errors=_coerce_errors(report.get("errors", [])),
    )


def semgrep_report_to_repo_profile(
    report: dict[str, Any],
    *,
    findings: list[NormalizedFinding] | None = None,
) -> RepoProfile:
    """Build a conservative repo profile for imported Semgrep findings."""
    findings = findings or semgrep_report_to_findings(report)
    scan_metadata = report.get("scan_metadata", {})
    semgrep_run_summary = report.get("semgrep_run_summary", {})
    target_path = str(scan_metadata.get("target") or "<imported-semgrep-report>")

    detected_languages = sorted(
        {
            finding.language
            for finding in findings
            if isinstance(finding.language, str) and finding.language.strip()
        }
    )
    if not detected_languages:
        inferred_language = RepoIntake.infer_language_from_target(target_path)
        if inferred_language:
            detected_languages.append(inferred_language)

    configured_profile = str(semgrep_run_summary.get("profile") or "").strip()
    scan_profile = configured_profile or RepoIntake.choose_scan_profile(detected_languages)
    files_scanned = _safe_int(
        scan_metadata.get("files_scanned"),
        default=len({finding.file_path for finding in findings if finding.file_path}),
    )

    framework_hints = semgrep_run_summary.get("framework_hints", [])
    if not isinstance(framework_hints, list):
        framework_hints = []

    return RepoProfile(
        target_path=target_path,
        scan_profile=scan_profile,
        detected_languages=detected_languages,
        framework_hints=[
            str(value).strip()
            for value in framework_hints
            if isinstance(value, str) and value.strip()
        ],
        files_scanned=files_scanned,
        metadata={
            "profile_source": "semgrep-report-adapter",
            "analysis_plan": RepoIntake.build_analysis_plan(detected_languages),
            "supported_file_count": files_scanned,
            "imported_report_schema": report.get("schema_version"),
            "original_tool": scan_metadata.get("tool", "semgrep-community"),
            "original_files_scanned": files_scanned,
            "imported_finding_count": len(findings),
        },
    )


def normalized_finding_from_mapping(payload: dict[str, Any]) -> NormalizedFinding:
    """Convert one serialized finding mapping back into a NormalizedFinding."""
    triage_payload = payload.get("triage_decision", {})
    triage_payload = triage_payload if isinstance(triage_payload, dict) else {}
    metadata = dict(payload.get("metadata") or {})
    evidence = _evidence_bundle_from_mapping(payload.get("evidence"))

    if "detection" in evidence.metadata and "detection" not in metadata:
        metadata["detection"] = dict(evidence.metadata["detection"])

    triage_metadata = metadata.setdefault("triage", {})
    if triage_payload:
        triage_metadata.update(
            {
                "reviewer": triage_payload.get("reviewer"),
                "reason_codes": triage_payload.get("reason_codes", []),
                "evidence_summary": triage_payload.get("evidence_summary", {}),
                "manual_review_required": bool(
                    triage_payload.get("manual_review_required", False)
                ),
            }
        )
    if "agent_reviews" in payload and "agent_reviews" not in metadata:
        metadata["agent_reviews"] = payload.get("agent_reviews")

    detected_at = _coerce_datetime(
        payload.get("detected_at")
        or triage_payload.get("timestamp")
    )
    file_path = str(payload.get("file") or payload.get("path") or evidence.sink.file_path)

    return NormalizedFinding(
        id=str(payload.get("id") or ""),
        tool=str(payload.get("tool") or "semgrep-community"),
        language=_infer_language(
            payload.get("language"),
            file_path=file_path,
        ),
        rule_id=str(payload.get("rule_id") or payload.get("check_id") or payload.get("type") or ""),
        vulnerability_type=str(payload.get("type") or payload.get("vulnerability_type") or "UNKNOWN"),
        severity=_coerce_severity(payload.get("severity")),
        triage_status=_coerce_triage_status(
            triage_payload.get("status") or payload.get("triage_status")
        ),
        confidence=_safe_float(
            triage_payload.get("confidence"),
            default=_safe_float(payload.get("confidence"), default=0.5),
        ),
        file_path=file_path,
        line_number=_safe_int(payload.get("line"), default=evidence.sink.line_number or 1),
        message=str(payload.get("message") or payload.get("title") or "Imported Semgrep finding"),
        evidence=evidence,
        explanation=str(
            triage_payload.get("explanation")
            or payload.get("explanation")
            or payload.get("message")
            or ""
        )
        or None,
        recommendation=str(
            triage_payload.get("recommendation")
            or payload.get("recommendation")
            or ""
        )
        or None,
        metadata=metadata,
        detected_at=detected_at,
    )


@dataclass
class ImportedNormalizedVulnerability:
    """Thin wrapper so imported findings can flow through the existing workflow."""

    finding: NormalizedFinding

    @property
    def severity(self) -> Severity:
        """Expose severity like the native Vulnerability model does."""
        return self.finding.severity

    @property
    def file_path(self) -> str:
        """Expose file path for compatibility with report helpers."""
        return self.finding.file_path

    @property
    def line_number(self) -> int:
        """Expose line number for compatibility with report helpers."""
        return self.finding.line_number

    def to_normalized_finding(
        self,
        tool: str = "aegis-sast",
        language: str | None = None,
    ) -> NormalizedFinding:
        """Return a defensive copy so triage can mutate it safely."""
        finding = deepcopy(self.finding)
        if language and not finding.language:
            finding.language = language
        if tool and not finding.tool:
            finding.tool = tool
        return finding

    def to_dict(self) -> dict[str, Any]:
        """Serialize the wrapped finding back to the report schema."""
        return self.finding.to_dict()


def _evidence_bundle_from_mapping(payload: Any) -> EvidenceBundle:
    """Convert one serialized evidence mapping back into an EvidenceBundle."""
    payload = payload if isinstance(payload, dict) else {}
    metadata = dict(payload.get("metadata") or {})
    return EvidenceBundle(
        source=_location_from_mapping(payload.get("source")),
        sink=_location_from_mapping(payload.get("sink")),
        intermediate_steps=[
            _location_from_mapping(item)
            for item in payload.get("intermediate_steps", [])
            if isinstance(item, dict)
        ],
        sanitizers=[
            _sanitizer_from_mapping(item)
            for item in payload.get("sanitizers", [])
            if isinstance(item, dict)
        ],
        metadata=metadata,
    )


def _location_from_mapping(payload: Any) -> CodeLocation:
    """Convert one serialized location mapping into a CodeLocation."""
    payload = payload if isinstance(payload, dict) else {}
    return CodeLocation(
        file_path=str(payload.get("file") or payload.get("path") or ""),
        line_number=_safe_int(payload.get("line"), default=1),
        column_number=_safe_int(payload.get("column"), default=1),
        code_snippet=str(payload.get("snippet") or payload.get("content") or ""),
    )


def _sanitizer_from_mapping(payload: Any) -> Sanitizer:
    """Convert one serialized sanitizer mapping into a Sanitizer model."""
    payload = payload if isinstance(payload, dict) else {}
    return Sanitizer(
        location=_location_from_mapping(payload.get("location") or payload),
        sanitizer_type=str(payload.get("type") or payload.get("sanitizer_type") or ""),
        function_name=str(
            payload.get("function")
            or payload.get("function_name")
            or payload.get("name")
            or ""
        ),
        mitigates=_coerce_vulnerability_types(payload.get("mitigates", [])),
    )


def _coerce_vulnerability_types(values: Any) -> list[VulnerabilityType]:
    """Convert serialized vulnerability-type strings into enum values."""
    if not isinstance(values, list):
        return []

    resolved: list[VulnerabilityType] = []
    for value in values:
        normalized = str(value or "").strip().upper()
        if not normalized:
            continue
        try:
            resolved.append(VulnerabilityType(normalized))
        except ValueError:
            continue
    return resolved


def _coerce_severity(value: Any) -> Severity:
    """Map serialized severity strings back into the enum."""
    if isinstance(value, Severity):
        return value
    normalized = str(value or "").strip().upper()
    return SEVERITY_BY_VALUE.get(normalized, Severity.UNKNOWN)


def _coerce_triage_status(value: Any) -> TriageStatus:
    """Map serialized triage statuses back into the enum."""
    if isinstance(value, TriageStatus):
        return value
    normalized = str(value or "").strip().lower()
    return TRIAGE_STATUS_BY_VALUE.get(normalized, TriageStatus.NEEDS_REVIEW)


def _coerce_datetime(value: Any) -> datetime:
    """Parse timestamps conservatively and fall back to the current time."""
    if isinstance(value, datetime):
        return value

    if isinstance(value, str) and value.strip():
        normalized = value.strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            pass

    return datetime.now()


def _coerce_errors(payload: Any) -> list[str]:
    """Flatten imported error payloads into a stable list of strings."""
    if not isinstance(payload, list):
        return []

    errors: list[str] = []
    for item in payload:
        if isinstance(item, str):
            if item.strip():
                errors.append(item.strip())
            continue
        if isinstance(item, dict):
            errors.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
            continue
        if item is not None:
            errors.append(str(item))
    return errors


def _infer_language(value: Any, *, file_path: str) -> str | None:
    """Infer the language from the payload or, failing that, from the file path."""
    if isinstance(value, str) and value.strip():
        return value.strip().lower()

    suffix = Path(file_path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".php": "php",
    }.get(suffix)


def _safe_float(value: Any, *, default: float = 0.0) -> float:
    """Parse floats conservatively for imported metrics."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, *, default: int = 0) -> int:
    """Parse integers conservatively for imported metrics."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

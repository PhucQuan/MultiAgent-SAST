"""Reusable business logic for rule import, validation, and bundle export."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .models import (
    RuleWorkbenchBundleRequest,
    RuleWorkbenchBundleResult,
)
from .storage import RuleWorkbenchStorage


SUPPORTED_LANGUAGES = {"python", "javascript", "java", "php"}

SEVERITY_MAP = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "INFO": "MEDIUM",
    "LOW": "LOW",
}

FAMILY_BY_CWE = {
    "CWE-22": "PATH_TRAVERSAL",
    "CWE-77": "COMMAND_INJECTION",
    "CWE-78": "COMMAND_INJECTION",
    "CWE-79": "XSS",
    "CWE-89": "SQL_INJECTION",
    "CWE-502": "INSECURE_DESERIALIZATION",
    "CWE-918": "SSRF",
}

FAMILY_HINTS = {
    "command": "COMMAND_INJECTION",
    "deserial": "INSECURE_DESERIALIZATION",
    "path": "PATH_TRAVERSAL",
    "sql": "SQL_INJECTION",
    "ssrf": "SSRF",
    "template": "SSTI",
    "xss": "XSS",
}

CALLABLE_HEAD_RE = re.compile(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*\(")
SUPPORTED_FAMILIES = {
    "SQL_INJECTION",
    "COMMAND_INJECTION",
    "CODE_INJECTION",
    "PATH_TRAVERSAL",
    "XPATH_INJECTION",
    "LDAP_INJECTION",
    "XXE",
    "SSRF",
    "XSS",
    "NOSQL_INJECTION",
    "IDOR",
    "SSTI",
    "INSECURE_DESERIALIZATION",
    "MASS_ASSIGNMENT",
    "OPEN_REDIRECT",
}
SUPPORTED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
SUPPORTED_PATTERN_MODES = {"pattern", "pattern-regex", "literal"}
SUPPORTED_PROFILES = {"generic", "python-rule-workbench-v1"}
WORKBENCH_V1_FAMILIES = {
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "INSECURE_DESERIALIZATION",
}
CWE_RE = re.compile(r"^CWE-\d+$")
OWASP_RE = re.compile(r"^A\d{1,2}:\d{4}$")
LEGACY_FAMILY_TO_CATEGORY = {
    "SQL_INJECTION": "sqli",
    "COMMAND_INJECTION": "rce",
    "CODE_INJECTION": "rce",
    "PATH_TRAVERSAL": "path_traversal",
    "XSS": "xss",
    "SSRF": "ssrf",
    "NOSQL_INJECTION": "nosqli",
    "XXE": "xxe",
    "IDOR": "idor",
    "SSTI": "ssti",
    "INSECURE_DESERIALIZATION": "deserialization",
    "MASS_ASSIGNMENT": "mass_assignment",
    "OPEN_REDIRECT": "open_redirect",
}
LEGACY_CALLABLE_HEAD_RE = re.compile(r"^([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\(")


class RuleWorkbenchService:
    """Orchestrates reusable rule import, validation, and export flows."""

    def __init__(self, storage: RuleWorkbenchStorage | None = None):
        self.storage = storage or RuleWorkbenchStorage()

    def load_mapping_document(self, path: Path) -> dict[str, Any]:
        """Load a generic mapping document through the storage layer."""
        return self.storage.load_mapping_document(path)

    def load_semgrep_document(self, path: Path) -> dict[str, Any]:
        """Load a Semgrep-shaped YAML/JSON rule document."""
        return self.storage.load_mapping_document(path)

    def load_normalized_document(self, path: Path) -> dict[str, Any]:
        """Load a normalized rule YAML/JSON document."""
        return self.storage.load_mapping_document(path)

    def normalize_semgrep_document(
        self,
        document: dict[str, Any],
        *,
        language_filter: str | None = None,
        family_override: str | None = None,
        limit: int | None = None,
        provenance_source: str = "semgrep",
        snapshot_version: str = "manual-seed-v1",
        source_path: Path | None = None,
    ) -> dict[str, Any]:
        """Normalize a Semgrep document into the Aegis rule-set schema."""
        raw_rules = document.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError("Expected the Semgrep document to contain a top-level 'rules' list.")

        normalized_rules = []
        skipped_rules = []

        for rule in raw_rules:
            normalized_rule, skip_reason = self.normalize_semgrep_rule(
                rule,
                language_filter=language_filter,
                family_override=family_override,
                provenance_source=provenance_source,
                snapshot_version=snapshot_version,
                source_path=source_path,
            )
            if normalized_rule is None:
                skipped_rules.append(
                    {
                        "rule_id": rule.get("id", "<missing-id>") if isinstance(rule, dict) else "<invalid>",
                        "reason": skip_reason,
                    }
                )
                continue

            normalized_rules.append(normalized_rule)
            if limit is not None and len(normalized_rules) >= limit:
                break

        return {
            "schema_version": "aegis-normalized-rule-set-v1",
            "generated_by": "aegis_sast.rule_workbench.service",
            "source_path": str(source_path) if source_path else None,
            "rule_count": len(normalized_rules),
            "rules": normalized_rules,
            "skipped_rules": skipped_rules,
        }

    def normalize_semgrep_rule(
        self,
        rule: Any,
        *,
        language_filter: str | None = None,
        family_override: str | None = None,
        provenance_source: str = "semgrep",
        snapshot_version: str = "manual-seed-v1",
        source_path: Path | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Normalize one Semgrep taint rule or return a skip reason."""
        if not isinstance(rule, dict):
            return None, "rule is not a mapping"

        if rule.get("mode") != "taint":
            return None, "only taint-mode rules are supported in V1"

        normalized_language = _select_language(rule.get("languages", []), language_filter)
        if normalized_language is None:
            return None, "rule language is unsupported or filtered out"

        family = family_override or _infer_family(rule)
        if family is None:
            return None, "could not infer family and no override was supplied"

        source_patterns, source_notes = _normalize_pattern_entries(
            rule.get("pattern-sources", []),
            entry_kind="source",
        )
        sink_patterns, sink_notes = _normalize_pattern_entries(
            rule.get("pattern-sinks", []),
            entry_kind="sink",
        )
        sanitizer_patterns, sanitizer_notes = _normalize_pattern_entries(
            rule.get("pattern-sanitizers", []),
            entry_kind="sanitizer",
        )

        if not source_patterns or not sink_patterns:
            return None, "rule does not expose a reviewable taint source/sink subset"

        metadata = rule.get("metadata", {}) if isinstance(rule.get("metadata"), dict) else {}
        notes = []
        notes.extend(source_notes)
        notes.extend(sink_notes)
        notes.extend(sanitizer_notes)

        normalized_rule = {
            "rule_id": rule.get("id", "<missing-id>"),
            "title": rule.get("message", rule.get("id", "Imported Semgrep seed rule")),
            "language": normalized_language,
            "family": family,
            "severity": _map_severity(rule.get("severity")),
            "taxonomy": {
                "cwe": _extract_cwe_ids(metadata),
                "owasp": _extract_owasp_refs(metadata),
            },
            "detection": {
                "match_mode": "semgrep-taint-subset",
                "source_patterns": source_patterns,
                "sink_patterns": sink_patterns,
                "sanitizers": sanitizer_patterns,
            },
            "triage": {
                "knowledge_refs": _normalize_string_list(metadata.get("references")),
                "fp_hints": _normalize_string_list(metadata.get("false_positives")),
                "remediation_notes": _extract_remediation_notes(metadata),
            },
            "provenance": {
                "source": provenance_source,
                "source_rule_id": rule.get("id", "<missing-id>"),
                "source_path": str(source_path) if source_path else None,
                "importer": "aegis_sast.rule_workbench.service",
                "snapshot_version": snapshot_version,
            },
            "notes": notes,
        }
        return normalized_rule, None

    def write_normalized_document(
        self,
        document: dict[str, Any],
        output_path: Path,
        format_name: str,
    ) -> None:
        """Write the normalized rule-set document in JSON or YAML."""
        self.storage.write_mapping_document(document, output_path, format_name)

    def validate_normalized_document(
        self,
        document: dict[str, Any],
        *,
        profile: str = "generic",
    ) -> dict[str, Any]:
        """Validate a normalized rule or rule-set document."""
        if profile not in SUPPORTED_PROFILES:
            raise ValueError(f"Unsupported validation profile: {profile}")

        errors: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        rules_checked = 0

        schema_version = document.get("schema_version")
        if schema_version == "aegis-normalized-rule-v1":
            rule_id = _safe_rule_id(document)
            _validate_rule(
                document,
                rule_id=rule_id,
                profile=profile,
                errors=errors,
                warnings=warnings,
                path_prefix="",
                require_schema_version=True,
            )
            rules_checked = 1
        elif schema_version == "aegis-normalized-rule-set-v1":
            rules = document.get("rules")
            if not isinstance(rules, list):
                _record_issue(
                    errors,
                    level="error",
                    rule_id="<document>",
                    path="rules",
                    code="invalid_rules_list",
                    message="Rule-set documents must contain a top-level 'rules' list.",
                )
            else:
                for index, rule in enumerate(rules):
                    if not isinstance(rule, dict):
                        _record_issue(
                            errors,
                            level="error",
                            rule_id=f"rules[{index}]",
                            path=f"rules[{index}]",
                            code="invalid_rule_type",
                            message="Each rule in a rule-set document must be a mapping.",
                        )
                        continue
                    rule_id = _safe_rule_id(rule, fallback=f"rules[{index}]")
                    _validate_rule(
                        rule,
                        rule_id=rule_id,
                        profile=profile,
                        errors=errors,
                        warnings=warnings,
                        path_prefix=f"rules[{index}].",
                        require_schema_version=False,
                    )
                    rules_checked += 1
        else:
            _record_issue(
                errors,
                level="error",
                rule_id="<document>",
                path="schema_version",
                code="unsupported_schema_version",
                message=(
                    "Expected schema_version to be either "
                    "'aegis-normalized-rule-v1' or 'aegis-normalized-rule-set-v1'."
                ),
            )

        return {
            "valid": not errors,
            "profile": profile,
            "rules_checked": rules_checked,
            "error_count": len(errors),
            "warning_count": len(warnings),
            "errors": errors,
            "warnings": warnings,
        }

    def format_validation_report(self, report: dict[str, Any], *, format_name: str) -> str:
        """Render the validation report in text or JSON form."""
        if format_name == "json":
            return json.dumps(report, indent=2, ensure_ascii=False) + "\n"

        lines = [
            (
                f"Validation {'passed' if report['valid'] else 'failed'} "
                f"({report['rules_checked']} rule(s), "
                f"{report['error_count']} error(s), "
                f"{report['warning_count']} warning(s))"
            )
        ]

        for issue in report["errors"]:
            lines.append(
                f"[error] {issue['rule_id']} {issue['path']} "
                f"({issue['code']}): {issue['message']}"
            )
        for issue in report["warnings"]:
            lines.append(
                f"[warning] {issue['rule_id']} {issue['path']} "
                f"({issue['code']}): {issue['message']}"
            )

        return "\n".join(lines) + "\n"

    def write_validation_report(
        self,
        report: dict[str, Any],
        *,
        format_name: str,
        output_path: Path | None = None,
    ) -> None:
        """Write the validation report either to stdout or a file."""
        rendered = self.format_validation_report(report, format_name=format_name)
        if output_path is None:
            print(rendered)
            return

        if format_name == "json":
            self.storage.write_text_report(rendered, output_path)
            return
        self.storage.write_text_report(rendered, output_path)

    def export_legacy_rules(
        self,
        document: dict[str, Any],
        *,
        language_filter: str | None = None,
        family_filter: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Convert normalized rules into the legacy rule-engine shape."""
        rules = _extract_rules(document)
        legacy_sources: list[dict[str, Any]] = []
        legacy_sinks: dict[str, list[dict[str, Any]]] = {}
        legacy_sanitizers: list[dict[str, Any]] = []

        report = {
            "rules_seen": len(rules),
            "rules_selected": 0,
            "rules_skipped": [],
            "exported_sources": 0,
            "exported_sinks": 0,
            "exported_sanitizers": 0,
            "skipped_patterns": [],
        }

        seen_sources = set()
        seen_sinks = set()
        seen_sanitizers = set()

        for rule in rules:
            rule_id = _safe_rule_id(rule)
            language = rule.get("language")
            family = rule.get("family")

            if language_filter and language != language_filter:
                report["rules_skipped"].append(
                    {"rule_id": rule_id, "reason": f"language filter mismatch ({language})"}
                )
                continue

            if family_filter and family != family_filter:
                report["rules_skipped"].append(
                    {"rule_id": rule_id, "reason": f"family filter mismatch ({family})"}
                )
                continue

            if family not in LEGACY_FAMILY_TO_CATEGORY:
                report["rules_skipped"].append(
                    {"rule_id": rule_id, "reason": f"unsupported legacy family mapping ({family})"}
                )
                continue

            detection = rule.get("detection", {})
            if not isinstance(detection, dict):
                report["rules_skipped"].append(
                    {"rule_id": rule_id, "reason": "missing detection mapping"}
                )
                continue

            report["rules_selected"] += 1
            legacy_category = LEGACY_FAMILY_TO_CATEGORY[family]

            for entry in detection.get("source_patterns", []):
                converted = _convert_pattern_entry(entry, rule_id=rule_id, role="source", report=report)
                if converted is None:
                    continue

                source_type = _infer_legacy_source_type(converted)
                payload = {
                    "pattern": converted,
                    "type": source_type,
                    "severity": "MEDIUM",
                }
                identity = (payload["pattern"], payload["type"])
                if identity in seen_sources:
                    continue
                seen_sources.add(identity)
                legacy_sources.append(payload)
                report["exported_sources"] += 1

            bucket = legacy_sinks.setdefault(legacy_category, [])
            for entry in detection.get("sink_patterns", []):
                converted = _convert_pattern_entry(entry, rule_id=rule_id, role="sink", report=report)
                if converted is None:
                    continue

                payload = {
                    "pattern": converted,
                    "type": family,
                    "severity": rule.get("severity", "MEDIUM"),
                    "description": rule.get("title", rule_id),
                }
                identity = (legacy_category, payload["pattern"], payload["type"])
                if identity in seen_sinks:
                    continue
                seen_sinks.add(identity)
                bucket.append(payload)
                report["exported_sinks"] += 1

            for entry in detection.get("sanitizers", []):
                converted = _convert_pattern_entry(
                    entry,
                    rule_id=rule_id,
                    role="sanitizer",
                    report=report,
                )
                if converted is None:
                    continue

                payload = {
                    "pattern": converted,
                    "mitigates": [family],
                    "description": f"Imported sanitizer from {rule_id}",
                }
                identity = (payload["pattern"], tuple(payload["mitigates"]))
                if identity in seen_sanitizers:
                    continue
                seen_sanitizers.add(identity)
                legacy_sanitizers.append(payload)
                report["exported_sanitizers"] += 1

        legacy_document = {
            "sources": legacy_sources,
            "sinks": legacy_sinks,
            "sanitizers": legacy_sanitizers,
            "safe_patterns": [],
        }
        return legacy_document, report

    def write_legacy_document(self, document: dict[str, Any], output_path: Path, format_name: str) -> None:
        """Write legacy rules in JSON or YAML form."""
        self.storage.write_mapping_document(document, output_path, format_name)

    def write_report(self, report: dict[str, Any], output_path: Path) -> None:
        """Write an export report as JSON."""
        self.storage.write_json_report(report, output_path)

    def build_review_bundle(self, request: RuleWorkbenchBundleRequest) -> RuleWorkbenchBundleResult:
        """Build one review bundle from a Semgrep-shaped seed document."""
        paths = self.storage.build_bundle_paths(
            input_path=request.input_path,
            output_dir=request.output_dir,
            normalized_format=request.normalized_format,
            validation_format=request.validation_format,
            legacy_format=request.legacy_format,
        )

        seed_document = self.load_semgrep_document(request.input_path)
        normalized_document = self.normalize_semgrep_document(
            seed_document,
            language_filter=request.language,
            family_override=request.family,
            limit=request.limit,
            provenance_source=request.provenance_source,
            snapshot_version=request.snapshot_version,
            source_path=request.input_path,
        )
        self.write_normalized_document(
            normalized_document,
            paths.normalized_path,
            request.normalized_format,
        )

        validation_report = self.validate_normalized_document(
            normalized_document,
            profile=request.profile,
        )
        self.write_validation_report(
            validation_report,
            format_name=request.validation_format,
            output_path=paths.validation_path,
        )

        if request.legacy_format and paths.legacy_path and paths.legacy_report_path:
            legacy_document, legacy_report = self.export_legacy_rules(
                normalized_document,
                language_filter=request.language,
                family_filter=request.family,
            )
            self.write_legacy_document(
                legacy_document,
                paths.legacy_path,
                request.legacy_format,
            )
            self.write_report(legacy_report, paths.legacy_report_path)

        return RuleWorkbenchBundleResult(
            paths=paths,
            valid=validation_report["valid"],
            rules_checked=validation_report["rules_checked"],
            error_count=validation_report["error_count"],
            warning_count=validation_report["warning_count"],
        )


def _select_language(raw_languages: Any, language_filter: str | None) -> str | None:
    """Pick one supported language for the normalized rule."""
    languages = [str(language).strip().lower() for language in _normalize_list(raw_languages)]
    if language_filter:
        normalized_filter = language_filter.strip().lower()
        return normalized_filter if normalized_filter in languages else None

    for language in languages:
        if language in SUPPORTED_LANGUAGES:
            return language
    return None


def _infer_family(rule: dict[str, Any]) -> str | None:
    """Infer the vulnerability family from metadata and identifiers."""
    metadata = rule.get("metadata", {}) if isinstance(rule.get("metadata"), dict) else {}
    for cwe_id in _extract_cwe_ids(metadata):
        if cwe_id in FAMILY_BY_CWE:
            return FAMILY_BY_CWE[cwe_id]

    haystacks = [
        str(rule.get("id", "")),
        str(rule.get("message", "")),
        json.dumps(metadata, ensure_ascii=False),
    ]
    lower_text = " ".join(haystacks).lower()
    for hint, family in FAMILY_HINTS.items():
        if hint in lower_text:
            return family
    return None


def _normalize_pattern_entries(raw_entries: Any, *, entry_kind: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Flatten a small Semgrep pattern subset into reviewable pattern entries."""
    normalized_entries: list[dict[str, Any]] = []
    notes: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, str):
            normalized_entries.append(
                {
                    "pattern": item,
                    "pattern_mode": "literal",
                    "exact": False,
                    "by_side_effect": False,
                }
            )
            return

        if not isinstance(item, dict):
            notes.append(f"Skipped {entry_kind} entry with unsupported type: {type(item).__name__}")
            return

        direct_pattern = item.get("pattern")
        if isinstance(direct_pattern, str):
            normalized_entries.append(
                {
                    "pattern": direct_pattern,
                    "pattern_mode": "pattern",
                    "exact": _infer_default_exact_flag(direct_pattern, item),
                    "by_side_effect": bool(item.get("by-side-effect", False)),
                    "focus_metavariable": item.get("focus-metavariable"),
                }
            )

        direct_regex = item.get("pattern-regex")
        if isinstance(direct_regex, str):
            normalized_entries.append(
                {
                    "pattern": direct_regex,
                    "pattern_mode": "pattern-regex",
                    "exact": bool(item.get("exact", False)),
                    "by_side_effect": bool(item.get("by-side-effect", False)),
                    "focus_metavariable": item.get("focus-metavariable"),
                }
            )

        for nested_key in ("pattern-either", "patterns"):
            nested = item.get(nested_key)
            if nested is None:
                continue
            if not isinstance(nested, list):
                notes.append(f"Skipped {entry_kind} nested group '{nested_key}' because it is not a list")
                continue
            for child in nested:
                visit(child)

        if (
            not isinstance(direct_pattern, str)
            and not isinstance(direct_regex, str)
            and not any(key in item for key in ("pattern-either", "patterns"))
        ):
            keys = ", ".join(sorted(item.keys())) or "<none>"
            notes.append(f"Skipped {entry_kind} entry without reviewable pattern fields: {keys}")

    for raw_entry in _normalize_list(raw_entries):
        visit(raw_entry)

    deduped_entries = []
    seen_keys = set()
    for entry in normalized_entries:
        identity = (
            entry.get("pattern"),
            entry.get("pattern_mode"),
            entry.get("exact"),
            entry.get("by_side_effect"),
            entry.get("focus_metavariable"),
        )
        if identity in seen_keys:
            continue
        seen_keys.add(identity)
        deduped_entries.append(entry)

    return deduped_entries, notes


def _infer_default_exact_flag(pattern: str, item: dict[str, Any]) -> bool:
    """Default call-like patterns to exact matching unless explicitly overridden."""
    if "exact" in item:
        return bool(item.get("exact"))

    normalized = pattern.strip()
    if CALLABLE_HEAD_RE.match(normalized):
        return True
    return False


def _extract_cwe_ids(metadata: dict[str, Any]) -> list[str]:
    """Extract normalized CWE identifiers from Semgrep metadata."""
    cwe_values = _normalize_string_list(metadata.get("cwe"))
    cwe_ids = []
    for value in cwe_values:
        cwe_ids.extend(re.findall(r"CWE-\d+", value.upper()))
    return _dedupe_preserve_order(cwe_ids)


def _extract_owasp_refs(metadata: dict[str, Any]) -> list[str]:
    """Extract OWASP category references from Semgrep metadata."""
    values = _normalize_string_list(metadata.get("owasp"))
    refs = []
    for value in values:
        refs.extend(re.findall(r"A\d{1,2}:\d{4}", value.upper()))
    return _dedupe_preserve_order(refs)


def _extract_remediation_notes(metadata: dict[str, Any]) -> list[str]:
    """Pull lightweight remediation hints from common metadata fields."""
    notes = []
    for key in ("fix", "remediation", "shortlink"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            notes.append(value.strip())
    return _dedupe_preserve_order(notes)


def _map_severity(raw_severity: Any) -> str:
    """Map Semgrep severities to the Aegis severity vocabulary."""
    if isinstance(raw_severity, str):
        normalized = raw_severity.strip().upper()
        return SEVERITY_MAP.get(normalized, "MEDIUM")
    return "MEDIUM"


def _normalize_list(value: Any) -> list[Any]:
    """Normalize a scalar or list-shaped value into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_string_list(value: Any) -> list[str]:
    """Return only non-empty string values, preserving order."""
    normalized = []
    for item in _normalize_list(value):
        if isinstance(item, str) and item.strip():
            normalized.append(item.strip())
    return _dedupe_preserve_order(normalized)


def _dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    """Deduplicate string values while preserving the first-seen order."""
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _validate_rule(
    rule: dict[str, Any],
    *,
    rule_id: str,
    profile: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    path_prefix: str,
    require_schema_version: bool,
) -> None:
    """Validate one normalized rule mapping."""
    if require_schema_version:
        schema_version = rule.get("schema_version")
        if schema_version != "aegis-normalized-rule-v1":
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=f"{path_prefix}schema_version".rstrip("."),
                code="invalid_rule_schema_version",
                message="Single rule documents must declare schema_version 'aegis-normalized-rule-v1'.",
            )

    for field_name in ("rule_id", "title", "language", "family", "severity"):
        _require_non_empty_string(
            rule,
            field_name,
            rule_id=rule_id,
            errors=errors,
            path_prefix=path_prefix,
        )

    language = rule.get("language")
    if isinstance(language, str) and language not in SUPPORTED_LANGUAGES:
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=f"{path_prefix}language".rstrip("."),
            code="unsupported_language",
            message=f"Unsupported language '{language}'.",
        )

    family = rule.get("family")
    if isinstance(family, str) and family not in SUPPORTED_FAMILIES:
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=f"{path_prefix}family".rstrip("."),
            code="unsupported_family",
            message=f"Unsupported family '{family}'.",
        )

    severity = rule.get("severity")
    if isinstance(severity, str) and severity not in SUPPORTED_SEVERITIES:
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=f"{path_prefix}severity".rstrip("."),
            code="unsupported_severity",
            message=f"Unsupported severity '{severity}'.",
        )

    _validate_taxonomy(rule.get("taxonomy"), rule_id, errors, warnings, path_prefix)
    _validate_detection(rule.get("detection"), rule_id, errors, warnings, path_prefix)
    _validate_triage(rule.get("triage"), rule_id, errors, warnings, path_prefix)
    _validate_provenance(rule.get("provenance"), rule_id, errors, warnings, path_prefix)
    _validate_notes(rule.get("notes"), rule_id, errors, warnings, path_prefix)
    _validate_profile_scope(rule, rule_id=rule_id, profile=profile, errors=errors, path_prefix=path_prefix)


def _validate_taxonomy(
    taxonomy: Any,
    rule_id: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    path_prefix: str,
) -> None:
    """Validate taxonomy metadata."""
    field_path = f"{path_prefix}taxonomy".rstrip(".")
    if not isinstance(taxonomy, dict):
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=field_path,
            code="invalid_taxonomy",
            message="taxonomy must be a mapping containing 'cwe' and 'owasp' lists.",
        )
        return

    for list_name in ("cwe", "owasp"):
        values = taxonomy.get(list_name)
        path = f"{path_prefix}taxonomy.{list_name}".rstrip(".")
        if not isinstance(values, list):
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=path,
                code="invalid_taxonomy_list",
                message=f"taxonomy.{list_name} must be a list.",
            )
            continue
        for index, value in enumerate(values):
            item_path = f"{path}[{index}]"
            if not isinstance(value, str) or not value.strip():
                _record_issue(
                    errors,
                    level="error",
                    rule_id=rule_id,
                    path=item_path,
                    code="invalid_taxonomy_value",
                    message="Taxonomy values must be non-empty strings.",
                )
                continue
            if list_name == "cwe" and not CWE_RE.match(value.strip().upper()):
                _record_issue(
                    warnings,
                    level="warning",
                    rule_id=rule_id,
                    path=item_path,
                    code="suspicious_cwe_format",
                    message="Expected CWE identifiers like 'CWE-78'.",
                )
            if list_name == "owasp" and not OWASP_RE.match(value.strip().upper()):
                _record_issue(
                    warnings,
                    level="warning",
                    rule_id=rule_id,
                    path=item_path,
                    code="suspicious_owasp_format",
                    message="Expected OWASP identifiers like 'A05:2025'.",
                )


def _validate_detection(
    detection: Any,
    rule_id: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    path_prefix: str,
) -> None:
    """Validate detector-facing fields."""
    field_path = f"{path_prefix}detection".rstrip(".")
    if not isinstance(detection, dict):
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=field_path,
            code="invalid_detection",
            message="detection must be a mapping.",
        )
        return

    match_mode = detection.get("match_mode")
    if not isinstance(match_mode, str) or not match_mode.strip():
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=f"{path_prefix}detection.match_mode".rstrip("."),
            code="missing_match_mode",
            message="detection.match_mode must be a non-empty string.",
        )

    _validate_pattern_list(
        detection.get("source_patterns"),
        entry_kind="source_patterns",
        allow_empty=False,
        rule_id=rule_id,
        errors=errors,
        warnings=warnings,
        path_prefix=path_prefix,
    )
    _validate_pattern_list(
        detection.get("sink_patterns"),
        entry_kind="sink_patterns",
        allow_empty=False,
        rule_id=rule_id,
        errors=errors,
        warnings=warnings,
        path_prefix=path_prefix,
    )
    _validate_pattern_list(
        detection.get("sanitizers"),
        entry_kind="sanitizers",
        allow_empty=True,
        rule_id=rule_id,
        errors=errors,
        warnings=warnings,
        path_prefix=path_prefix,
    )


def _validate_pattern_list(
    raw_entries: Any,
    *,
    entry_kind: str,
    allow_empty: bool,
    rule_id: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    path_prefix: str,
) -> None:
    """Validate one list of normalized pattern entries."""
    path = f"{path_prefix}detection.{entry_kind}".rstrip(".")
    if not isinstance(raw_entries, list):
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=path,
            code="invalid_pattern_list",
            message=f"detection.{entry_kind} must be a list.",
        )
        return

    if not allow_empty and not raw_entries:
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=path,
            code="empty_pattern_list",
            message=f"detection.{entry_kind} must contain at least one entry.",
        )
        return

    for index, entry in enumerate(raw_entries):
        item_path = f"{path}[{index}]"
        if not isinstance(entry, dict):
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=item_path,
                code="invalid_pattern_entry",
                message="Pattern entries must be mappings.",
            )
            continue

        pattern = entry.get("pattern")
        pattern_mode = entry.get("pattern_mode")
        exact = entry.get("exact")
        by_side_effect = entry.get("by_side_effect")

        if not isinstance(pattern, str) or not pattern.strip():
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=f"{item_path}.pattern",
                code="missing_pattern",
                message="Pattern entries must include a non-empty 'pattern' string.",
            )
        if not isinstance(pattern_mode, str) or pattern_mode not in SUPPORTED_PATTERN_MODES:
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=f"{item_path}.pattern_mode",
                code="invalid_pattern_mode",
                message=f"pattern_mode must be one of {sorted(SUPPORTED_PATTERN_MODES)}.",
            )
        if not isinstance(exact, bool):
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=f"{item_path}.exact",
                code="invalid_exact_flag",
                message="'exact' must be a boolean.",
            )
        if not isinstance(by_side_effect, bool):
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=f"{item_path}.by_side_effect",
                code="invalid_by_side_effect_flag",
                message="'by_side_effect' must be a boolean.",
            )

        focus_metavariable = entry.get("focus_metavariable")
        if focus_metavariable is not None and (
            not isinstance(focus_metavariable, str) or not focus_metavariable.strip()
        ):
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=f"{item_path}.focus_metavariable",
                code="invalid_focus_metavariable",
                message="focus_metavariable must be a non-empty string when present.",
            )

        if (
            isinstance(pattern, str)
            and isinstance(pattern_mode, str)
            and pattern_mode == "pattern"
            and _looks_call_like_pattern(pattern)
            and exact is False
        ):
            _record_issue(
                warnings,
                level="warning",
                rule_id=rule_id,
                path=f"{item_path}.exact",
                code="call_pattern_without_exact",
                message=(
                    f"Call-like {entry_kind[:-1]} pattern '{pattern}' should likely set exact=true "
                    "to avoid substring bleed into unrelated APIs."
                ),
            )


def _validate_triage(
    triage: Any,
    rule_id: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    path_prefix: str,
) -> None:
    """Validate triage guidance fields."""
    field_path = f"{path_prefix}triage".rstrip(".")
    if not isinstance(triage, dict):
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=field_path,
            code="invalid_triage",
            message="triage must be a mapping.",
        )
        return

    for list_name in ("knowledge_refs", "fp_hints", "remediation_notes"):
        values = triage.get(list_name)
        path = f"{path_prefix}triage.{list_name}".rstrip(".")
        if not isinstance(values, list):
            _record_issue(
                errors,
                level="error",
                rule_id=rule_id,
                path=path,
                code="invalid_triage_list",
                message=f"triage.{list_name} must be a list.",
            )
            continue
        for index, value in enumerate(values):
            item_path = f"{path}[{index}]"
            if not isinstance(value, str) or not value.strip():
                _record_issue(
                    errors,
                    level="error",
                    rule_id=rule_id,
                    path=item_path,
                    code="invalid_triage_value",
                    message="Triage list values must be non-empty strings.",
                )


def _validate_provenance(
    provenance: Any,
    rule_id: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    path_prefix: str,
) -> None:
    """Validate provenance metadata."""
    field_path = f"{path_prefix}provenance".rstrip(".")
    if not isinstance(provenance, dict):
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=field_path,
            code="invalid_provenance",
            message="provenance must be a mapping.",
        )
        return

    for field_name in ("source", "source_rule_id", "importer", "snapshot_version"):
        _require_non_empty_string(
            provenance,
            field_name,
            rule_id=rule_id,
            errors=errors,
            path_prefix=f"{path_prefix}provenance.",
        )

    source_path = provenance.get("source_path")
    if source_path in (None, ""):
        _record_issue(
            warnings,
            level="warning",
            rule_id=rule_id,
            path=f"{path_prefix}provenance.source_path".rstrip("."),
            code="missing_source_path",
            message="provenance.source_path is empty; review provenance before merging the rule.",
        )
    elif not isinstance(source_path, str):
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=f"{path_prefix}provenance.source_path".rstrip("."),
            code="invalid_source_path",
            message="provenance.source_path must be a string when present.",
        )


def _validate_notes(
    notes: Any,
    rule_id: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    path_prefix: str,
) -> None:
    """Validate optional notes metadata."""
    if notes is None:
        return
    path = f"{path_prefix}notes".rstrip(".")
    if not isinstance(notes, list):
        _record_issue(
            warnings,
            level="warning",
            rule_id=rule_id,
            path=path,
            code="invalid_notes",
            message="notes should be a list of strings when present.",
        )
        return
    for index, value in enumerate(notes):
        if not isinstance(value, str) or not value.strip():
            _record_issue(
                warnings,
                level="warning",
                rule_id=rule_id,
                path=f"{path}[{index}]",
                code="invalid_note_value",
                message="notes entries should be non-empty strings.",
            )


def _validate_profile_scope(
    rule: dict[str, Any],
    *,
    rule_id: str,
    profile: str,
    errors: list[dict[str, Any]],
    path_prefix: str,
) -> None:
    """Validate profile-specific scope constraints."""
    if profile != "python-rule-workbench-v1":
        return

    language = rule.get("language")
    if isinstance(language, str) and language != "python":
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=f"{path_prefix}language".rstrip("."),
            code="out_of_scope_language",
            message="python-rule-workbench-v1 only accepts language='python'.",
        )

    family = rule.get("family")
    if isinstance(family, str) and family not in WORKBENCH_V1_FAMILIES:
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=f"{path_prefix}family".rstrip("."),
            code="out_of_scope_family",
            message=f"python-rule-workbench-v1 only accepts families {sorted(WORKBENCH_V1_FAMILIES)}.",
        )


def _require_non_empty_string(
    mapping: dict[str, Any],
    field_name: str,
    *,
    rule_id: str,
    errors: list[dict[str, Any]],
    path_prefix: str,
) -> None:
    """Require a non-empty string field inside a mapping."""
    value = mapping.get(field_name)
    if not isinstance(value, str) or not value.strip():
        _record_issue(
            errors,
            level="error",
            rule_id=rule_id,
            path=f"{path_prefix}{field_name}".rstrip("."),
            code="missing_required_field",
            message=f"Expected a non-empty string for '{field_name}'.",
        )


def _looks_call_like_pattern(pattern: str) -> bool:
    """Heuristically detect simple call-like patterns such as os.system(...)."""
    head, separator, _ = pattern.partition("(")
    if separator != "(":
        return False
    return bool(re.match(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*$", head.strip()))


def _safe_rule_id(rule: dict[str, Any], fallback: str = "<missing-rule-id>") -> str:
    """Return a stable rule identifier for validation reporting."""
    rule_id = rule.get("rule_id")
    if isinstance(rule_id, str) and rule_id.strip():
        return rule_id.strip()
    return fallback


def _record_issue(
    bucket: list[dict[str, Any]],
    *,
    level: str,
    rule_id: str,
    path: str,
    code: str,
    message: str,
) -> None:
    """Append one validation issue to the given bucket."""
    bucket.append(
        {
            "level": level,
            "rule_id": rule_id,
            "path": path or "<document>",
            "code": code,
            "message": message,
        }
    )


def _extract_rules(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the rule list from a single-rule or rule-set document."""
    schema_version = document.get("schema_version")
    if schema_version == "aegis-normalized-rule-v1":
        return [document]
    if schema_version == "aegis-normalized-rule-set-v1":
        rules = document.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError("Rule-set documents must contain a top-level 'rules' list.")
        return [rule for rule in rules if isinstance(rule, dict)]
    raise ValueError(
        "Unsupported schema_version. Expected aegis-normalized-rule-v1 or aegis-normalized-rule-set-v1."
    )


def _convert_pattern_entry(
    entry: Any,
    *,
    rule_id: str,
    role: str,
    report: dict[str, Any],
) -> str | None:
    """Convert one normalized pattern entry into the legacy scanner pattern format."""
    if not isinstance(entry, dict):
        report["skipped_patterns"].append(
            {"rule_id": rule_id, "role": role, "reason": "entry is not a mapping"}
        )
        return None

    pattern = entry.get("pattern")
    pattern_mode = entry.get("pattern_mode")
    if not isinstance(pattern, str) or not pattern.strip():
        report["skipped_patterns"].append(
            {"rule_id": rule_id, "role": role, "reason": "missing pattern"}
        )
        return None
    if pattern_mode not in {"pattern", "literal"}:
        report["skipped_patterns"].append(
            {
                "rule_id": rule_id,
                "role": role,
                "reason": f"unsupported pattern_mode {pattern_mode}",
                "pattern": pattern,
            }
        )
        return None

    normalized = _normalize_pattern_for_legacy(pattern.strip())
    if normalized is None:
        report["skipped_patterns"].append(
            {
                "rule_id": rule_id,
                "role": role,
                "reason": "pattern cannot be represented in the legacy rule engine",
                "pattern": pattern,
            }
        )
        return None
    return normalized


def _normalize_pattern_for_legacy(pattern: str) -> str | None:
    """Convert a reviewable normalized pattern into a detector-friendly legacy pattern."""
    if "$" in pattern:
        return None

    match = LEGACY_CALLABLE_HEAD_RE.match(pattern)
    if match:
        return f"{match.group(1)}("

    if pattern.startswith("re:"):
        return None

    return pattern


def _infer_legacy_source_type(pattern: str) -> str:
    """Infer a basic legacy source type from one source pattern."""
    lowered = pattern.lower()
    if "request.args" in lowered or "request.form" in lowered or "request.values" in lowered:
        return "HTTP_PARAM"
    if "request.json" in lowered or "request.data" in lowered:
        return "HTTP_DATA"
    if lowered.startswith("input("):
        return "USER_INPUT"
    if lowered.startswith("sys.argv"):
        return "COMMAND_LINE_ARGS"
    if lowered.startswith("os.environ"):
        return "ENVIRONMENT_VAR"
    if "req.query" in lowered or "req.body" in lowered:
        return "HTTP_PARAM"
    return "UNTRUSTED_INPUT"


_DEFAULT_SERVICE = RuleWorkbenchService()


def load_semgrep_document(path: Path) -> dict[str, Any]:
    """Load a Semgrep-shaped rule document through the default service."""
    return _DEFAULT_SERVICE.load_semgrep_document(path)


def load_normalized_document(path: Path) -> dict[str, Any]:
    """Load a normalized rule document through the default service."""
    return _DEFAULT_SERVICE.load_normalized_document(path)


def load_rule_document(path: Path) -> dict[str, Any]:
    """Backward-compatible alias used by validator-oriented callers."""
    return _DEFAULT_SERVICE.load_mapping_document(path)


def normalize_semgrep_document(
    document: dict[str, Any],
    *,
    language_filter: str | None = None,
    family_override: str | None = None,
    limit: int | None = None,
    provenance_source: str = "semgrep",
    snapshot_version: str = "manual-seed-v1",
    source_path: Path | None = None,
) -> dict[str, Any]:
    """Normalize a Semgrep document through the default service."""
    return _DEFAULT_SERVICE.normalize_semgrep_document(
        document,
        language_filter=language_filter,
        family_override=family_override,
        limit=limit,
        provenance_source=provenance_source,
        snapshot_version=snapshot_version,
        source_path=source_path,
    )


def normalize_semgrep_rule(
    rule: Any,
    *,
    language_filter: str | None = None,
    family_override: str | None = None,
    provenance_source: str = "semgrep",
    snapshot_version: str = "manual-seed-v1",
    source_path: Path | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Normalize one Semgrep rule through the default service."""
    return _DEFAULT_SERVICE.normalize_semgrep_rule(
        rule,
        language_filter=language_filter,
        family_override=family_override,
        provenance_source=provenance_source,
        snapshot_version=snapshot_version,
        source_path=source_path,
    )


def write_normalized_document(document: dict[str, Any], output_path: Path, format_name: str) -> None:
    """Write a normalized document through the default service."""
    _DEFAULT_SERVICE.write_normalized_document(document, output_path, format_name)


def validate_normalized_document(document: dict[str, Any], *, profile: str = "generic") -> dict[str, Any]:
    """Validate a normalized document through the default service."""
    return _DEFAULT_SERVICE.validate_normalized_document(document, profile=profile)


def format_validation_report(report: dict[str, Any], *, format_name: str) -> str:
    """Format a validation report through the default service."""
    return _DEFAULT_SERVICE.format_validation_report(report, format_name=format_name)


def write_validation_report(
    report: dict[str, Any],
    *,
    format_name: str,
    output_path: Path | None = None,
) -> None:
    """Write a validation report through the default service."""
    _DEFAULT_SERVICE.write_validation_report(report, format_name=format_name, output_path=output_path)


def export_legacy_rules(
    document: dict[str, Any],
    *,
    language_filter: str | None = None,
    family_filter: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Export legacy rules through the default service."""
    return _DEFAULT_SERVICE.export_legacy_rules(
        document,
        language_filter=language_filter,
        family_filter=family_filter,
    )


def write_legacy_document(document: dict[str, Any], output_path: Path, format_name: str) -> None:
    """Write a legacy rules document through the default service."""
    _DEFAULT_SERVICE.write_legacy_document(document, output_path, format_name)


def write_report(report: dict[str, Any], output_path: Path) -> None:
    """Write a JSON report through the default service."""
    _DEFAULT_SERVICE.write_report(report, output_path)


def build_review_bundle(
    *,
    input_path: Path,
    output_dir: Path,
    language: str | None = None,
    family: str | None = None,
    limit: int | None = None,
    normalized_format: str = "json",
    validation_format: str = "json",
    profile: str = "generic",
    provenance_source: str = "semgrep",
    snapshot_version: str = "manual-seed-v1",
    legacy_format: str | None = None,
) -> dict[str, Any]:
    """Build one review bundle through the default service."""
    request = RuleWorkbenchBundleRequest(
        input_path=input_path,
        output_dir=output_dir,
        language=language,
        family=family,
        limit=limit,
        normalized_format=normalized_format,
        validation_format=validation_format,
        profile=profile,
        provenance_source=provenance_source,
        snapshot_version=snapshot_version,
        legacy_format=legacy_format,
    )
    return _DEFAULT_SERVICE.build_review_bundle(request).to_mapping()

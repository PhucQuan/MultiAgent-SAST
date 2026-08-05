"""Reusable business logic for rule import, validation, and bundle export."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .models import (
    RuleWorkbenchBundleRequest,
    RuleWorkbenchBundleResult,
    RuleWorkbenchDraftRequest,
    RuleWorkbenchDraftResult,
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
LANGUAGE_PREFIXES = {
    "python": "PY",
    "javascript": "JS",
    "java": "JAVA",
    "php": "PHP",
}
FAMILY_DEFAULTS = {
    "COMMAND_INJECTION": {
        "cwe": ["CWE-78"],
        "owasp": ["A05:2025"],
        "severity": "CRITICAL",
        "knowledge_refs": ["generic-command-injection"],
        "fp_hints": ["constant-command-string", "argument-array-with-shell-false"],
        "remediation_notes": ["Prefer subprocess argument arrays and keep shell disabled."],
    },
    "PATH_TRAVERSAL": {
        "cwe": ["CWE-22"],
        "owasp": ["A01:2025"],
        "severity": "HIGH",
        "knowledge_refs": ["generic-path-traversal"],
        "fp_hints": ["trusted-base-dir-join", "normalized-path-under-root"],
        "remediation_notes": ["Resolve the path under a trusted base directory and reject escapes."],
    },
    "INSECURE_DESERIALIZATION": {
        "cwe": ["CWE-502"],
        "owasp": ["A08:2025"],
        "severity": "CRITICAL",
        "knowledge_refs": ["generic-insecure-deserialization"],
        "fp_hints": ["safe-loader-only", "trusted-static-payload"],
        "remediation_notes": ["Prefer safe loaders or structured formats instead of unsafe object deserialization."],
    },
    "SQL_INJECTION": {
        "cwe": ["CWE-89"],
        "owasp": ["A05:2025"],
        "severity": "CRITICAL",
        "knowledge_refs": ["generic-sql-injection"],
        "fp_hints": ["parameterized-query", "strict-type-cast-before-query"],
        "remediation_notes": ["Use parameterized queries and avoid string-built SQL."],
    },
    "SSRF": {
        "cwe": ["CWE-918"],
        "owasp": ["A01:2025"],
        "severity": "HIGH",
        "knowledge_refs": ["generic-ssrf"],
        "fp_hints": ["allowlist-hosts", "internal-only-fixed-endpoint"],
        "remediation_notes": ["Restrict outbound destinations and resolve user-controlled URLs against an allowlist."],
    },
}
DRAFT_PATTERN_LIMITS = {
    "source_patterns": 4,
    "sink_patterns": 5,
    "sanitizers": 4,
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
LEGACY_CONSTRUCTOR_HEAD_RE = re.compile(
    r"^new\s+([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)(?:<[^>]+>)?\("
)


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

    def merge_normalized_documents(
        self,
        documents: Iterable[dict[str, Any]],
        *,
        source_paths: Iterable[Path | None] | None = None,
    ) -> dict[str, Any]:
        """Merge one or more normalized documents into a deduplicated rule-set document."""
        normalized_documents = list(documents)
        if not normalized_documents:
            raise ValueError("At least one normalized document is required for merging.")

        resolved_source_paths = list(source_paths or [])
        if resolved_source_paths and len(resolved_source_paths) != len(normalized_documents):
            raise ValueError("source_paths must match the number of normalized documents.")

        merged_rules: list[dict[str, Any]] = []
        merged_skipped_rules: list[dict[str, Any]] = []
        merged_source_documents: list[str] = []
        seen_rule_keys: set[str] = set()
        seen_source_documents: set[str] = set()

        for index, document in enumerate(normalized_documents):
            fallback_path = resolved_source_paths[index] if index < len(resolved_source_paths) else None

            for source_document in _source_documents_for_merge(document, fallback_path=fallback_path):
                if source_document in seen_source_documents:
                    continue
                seen_source_documents.add(source_document)
                merged_source_documents.append(source_document)

            skipped_rules = document.get("skipped_rules", [])
            if isinstance(skipped_rules, list):
                merged_skipped_rules.extend(item for item in skipped_rules if isinstance(item, dict))

            for rule in _extract_rules(document):
                dedupe_key = _rule_dedupe_key(rule)
                if dedupe_key in seen_rule_keys:
                    continue
                seen_rule_keys.add(dedupe_key)
                merged_rules.append(rule)

        merged_document = {
            "schema_version": "aegis-normalized-rule-set-v1",
            "generated_by": "aegis_sast.rule_workbench.service",
            "source_path": merged_source_documents[0] if len(merged_source_documents) == 1 else None,
            "source_document_count": len(merged_source_documents),
            "source_documents": merged_source_documents,
            "rule_count": len(merged_rules),
            "rules": merged_rules,
            "skipped_rules": merged_skipped_rules,
        }
        return merged_document

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

    def build_draft_bundle(self, request: RuleWorkbenchDraftRequest) -> RuleWorkbenchDraftResult:
        """Build one AI-ready draft bundle from a natural-language description and a local seed."""
        description = (request.description or "").strip()
        if not description:
            raise ValueError("A natural-language description is required for draft generation.")

        language = request.language.strip().lower()
        family = request.family.strip().upper()
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported draft language: {request.language}")
        if family not in SUPPORTED_FAMILIES:
            raise ValueError(f"Unsupported draft family: {request.family}")

        paths = self.storage.build_draft_paths(
            seed_input_path=request.seed_input_path,
            output_dir=request.output_dir,
            normalized_format=request.normalized_format,
            validation_format=request.validation_format,
            legacy_format=request.legacy_format,
        )

        seed_context = self._load_seed_context(
            seed_input_path=request.seed_input_path,
            language=language,
            family=family,
            snapshot_version=request.snapshot_version,
        )
        self.storage.write_json_report(seed_context, paths.seed_context_path)

        draft_document = self._build_draft_document(
            request=request,
            seed_context=seed_context,
            language=language,
            family=family,
        )
        self.write_normalized_document(
            draft_document,
            paths.draft_path,
            request.normalized_format,
        )

        draft_prompt = self._build_draft_prompt(
            request=request,
            draft_document=draft_document,
            seed_context=seed_context,
        )
        self.storage.write_text_report(draft_prompt, paths.prompt_path)

        validation_report = self.validate_normalized_document(
            draft_document,
            profile=request.profile,
        )
        self.write_validation_report(
            validation_report,
            format_name=request.validation_format,
            output_path=paths.validation_path,
        )

        if request.legacy_format and paths.legacy_path and paths.legacy_report_path:
            legacy_document, legacy_report = self.export_legacy_rules(
                draft_document,
                language_filter=language,
                family_filter=family,
            )
            self.write_legacy_document(
                legacy_document,
                paths.legacy_path,
                request.legacy_format,
            )
            self.write_report(legacy_report, paths.legacy_report_path)

        return RuleWorkbenchDraftResult(
            paths=paths,
            valid=validation_report["valid"],
            rules_checked=validation_report["rules_checked"],
            error_count=validation_report["error_count"],
            warning_count=validation_report["warning_count"],
        )

    def _load_seed_context(
        self,
        *,
        seed_input_path: Path,
        language: str,
        family: str,
        snapshot_version: str,
    ) -> dict[str, Any]:
        """Load one local seed file and reduce it to a draft-friendly context payload."""
        seed_document = self.storage.load_mapping_document(seed_input_path)
        schema_version = seed_document.get("schema_version")

        if schema_version in {"aegis-normalized-rule-v1", "aegis-normalized-rule-set-v1"}:
            normalized_document = seed_document
            document_kind = "normalized"
        elif isinstance(seed_document.get("rules"), list):
            normalized_document = self.normalize_semgrep_document(
                seed_document,
                language_filter=language,
                family_override=family,
                provenance_source="seed-context",
                snapshot_version=snapshot_version,
                source_path=seed_input_path,
            )
            document_kind = "semgrep"
        else:
            raise ValueError(
                "Seed input must be either a normalized rule document or a Semgrep-shaped mapping with a top-level 'rules' list."
            )

        rules = [
            rule
            for rule in _extract_rules(normalized_document)
            if rule.get("language") == language and rule.get("family") == family
        ]
        if not rules:
            raise ValueError(
                f"Seed input did not provide any normalized rules for language={language} family={family}."
            )

        return {
            "seed_source_path": str(seed_input_path),
            "seed_document_kind": document_kind,
            "seed_rule_count": len(rules),
            "seed_rules": [_seed_rule_summary(rule) for rule in rules],
            "selected_patterns": {
                "source_patterns": _collect_pattern_entries(
                    rules,
                    "source_patterns",
                    limit=DRAFT_PATTERN_LIMITS["source_patterns"],
                ),
                "sink_patterns": _collect_pattern_entries(
                    rules,
                    "sink_patterns",
                    limit=DRAFT_PATTERN_LIMITS["sink_patterns"],
                ),
                "sanitizers": _collect_pattern_entries(
                    rules,
                    "sanitizers",
                    limit=DRAFT_PATTERN_LIMITS["sanitizers"],
                ),
            },
            "taxonomy": {
                "cwe": _merge_taxonomy_values(rules, "cwe", family),
                "owasp": _merge_taxonomy_values(rules, "owasp", family),
            },
            "triage_defaults": {
                "knowledge_refs": _merge_triage_values(rules, "knowledge_refs", family),
                "fp_hints": _merge_triage_values(rules, "fp_hints", family),
                "remediation_notes": _merge_triage_values(rules, "remediation_notes", family),
            },
            "severity": _seed_severity(rules, family),
            "seed_rule_ids": [_safe_rule_id(rule) for rule in rules],
        }

    def _build_draft_document(
        self,
        *,
        request: RuleWorkbenchDraftRequest,
        seed_context: dict[str, Any],
        language: str,
        family: str,
    ) -> dict[str, Any]:
        """Create one normalized draft rule from seed context and user description."""
        description_hints = _extract_description_hints(request.description)
        selected_patterns = seed_context["selected_patterns"]

        source_patterns = _merge_pattern_candidates(
            description_hints.get("source_patterns", []),
            selected_patterns.get("source_patterns", []),
            limit=DRAFT_PATTERN_LIMITS["source_patterns"],
        )
        sink_patterns = _merge_pattern_candidates(
            description_hints.get("sink_patterns", []),
            selected_patterns.get("sink_patterns", []),
            limit=DRAFT_PATTERN_LIMITS["sink_patterns"],
        )
        sanitizer_patterns = _merge_pattern_candidates(
            description_hints.get("sanitizers", []),
            selected_patterns.get("sanitizers", []),
            limit=DRAFT_PATTERN_LIMITS["sanitizers"],
        )

        if not source_patterns or not sink_patterns:
            raise ValueError(
                "The seed context did not provide enough source/sink material to build a reviewable draft."
            )

        title = request.title or _derive_draft_title(request.description, family)
        rule_id = request.rule_id or _derive_draft_rule_id(language, family, title)

        notes = [
            "Draft generated from a natural-language description plus a local reviewed seed snapshot.",
            f"User description: {request.description.strip()}",
            f"Seed source: {seed_context['seed_source_path']}",
        ]
        if description_hints["notes"]:
            notes.extend(description_hints["notes"])

        return {
            "schema_version": "aegis-normalized-rule-v1",
            "rule_id": rule_id,
            "title": title,
            "language": language,
            "family": family,
            "severity": seed_context["severity"],
            "taxonomy": seed_context["taxonomy"],
            "detection": {
                "match_mode": "aegis-ai-draft",
                "source_patterns": source_patterns,
                "sink_patterns": sink_patterns,
                "sanitizers": sanitizer_patterns,
            },
            "triage": seed_context["triage_defaults"],
            "provenance": {
                "source": request.provenance_source,
                "source_rule_id": _summarize_seed_rule_ids(seed_context["seed_rule_ids"]),
                "source_path": str(request.seed_input_path),
                "importer": "aegis_sast.rule_workbench.service",
                "snapshot_version": request.snapshot_version,
            },
            "notes": notes,
        }

    def _build_draft_prompt(
        self,
        *,
        request: RuleWorkbenchDraftRequest,
        draft_document: dict[str, Any],
        seed_context: dict[str, Any],
    ) -> str:
        """Render a copy-pasteable AI prompt for refining the starter draft."""
        seed_patterns = seed_context["selected_patterns"]
        return (
            "You are adapting a reviewed Aegis-SAST rule draft.\n\n"
            "Task:\n"
            f"- Language: {request.language}\n"
            f"- Family: {request.family}\n"
            "- Goal: refine the starter normalized rule below without inventing broad, runtime-unsafe patterns.\n"
            "- Keep the final output as one JSON object that follows the Aegis normalized rule schema.\n\n"
            "User description:\n"
            f"{request.description.strip()}\n\n"
            "Seed context:\n"
            f"- Seed path: {seed_context['seed_source_path']}\n"
            f"- Seed rule ids: {', '.join(seed_context['seed_rule_ids'])}\n"
            f"- Candidate source patterns: {_format_pattern_list(seed_patterns.get('source_patterns', []))}\n"
            f"- Candidate sink patterns: {_format_pattern_list(seed_patterns.get('sink_patterns', []))}\n"
            f"- Candidate sanitizers: {_format_pattern_list(seed_patterns.get('sanitizers', []))}\n\n"
            "Hard constraints:\n"
            "- Stay inside the requested language and vulnerability family.\n"
            "- Keep detection metadata separate from triage guidance.\n"
            "- Prefer exact callable-head patterns for dangerous sinks.\n"
            "- Do not widen sources or sinks beyond what the seed and description justify.\n"
            "- Preserve provenance fields and keep source_path pointing to the local seed snapshot.\n"
            "- Return only the final JSON object, no markdown fences.\n\n"
            "Starter draft JSON:\n"
            f"{json.dumps(draft_document, indent=2, ensure_ascii=False)}\n"
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

    def append_entry(
        pattern: str,
        *,
        pattern_mode: str,
        exact: bool,
        by_side_effect: bool,
        focus_metavariable: str | None,
    ) -> None:
        normalized_entries.append(
            {
                "pattern": pattern,
                "pattern_mode": pattern_mode,
                "exact": exact,
                "by_side_effect": by_side_effect,
                "focus_metavariable": focus_metavariable,
            }
        )

    def extract_focus_metavariable(item: Any) -> str | None:
        if not isinstance(item, dict):
            return None
        focus_value = item.get("focus-metavariable")
        if isinstance(focus_value, str) and focus_value.strip():
            return focus_value.strip()
        return None

    def is_modifier_only_entry(item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        keys = set(item.keys())
        return keys.issubset(
            {
                "focus-metavariable",
                "metavariable-regex",
                "metavariable-pattern",
                "metavariable-comparison",
                "pattern-not",
                "pattern-not-regex",
                "pattern-not-inside",
                "pattern-where-python",
                "pattern-where-java",
            }
        )

    def resolve_nested_focus(nested_values: list[Any], fallback: str | None) -> str | None:
        focus_metavariable = fallback
        for child in nested_values:
            child_focus = extract_focus_metavariable(child)
            if child_focus:
                focus_metavariable = child_focus
        return focus_metavariable

    def visit(item: Any, *, inherited_focus: str | None = None) -> None:
        if isinstance(item, str):
            append_entry(
                item,
                pattern_mode="literal",
                exact=False,
                by_side_effect=False,
                focus_metavariable=inherited_focus,
            )
            return

        if not isinstance(item, dict):
            notes.append(f"Skipped {entry_kind} entry with unsupported type: {type(item).__name__}")
            return

        focus_metavariable = extract_focus_metavariable(item) or inherited_focus
        has_reviewable_pattern = False

        direct_pattern = item.get("pattern")
        if isinstance(direct_pattern, str):
            append_entry(
                direct_pattern,
                pattern_mode="pattern",
                exact=_infer_default_exact_flag(direct_pattern, item),
                by_side_effect=bool(item.get("by-side-effect", False)),
                focus_metavariable=focus_metavariable,
            )
            has_reviewable_pattern = True

        direct_pattern_inside = item.get("pattern-inside")
        if isinstance(direct_pattern_inside, str):
            append_entry(
                direct_pattern_inside,
                pattern_mode="pattern",
                exact=False,
                by_side_effect=bool(item.get("by-side-effect", False)),
                focus_metavariable=focus_metavariable,
            )
            has_reviewable_pattern = True

        direct_regex = item.get("pattern-regex")
        if isinstance(direct_regex, str):
            append_entry(
                direct_regex,
                pattern_mode="pattern-regex",
                exact=bool(item.get("exact", False)),
                by_side_effect=bool(item.get("by-side-effect", False)),
                focus_metavariable=focus_metavariable,
            )
            has_reviewable_pattern = True

        has_nested_groups = False
        for nested_key in ("pattern-either", "patterns"):
            nested = item.get(nested_key)
            if nested is None:
                continue
            has_nested_groups = True
            if not isinstance(nested, list):
                notes.append(f"Skipped {entry_kind} nested group '{nested_key}' because it is not a list")
                continue
            nested_focus = resolve_nested_focus(nested, focus_metavariable)
            for child in nested:
                if is_modifier_only_entry(child):
                    continue
                visit(child, inherited_focus=nested_focus)

        if (
            not has_reviewable_pattern
            and not isinstance(direct_regex, str)
            and not isinstance(direct_pattern_inside, str)
            and not has_nested_groups
            and not is_modifier_only_entry(item)
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


def _source_documents_for_merge(
    document: dict[str, Any],
    *,
    fallback_path: Path | None = None,
) -> list[str]:
    """Collect stable provenance paths for a normalized document merge."""
    raw_source_documents = document.get("source_documents")
    candidates: list[str] = []

    if isinstance(raw_source_documents, list):
        candidates.extend(
            item.strip()
            for item in raw_source_documents
            if isinstance(item, str) and item.strip()
        )
    elif isinstance(document.get("source_path"), str) and str(document["source_path"]).strip():
        candidates.append(str(document["source_path"]).strip())
    elif fallback_path is not None:
        candidates.append(str(fallback_path))

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _rule_dedupe_key(rule: dict[str, Any]) -> str:
    """Return a stable deep-identity key for one normalized rule."""
    return json.dumps(rule, sort_keys=True, ensure_ascii=False)


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

    constructor_match = LEGACY_CONSTRUCTOR_HEAD_RE.match(pattern)
    if constructor_match:
        return f"new {constructor_match.group(1)}("

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


def _seed_rule_summary(rule: dict[str, Any]) -> dict[str, Any]:
    """Return a compact, serializable summary for one normalized seed rule."""
    detection = rule.get("detection", {})
    taxonomy = rule.get("taxonomy", {})
    triage = rule.get("triage", {})
    return {
        "rule_id": _safe_rule_id(rule),
        "title": rule.get("title", ""),
        "language": rule.get("language"),
        "family": rule.get("family"),
        "severity": rule.get("severity"),
        "taxonomy": {
            "cwe": _normalize_string_list(taxonomy.get("cwe")),
            "owasp": _normalize_string_list(taxonomy.get("owasp")),
        },
        "detection": {
            "match_mode": detection.get("match_mode"),
            "source_patterns": detection.get("source_patterns", []),
            "sink_patterns": detection.get("sink_patterns", []),
            "sanitizers": detection.get("sanitizers", []),
        },
        "triage": {
            "knowledge_refs": _normalize_string_list(triage.get("knowledge_refs")),
            "fp_hints": _normalize_string_list(triage.get("fp_hints")),
            "remediation_notes": _normalize_string_list(triage.get("remediation_notes")),
        },
    }


def _collect_pattern_entries(
    rules: list[dict[str, Any]],
    field_name: str,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Merge pattern entries from multiple normalized rules while preserving order."""
    entries: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for rule in rules:
        detection = rule.get("detection", {})
        raw_entries = detection.get(field_name, [])
        if not isinstance(raw_entries, list):
            continue
        for entry in raw_entries:
            if not isinstance(entry, dict):
                continue
            identity = (
                entry.get("pattern"),
                entry.get("pattern_mode"),
                entry.get("exact"),
                entry.get("by_side_effect"),
                entry.get("focus_metavariable"),
            )
            if identity in seen:
                continue
            seen.add(identity)
            entries.append(dict(entry))
            if len(entries) >= limit:
                return entries
    return entries


def _merge_taxonomy_values(
    rules: list[dict[str, Any]],
    key: str,
    family: str,
) -> list[str]:
    """Merge taxonomy values from normalized rules with family-based fallback."""
    merged: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        taxonomy = rule.get("taxonomy", {})
        values = taxonomy.get(key, []) if isinstance(taxonomy, dict) else []
        for value in _normalize_string_list(values):
            if value in seen:
                continue
            seen.add(value)
            merged.append(value)

    if not merged:
        for value in FAMILY_DEFAULTS.get(family, {}).get(key, []):
            if value in seen:
                continue
            seen.add(value)
            merged.append(value)
    return merged


def _merge_triage_values(
    rules: list[dict[str, Any]],
    key: str,
    family: str,
) -> list[str]:
    """Merge triage guidance from normalized seed rules with family defaults."""
    merged: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        triage = rule.get("triage", {})
        values = triage.get(key, []) if isinstance(triage, dict) else []
        for value in _normalize_string_list(values):
            if value in seen:
                continue
            seen.add(value)
            merged.append(value)

    if not merged:
        for value in FAMILY_DEFAULTS.get(family, {}).get(key, []):
            if value in seen:
                continue
            seen.add(value)
            merged.append(value)
    return merged


def _seed_severity(rules: list[dict[str, Any]], family: str) -> str:
    """Pick the strongest severity present in seed rules or a family fallback."""
    ranking = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    best = FAMILY_DEFAULTS.get(family, {}).get("severity", "HIGH")
    best_score = ranking.get(best, 0)
    for rule in rules:
        severity = str(rule.get("severity", "")).upper()
        score = ranking.get(severity, -1)
        if score > best_score:
            best = severity
            best_score = score
    return best


def _extract_description_hints(description: str) -> dict[str, Any]:
    """Parse lightweight source/sink/sanitizer hints from a natural-language description."""
    hints = {
        "source_patterns": [],
        "sink_patterns": [],
        "sanitizers": [],
        "notes": [],
    }

    label_map = {
        "source": "source_patterns",
        "sources": "source_patterns",
        "sink": "sink_patterns",
        "sinks": "sink_patterns",
        "sanitizer": "sanitizers",
        "sanitizers": "sanitizers",
    }

    for raw_line in description.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        label, raw_values = line.split(":", 1)
        normalized_label = label.strip().lower()
        if normalized_label not in label_map:
            continue
        bucket = label_map[normalized_label]
        for token in re.split(r"[,\n;]+", raw_values):
            pattern_entry = _pattern_entry_from_hint(token.strip())
            if pattern_entry is not None:
                hints[bucket].append(pattern_entry)
        if hints[bucket]:
            hints["notes"].append(
                f"Used explicit {normalized_label} hints from the natural-language description."
            )

    return hints


def _pattern_entry_from_hint(raw_value: str) -> dict[str, Any] | None:
    """Convert one human-written API hint into a normalized pattern entry."""
    value = raw_value.strip()
    if not value:
        return None

    value = value.rstrip(".")
    if value.endswith("()"):
        callable_head = value[:-2].strip()
        if callable_head:
            return {
                "pattern": f"{callable_head}(...)",
                "pattern_mode": "pattern",
                "exact": True,
                "by_side_effect": False,
            }

    if value.endswith("("):
        callable_head = value[:-1].strip()
        if callable_head:
            return {
                "pattern": f"{callable_head}(...)",
                "pattern_mode": "pattern",
                "exact": True,
                "by_side_effect": False,
            }

    if CALLABLE_HEAD_RE.match(f"{value}("):
        return {
            "pattern": f"{value}(...)",
            "pattern_mode": "pattern",
            "exact": True,
            "by_side_effect": False,
        }

    return {
        "pattern": value,
        "pattern_mode": "literal",
        "exact": False,
        "by_side_effect": False,
    }


def _merge_pattern_candidates(
    preferred: list[dict[str, Any]],
    fallback: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Merge explicit hint patterns ahead of seed-derived fallback patterns."""
    merged: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for entry in [*preferred, *fallback]:
        if not isinstance(entry, dict):
            continue
        identity = (
            entry.get("pattern"),
            entry.get("pattern_mode"),
            entry.get("exact"),
            entry.get("by_side_effect"),
            entry.get("focus_metavariable"),
        )
        if identity in seen:
            continue
        seen.add(identity)
        merged.append(dict(entry))
        if len(merged) >= limit:
            break
    return merged


def _derive_draft_title(description: str, family: str) -> str:
    """Build a human-readable title for one AI draft rule."""
    first_line = next((line.strip() for line in description.splitlines() if line.strip()), "")
    first_line = re.sub(r"\s+", " ", first_line)
    first_line = re.split(r"\b(?:Sources?|Sinks?|Sanitizers?)\s*:", first_line, maxsplit=1)[0].strip()
    if not first_line:
        return f"Draft {family.replace('_', ' ').title()} rule"
    if len(first_line) > 72:
        first_line = first_line[:69].rstrip() + "..."
    return first_line


def _derive_draft_rule_id(language: str, family: str, title: str) -> str:
    """Build a stable draft rule id from language, family, and title."""
    language_prefix = LANGUAGE_PREFIXES.get(language, language.upper())
    family_slug = family.replace("_", "-")
    title_slug = re.sub(r"[^A-Za-z0-9]+", "-", title.upper()).strip("-")
    title_slug = re.sub(r"-{2,}", "-", title_slug)
    compact = title_slug[:32].strip("-") or "DRAFT"
    return f"{language_prefix}-{family_slug}-{compact}-DRAFT"


def _summarize_seed_rule_ids(seed_rule_ids: list[str]) -> str:
    """Collapse multiple seed rule ids into one provenance-friendly string."""
    cleaned = [item for item in seed_rule_ids if item]
    if not cleaned:
        return "seed:<missing>"
    if len(cleaned) == 1:
        return cleaned[0]
    return f"{cleaned[0]} (+{len(cleaned) - 1} more)"


def _format_pattern_list(entries: list[dict[str, Any]]) -> str:
    """Render normalized pattern entries for prompt text."""
    patterns = [entry.get("pattern", "<missing-pattern>") for entry in entries if isinstance(entry, dict)]
    return ", ".join(patterns) if patterns else "none"


_DEFAULT_SERVICE = RuleWorkbenchService()


def load_semgrep_document(path: Path) -> dict[str, Any]:
    """Load a Semgrep-shaped rule document through the default service."""
    return _DEFAULT_SERVICE.load_semgrep_document(path)


def load_normalized_document(path: Path) -> dict[str, Any]:
    """Load a normalized rule document through the default service."""
    return _DEFAULT_SERVICE.load_normalized_document(path)


def merge_normalized_documents(
    documents: Iterable[dict[str, Any]],
    *,
    source_paths: Iterable[Path | None] | None = None,
) -> dict[str, Any]:
    """Merge normalized documents through the default service."""
    return _DEFAULT_SERVICE.merge_normalized_documents(
        documents,
        source_paths=source_paths,
    )


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


def build_draft_bundle(
    *,
    description: str,
    seed_input_path: Path,
    output_dir: Path,
    language: str,
    family: str,
    profile: str = "generic",
    normalized_format: str = "json",
    validation_format: str = "json",
    provenance_source: str = "ai-adapted",
    snapshot_version: str = "draft-v1",
    legacy_format: str | None = None,
    rule_id: str | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    """Build one natural-language draft bundle through the default service."""
    request = RuleWorkbenchDraftRequest(
        description=description,
        seed_input_path=seed_input_path,
        output_dir=output_dir,
        language=language,
        family=family,
        profile=profile,
        normalized_format=normalized_format,
        validation_format=validation_format,
        provenance_source=provenance_source,
        snapshot_version=snapshot_version,
        legacy_format=legacy_format,
        rule_id=rule_id,
        title=title,
    )
    return _DEFAULT_SERVICE.build_draft_bundle(request).to_mapping()

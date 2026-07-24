"""Import a reviewable Semgrep taint-rule subset into the Aegis normalized schema.

This script intentionally supports a narrow V1 subset:

- Semgrep documents with a top-level ``rules`` list
- ``mode: taint`` rules only
- Python/JavaScript/Java/PHP language filters
- direct ``pattern`` / ``pattern-regex`` entries plus nested
  ``pattern-either`` / ``patterns`` groups

The output is meant for human review and benchmarking, not direct production use.

Examples:
  python scripts/import_semgrep_subset.py refs/semgrep/python-taint.yaml ^
      --language python --family COMMAND_INJECTION ^
      --output refs/normalized/python-command-seed.json --format json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover - depends on runtime extras
    yaml = None


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


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Import a small Semgrep taint-rule subset into the Aegis normalized schema.",
    )
    parser.add_argument("input_path", type=Path, help="Path to a Semgrep YAML or JSON rule file")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Where to write the normalized rule-set document",
    )
    parser.add_argument(
        "--language",
        choices=sorted(SUPPORTED_LANGUAGES),
        help="Optional language filter for multi-language input files",
    )
    parser.add_argument(
        "--family",
        help="Optional vulnerability family override such as COMMAND_INJECTION",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional maximum number of normalized rules to emit",
    )
    parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="Output format for the normalized rule-set document",
    )
    parser.add_argument(
        "--provenance-source",
        default="semgrep",
        help="Logical provenance source label recorded in normalized rules",
    )
    parser.add_argument(
        "--snapshot-version",
        default="manual-seed-v1",
        help="Version label stored inside provenance metadata",
    )
    return parser


def load_semgrep_document(path: Path) -> dict[str, Any]:
    """Load a Semgrep rule document from YAML or JSON."""
    suffix = path.suffix.lower()
    raw_text = path.read_text(encoding="utf-8")

    if suffix == ".json":
        return json.loads(raw_text)

    if suffix not in {".yaml", ".yml"}:
        raise ValueError(f"Unsupported input format: {suffix}")

    if yaml is None:
        raise RuntimeError("PyYAML is required to load Semgrep YAML files.")

    data = yaml.safe_load(raw_text) or {}
    if not isinstance(data, dict):
        raise ValueError("Expected a Semgrep rule document with a top-level mapping.")
    return data


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
    """Normalize a Semgrep document into the Aegis rule-set schema."""
    raw_rules = document.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError("Expected the Semgrep document to contain a top-level 'rules' list.")

    normalized_rules = []
    skipped_rules = []

    for rule in raw_rules:
        normalized_rule, skip_reason = normalize_semgrep_rule(
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
        "generated_by": "scripts/import_semgrep_subset.py",
        "source_path": str(source_path) if source_path else None,
        "rule_count": len(normalized_rules),
        "rules": normalized_rules,
        "skipped_rules": skipped_rules,
    }


def normalize_semgrep_rule(
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

    severity = _map_severity(rule.get("severity"))
    cwe_ids = _extract_cwe_ids(metadata)
    owasp_refs = _extract_owasp_refs(metadata)

    normalized_rule = {
        "rule_id": rule.get("id", "<missing-id>"),
        "title": rule.get("message", rule.get("id", "Imported Semgrep seed rule")),
        "language": normalized_language,
        "family": family,
        "severity": severity,
        "taxonomy": {
            "cwe": cwe_ids,
            "owasp": owasp_refs,
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
            "importer": "scripts/import_semgrep_subset.py",
            "snapshot_version": snapshot_version,
        },
        "notes": notes,
    }
    return normalized_rule, None


def write_normalized_document(document: dict[str, Any], output_path: Path, format_name: str) -> None:
    """Write the normalized rule-set document in JSON or YAML."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        if format_name == "json":
            json.dump(document, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            return

        if yaml is None:
            raise RuntimeError("PyYAML is required to write YAML output.")
        yaml.safe_dump(document, handle, sort_keys=False, allow_unicode=False)


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
                    "exact": bool(item.get("exact", False)),
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


def main(argv: list[str] | None = None) -> int:
    """Run the Semgrep subset importer."""
    args = build_parser().parse_args(argv)

    document = load_semgrep_document(args.input_path)
    normalized = normalize_semgrep_document(
        document,
        language_filter=args.language,
        family_override=args.family,
        limit=args.limit,
        provenance_source=args.provenance_source,
        snapshot_version=args.snapshot_version,
        source_path=args.input_path,
    )
    write_normalized_document(normalized, args.output, args.format)

    print(
        "Imported "
        f"{normalized['rule_count']} normalized rules "
        f"({len(normalized['skipped_rules'])} skipped) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

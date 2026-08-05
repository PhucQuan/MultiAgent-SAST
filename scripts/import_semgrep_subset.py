"""Import a reviewable Semgrep taint-rule subset into the Aegis normalized schema."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.rule_workbench.service import (
    SUPPORTED_LANGUAGES,
    load_semgrep_document,
    normalize_semgrep_document,
    write_normalized_document,
)

SUPPORTED_DOCUMENT_SUFFIXES = {".json", ".yaml", ".yml"}


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Import a reviewable Semgrep taint-rule subset into the Aegis normalized schema "
            "from one file or a directory tree."
        ),
    )
    parser.add_argument(
        "input_path",
        type=Path,
        help="Path to a Semgrep YAML/JSON rule file or a directory that contains Semgrep rule documents",
    )
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


def discover_input_documents(input_path: Path) -> list[Path]:
    """Resolve one file or a directory tree into supported Semgrep documents."""
    if not input_path.exists():
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    if input_path.is_file():
        if input_path.suffix.lower() not in SUPPORTED_DOCUMENT_SUFFIXES:
            raise ValueError(
                f"Unsupported input format for {input_path}. "
                f"Expected one of: {', '.join(sorted(SUPPORTED_DOCUMENT_SUFFIXES))}"
            )
        return [input_path]

    if not input_path.is_dir():
        raise ValueError(f"Input path must be a file or directory: {input_path}")

    documents = sorted(
        path
        for path in input_path.rglob("*")
        if path.is_file() and path.suffix.lower() in SUPPORTED_DOCUMENT_SUFFIXES
    )
    if not documents:
        raise ValueError(
            f"No Semgrep YAML/JSON documents were found under directory: {input_path}"
        )
    return documents


def import_semgrep_documents(
    document_paths: list[Path],
    *,
    source_root: Path,
    language_filter: str | None = None,
    family_override: str | None = None,
    limit: int | None = None,
    provenance_source: str = "semgrep",
    snapshot_version: str = "manual-seed-v1",
) -> dict[str, Any]:
    """Normalize one or more Semgrep documents into a single Aegis rule-set artifact."""
    normalized_rules: list[dict[str, Any]] = []
    skipped_rules: list[dict[str, Any]] = []
    source_documents: list[str] = []

    for document_path in document_paths:
        remaining = None if limit is None else limit - len(normalized_rules)
        if remaining is not None and remaining <= 0:
            break

        document = load_semgrep_document(document_path)
        normalized = normalize_semgrep_document(
            document,
            language_filter=language_filter,
            family_override=family_override,
            limit=remaining,
            provenance_source=provenance_source,
            snapshot_version=snapshot_version,
            source_path=document_path,
        )
        normalized_rules.extend(normalized.get("rules", []))
        skipped_rules.extend(normalized.get("skipped_rules", []))
        source_documents.append(str(document_path))

    return {
        "schema_version": "aegis-normalized-rule-set-v1",
        "generated_by": "scripts/import_semgrep_subset.py",
        "source_path": str(source_root),
        "source_document_count": len(source_documents),
        "source_documents": source_documents,
        "rule_count": len(normalized_rules),
        "rules": normalized_rules,
        "skipped_rules": skipped_rules,
    }


def main(argv: list[str] | None = None) -> int:
    """Run the Semgrep subset importer."""
    args = build_parser().parse_args(argv)

    document_paths = discover_input_documents(args.input_path)
    normalized = import_semgrep_documents(
        document_paths,
        source_root=args.input_path,
        language_filter=args.language,
        family_override=args.family,
        limit=args.limit,
        provenance_source=args.provenance_source,
        snapshot_version=args.snapshot_version,
    )
    write_normalized_document(normalized, args.output, args.format)

    print(
        "Imported "
        f"{normalized['rule_count']} normalized rules "
        f"from {normalized['source_document_count']} document(s) "
        f"({len(normalized['skipped_rules'])} skipped) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

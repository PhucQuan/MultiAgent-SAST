"""Import a reviewable Semgrep taint-rule subset into the Aegis normalized schema."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.rule_workbench.service import (
    SUPPORTED_LANGUAGES,
    load_semgrep_document,
    normalize_semgrep_document,
    normalize_semgrep_rule,
    write_normalized_document,
)


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

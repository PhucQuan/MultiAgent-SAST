"""Validate Aegis normalized rule documents for review and workbench flows."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.rule_workbench.service import (
    SUPPORTED_PROFILES,
    format_validation_report,
    load_rule_document,
    validate_normalized_document,
    write_validation_report,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Validate Aegis normalized rule documents before review or ingestion.",
    )
    parser.add_argument("input_path", type=Path, help="Path to a normalized rule JSON/YAML file")
    parser.add_argument(
        "--profile",
        choices=sorted(SUPPORTED_PROFILES),
        default="generic",
        help="Validation profile. Use python-rule-workbench-v1 for the current V1 scope.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Validation report format.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the validation report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI validator."""
    args = build_parser().parse_args(argv)
    document = load_rule_document(args.input_path)
    report = validate_normalized_document(document, profile=args.profile)
    write_validation_report(report, format_name=args.format, output_path=args.output)
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

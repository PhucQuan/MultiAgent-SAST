"""Export reviewed normalized rules into the legacy custom-rules format."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.rule_workbench.service import (
    export_legacy_rules,
    load_normalized_document,
    merge_normalized_documents,
    write_legacy_document,
    write_report,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Export reviewed normalized rules into the legacy custom-rules format.",
    )
    parser.add_argument(
        "input_path",
        type=Path,
        nargs="+",
        help="One or more normalized rule JSON/YAML files",
    )
    parser.add_argument("--output", type=Path, required=True, help="Legacy rule output path")
    parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="yaml",
        help="Legacy rule output format.",
    )
    parser.add_argument(
        "--language",
        help="Optional language filter when exporting a rule-set document.",
    )
    parser.add_argument(
        "--family",
        help="Optional family filter when exporting a rule-set document.",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        help="Optional JSON report path describing exported/skipped rules and patterns.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI bridge."""
    args = build_parser().parse_args(argv)
    normalized_documents = [load_normalized_document(path) for path in args.input_path]
    document = (
        merge_normalized_documents(normalized_documents, source_paths=args.input_path)
        if len(normalized_documents) > 1
        else normalized_documents[0]
    )
    legacy_document, report = export_legacy_rules(
        document,
        language_filter=args.language,
        family_filter=args.family,
    )
    write_legacy_document(legacy_document, args.output, args.format)
    if args.report_output:
        write_report(report, args.report_output)

    print(
        "Exported legacy rules "
        f"(sources={report['exported_sources']}, "
        f"sinks={report['exported_sinks']}, "
        f"sanitizers={report['exported_sanitizers']}, "
        f"inputs={len(args.input_path)}) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

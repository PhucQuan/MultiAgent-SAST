"""Build a repeatable rule-review bundle from one Semgrep-shaped seed file."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.rule_workbench.service import build_review_bundle


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Run importer + validator (+ optional legacy bridge) in one repeatable command.",
    )
    parser.add_argument("input_path", type=Path, help="Semgrep-shaped YAML/JSON seed file")
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to write bundle artifacts into",
    )
    parser.add_argument(
        "--language",
        help="Optional language filter for multi-language seed documents",
    )
    parser.add_argument(
        "--family",
        help="Optional family override such as COMMAND_INJECTION",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional max number of normalized rules to emit",
    )
    parser.add_argument(
        "--normalized-format",
        choices=["json", "yaml"],
        default="json",
        help="Output format for the normalized rule bundle",
    )
    parser.add_argument(
        "--validation-format",
        choices=["text", "json"],
        default="json",
        help="Output format for the validation report",
    )
    parser.add_argument(
        "--profile",
        default="generic",
        help="Validation profile such as python-rule-workbench-v1",
    )
    parser.add_argument(
        "--provenance-source",
        default="semgrep",
        help="Logical provenance source recorded in normalized rules",
    )
    parser.add_argument(
        "--snapshot-version",
        default="manual-seed-v1",
        help="Snapshot label recorded in provenance metadata",
    )
    parser.add_argument(
        "--legacy-format",
        choices=["json", "yaml"],
        help="Optional output format for a legacy custom-rules bridge document",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI bundle builder."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = build_review_bundle(
            input_path=args.input_path,
            output_dir=args.output_dir,
            language=args.language,
            family=args.family,
            limit=args.limit,
            normalized_format=args.normalized_format,
            validation_format=args.validation_format,
            profile=args.profile,
            provenance_source=args.provenance_source,
            snapshot_version=args.snapshot_version,
            legacy_format=args.legacy_format,
        )
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except RuntimeError as exc:
        print(f"[error] {exc}")
        print("Run `python scripts/doctor_env.py` and install requirements.txt first.")
        return 1

    print(f"Normalized rules -> {result['normalized_path']}")
    print(f"Validation report -> {result['validation_path']}")
    if result["legacy_path"]:
        print(f"Legacy rules -> {result['legacy_path']}")
        print(f"Legacy export report -> {result['legacy_report_path']}")
    print(
        "Bundle summary: "
        f"rules={result['rules_checked']}, "
        f"errors={result['error_count']}, "
        f"warnings={result['warning_count']}"
    )
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

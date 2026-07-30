"""Compare default rules against one reviewed bundle on a small target.

Examples:
  python scripts/compare_reviewed_bundle_scan.py examples/vulnerable_rce.py --reviewed-rules reports/rule_review/command_injection_seed/python_command_injection_semgrep_shape.legacy.yaml
  python scripts/compare_reviewed_bundle_scan.py examples/vulnerable_rce.py --reviewed-rules reports/rule_review/command_injection_seed/python_command_injection_semgrep_shape.legacy.yaml --format json --format markdown
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from analyze_scan_report import (  # noqa: E402
    compare_summaries,
    find_source_pattern_mismatches,
    load_report,
    summarize_report,
)
from scan_target import run_manual_scan  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Run default and reviewed-bundle scans side by side on one target.",
    )
    parser.add_argument("target", type=Path, help="File or directory to scan")
    parser.add_argument(
        "--reviewed-rules",
        type=Path,
        required=True,
        help="Legacy bridge YAML/JSON rules file exported from a reviewed bundle",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Root directory for the paired scan outputs and comparison summary",
    )
    parser.add_argument(
        "--format",
        action="append",
        choices=["json", "markdown", "sarif"],
        default=[],
        help="Repeatable report format selector. JSON is always included for analysis.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum analysis depth for detector-level taint tracking.",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Repeatable directory-name exclusion such as tests or build.",
    )
    parser.add_argument(
        "--exclude-glob",
        action="append",
        default=[],
        help="Repeatable relative-path glob exclusion such as *.min.js.",
    )
    parser.add_argument(
        "--exclude-profile",
        action="append",
        choices=["baseline", "focus"],
        default=[],
        help="Repeatable exclusion preset reused from scripts/scan_target.py.",
    )
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Disable the automatic baseline exclusion profile for directory scans.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Print scan progress every N processed files when the target is a directory.",
    )
    parser.add_argument(
        "--mismatch-limit",
        type=int,
        default=10,
        help="Maximum number of heuristic source-pattern mismatches to keep in the summary.",
    )
    return parser


def default_output_dir(target: Path) -> Path:
    """Build a stable output directory for one side-by-side comparison run."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = target.resolve().name if target.exists() else target.name
    safe_name = safe_name.replace(" ", "_")
    return REPO_ROOT / "reports" / "rule_review_smoke" / f"{safe_name}_{timestamp}"


def ensure_report_formats(formats: list[str]) -> list[str]:
    """Guarantee JSON output so the comparison helper can load reports."""
    ordered = []
    for format_name in ["json", *formats]:
        if format_name not in ordered:
            ordered.append(format_name)
    return ordered


def select_report_path(paths: list[Path], suffix: str) -> Path:
    """Return the report with the requested suffix or raise a helpful error."""
    for path in paths:
        if path.suffix.lower() == suffix.lower():
            return path
    raise FileNotFoundError(f"Could not find a {suffix} report in the written artifacts.")


def build_comparison_summary(
    *,
    target: Path,
    reviewed_rules: Path,
    output_dir: Path,
    default_report_path: Path,
    reviewed_report_path: Path,
    mismatch_limit: int,
) -> dict[str, Any]:
    """Build a JSON-friendly summary for one side-by-side comparison run."""
    default_report = load_report(default_report_path)
    reviewed_report = load_report(reviewed_report_path)

    default_summary = summarize_report(default_report, default_report_path)
    reviewed_summary = summarize_report(reviewed_report, reviewed_report_path)
    comparison = compare_summaries(default_summary, reviewed_summary)

    default_mismatches = find_source_pattern_mismatches(default_report, limit=mismatch_limit)
    reviewed_mismatches = find_source_pattern_mismatches(reviewed_report, limit=mismatch_limit)

    return {
        "target": str(target),
        "reviewed_rules": str(reviewed_rules),
        "output_dir": str(output_dir),
        "artifacts": {
            "default_report": str(default_report_path),
            "reviewed_report": str(reviewed_report_path),
        },
        "default": _summary_payload(default_summary, default_mismatches),
        "reviewed": _summary_payload(reviewed_summary, reviewed_mismatches),
        "comparison": {
            "finding_delta": comparison["finding_delta"],
            "unique_delta": comparison["unique_delta"],
            "old_total": comparison["old_total"],
            "new_total": comparison["new_total"],
            "old_unique": comparison["old_unique"],
            "new_unique": comparison["new_unique"],
            "old_coverage": comparison["old_coverage"],
            "new_coverage": comparison["new_coverage"],
            "coverage_delta": comparison["coverage_delta"],
            "removed_keys": [_stringify_key(key) for key in sorted(comparison["removed_keys"])],
            "added_keys": [_stringify_key(key) for key in sorted(comparison["added_keys"])],
            "removed_coverage_keys": [
                _stringify_coverage_key(key)
                for key in sorted(comparison["removed_coverage_keys"])
            ],
            "added_coverage_keys": [
                _stringify_coverage_key(key)
                for key in sorted(comparison["added_coverage_keys"])
            ],
            "by_type_delta": dict(comparison["by_type_delta"]),
            "by_sink_pattern_delta": dict(comparison["by_sink_pattern_delta"]),
        },
    }


def write_summary(summary: dict[str, Any], output_path: Path) -> None:
    """Write the comparison summary as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def print_summary(summary: dict[str, Any], output_path: Path) -> None:
    """Render a concise terminal summary for manual runs."""
    default_summary = summary["default"]
    reviewed_summary = summary["reviewed"]
    comparison = summary["comparison"]

    print("Reviewed Bundle Comparison:")
    print(f"  - target: {summary['target']}")
    print(f"  - reviewed rules: {summary['reviewed_rules']}")
    print(f"  - default findings: {default_summary['total_findings']}")
    print(f"  - reviewed findings: {reviewed_summary['total_findings']}")
    print(
        "  - unique sink keys: "
        f"{comparison['old_unique']} -> {comparison['new_unique']} "
        f"(delta {comparison['unique_delta']:+d})"
    )
    print(
        "  - coverage-equivalent keys: "
        f"{comparison['old_coverage']} -> {comparison['new_coverage']} "
        f"(delta {comparison['coverage_delta']:+d})"
    )
    print(
        "  - mismatch counts: "
        f"default={default_summary['mismatch_count']}, "
        f"reviewed={reviewed_summary['mismatch_count']}"
    )
    print(f"  - summary json: {output_path}")


def _summary_payload(summary: dict[str, Any], mismatches: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert one Counter-heavy report summary into JSON-friendly data."""
    return {
        "report_path": summary["path"],
        "target": summary.get("target"),
        "files_scanned": summary["files_scanned"],
        "total_findings": summary["total_findings"],
        "duplicate_delta": summary["duplicate_delta"],
        "duplicate_groups": [
            {
                "key": _stringify_key(item["key"]),
                "count": item["count"],
            }
            for item in summary["duplicate_groups"]
        ],
        "by_type": dict(summary["by_type"]),
        "by_severity": dict(summary["by_severity"]),
        "by_triage": dict(summary["by_triage"]),
        "by_source_pattern": dict(summary["by_source_pattern"]),
        "by_sink_pattern": dict(summary["by_sink_pattern"]),
        "by_sink_function": dict(summary["by_sink_function"]),
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }


def _stringify_key(key: tuple[Any, ...]) -> str:
    """Render one dedupe key in a readable single-line format."""
    file_path, line, column, vuln_type, sink_function, sink_pattern = key
    return (
        f"{vuln_type}|{sink_function or 'unknown'}|"
        f"{file_path}:{line}:{column}|{sink_pattern or 'unknown'}"
    )


def _stringify_coverage_key(key: tuple[Any, ...]) -> str:
    """Render one pattern-agnostic coverage key in a readable single-line format."""
    file_path, line, column, vuln_type, sink_identity = key
    return (
        f"{vuln_type}|{sink_identity or 'unknown'}|"
        f"{file_path}:{line}:{column}"
    )


def main(argv: list[str] | None = None) -> int:
    """Run one paired default-versus-reviewed scan."""
    parser = build_parser()
    args = parser.parse_args(argv)
    target = args.target.resolve()
    reviewed_rules = args.reviewed_rules.resolve()

    if not target.exists():
        raise SystemExit(f"Target does not exist: {target}")
    if not reviewed_rules.exists():
        raise SystemExit(f"Reviewed rules file does not exist: {reviewed_rules}")

    output_dir = (args.output_dir or default_output_dir(target)).resolve()
    formats = ensure_report_formats(args.format or ["markdown"])
    default_scan_dir = output_dir / "default_scan"
    reviewed_scan_dir = output_dir / "reviewed_scan"

    common_kwargs = {
        "target": target,
        "formats": formats,
        "max_depth": args.max_depth,
        "with_ai": False,
        "exclude_dirs": args.exclude_dir,
        "exclude_globs": args.exclude_glob,
        "exclude_profiles": args.exclude_profile,
        "no_default_excludes": args.no_default_excludes,
        "progress_every": args.progress_every,
        "emit_console": False,
    }

    try:
        print("Running default scan...")
        default_result = run_manual_scan(
            custom_rules_path=None,
            output_dir=default_scan_dir,
            **common_kwargs,
        )

        print("Running reviewed bundle overlay scan...")
        reviewed_result = run_manual_scan(
            custom_rules_path=None,
            append_rules_paths=[reviewed_rules],
            output_dir=reviewed_scan_dir,
            **common_kwargs,
        )
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except RuntimeError as exc:
        print(f"[error] {exc}")
        print("Run `python scripts/doctor_env.py` and install requirements.txt first.")
        return 1

    default_report_path = select_report_path(default_result["written_reports"], ".json")
    reviewed_report_path = select_report_path(reviewed_result["written_reports"], ".json")
    summary = build_comparison_summary(
        target=target,
        reviewed_rules=reviewed_rules,
        output_dir=output_dir,
        default_report_path=default_report_path,
        reviewed_report_path=reviewed_report_path,
        mismatch_limit=args.mismatch_limit,
    )

    summary_path = output_dir / "comparison_summary.json"
    write_summary(summary, summary_path)
    print_summary(summary, summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

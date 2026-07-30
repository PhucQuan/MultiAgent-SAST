"""Run the reviewed-bundle mini benchmark for the Python reviewed-bundle suite.

Examples:
  python scripts/run_benchmark_v1.py
  python scripts/run_benchmark_v1.py --case python-path-traversal
  python scripts/run_benchmark_v1.py --manifest datasets/benchmark/reviewed_bundle_v1/cases_sql_injection_extension.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from compare_reviewed_bundle_scan import (  # noqa: E402
    build_comparison_summary,
    ensure_report_formats,
    select_report_path,
    write_summary,
)
from scan_target import run_manual_scan  # noqa: E402


DEFAULT_MANIFEST = (
    REPO_ROOT / "datasets" / "benchmark" / "reviewed_bundle_v1" / "cases.json"
)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Run the reviewed-bundle mini benchmark across the default Python V1 "
            "families or a custom reviewed-bundle manifest."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Path to the reviewed-bundle benchmark manifest.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Root directory for benchmark artifacts. Defaults to reports/benchmark/reviewed_bundle_v1/<timestamp>.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Optional repeatable case_id filter.",
    )
    parser.add_argument(
        "--format",
        action="append",
        choices=["json", "markdown", "sarif"],
        default=[],
        help="Repeatable report format selector for underlying scans. JSON is always included.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum analysis depth for detector-level taint tracking.",
    )
    parser.add_argument(
        "--mismatch-limit",
        type=int,
        default=10,
        help="Maximum number of heuristic source-pattern mismatches kept per case summary.",
    )
    return parser


def default_output_dir() -> Path:
    """Build a stable output directory for one benchmark run."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return REPO_ROOT / "reports" / "benchmark" / "reviewed_bundle_v1" / timestamp


def load_manifest(path: Path) -> dict[str, Any]:
    """Load the benchmark manifest as JSON."""
    if not path.exists():
        raise FileNotFoundError(f"Benchmark manifest does not exist: {path}")

    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "aegis-reviewed-bundle-benchmark-v1":
        raise ValueError(
            "Expected schema_version 'aegis-reviewed-bundle-benchmark-v1' in the manifest."
        )
    if not isinstance(payload.get("cases"), list):
        raise ValueError("Benchmark manifest must contain a top-level 'cases' list.")
    return payload


def resolve_manifest_cases(
    manifest: dict[str, Any],
    *,
    selected_case_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Resolve relative manifest paths and optionally filter cases."""
    selected = {case_id.strip() for case_id in (selected_case_ids or []) if case_id.strip()}
    resolved_cases: list[dict[str, Any]] = []

    for item in manifest.get("cases", []):
        if not isinstance(item, dict):
            raise ValueError("Each benchmark case must be a mapping.")

        case_id = item.get("case_id")
        family = item.get("family")
        target = item.get("target")
        reviewed_rules = item.get("reviewed_rules")

        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("Each benchmark case must define a non-empty string case_id.")
        if selected and case_id not in selected:
            continue
        if not isinstance(family, str) or not family.strip():
            raise ValueError(f"Benchmark case {case_id!r} is missing a valid family.")
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"Benchmark case {case_id!r} is missing a valid target.")
        if not isinstance(reviewed_rules, str) or not reviewed_rules.strip():
            raise ValueError(f"Benchmark case {case_id!r} is missing reviewed_rules.")

        resolved_cases.append(
            {
                "case_id": case_id,
                "family": family,
                "target": (REPO_ROOT / target).resolve(),
                "reviewed_rules": (REPO_ROOT / reviewed_rules).resolve(),
                "goal": item.get("goal", ""),
            }
        )

    if selected and not resolved_cases:
        raise ValueError("No benchmark cases matched the requested --case filters.")

    return resolved_cases


def run_benchmark_case(
    *,
    case: dict[str, Any],
    output_root: Path,
    formats: list[str],
    max_depth: int,
    mismatch_limit: int,
) -> dict[str, Any]:
    """Run default-vs-reviewed scans for one manifest case."""
    target = case["target"]
    reviewed_rules = case["reviewed_rules"]

    if not target.exists():
        raise FileNotFoundError(f"Benchmark target does not exist: {target}")
    if not reviewed_rules.exists():
        raise FileNotFoundError(
            f"Reviewed rules file does not exist for case {case['case_id']}: {reviewed_rules}"
        )

    case_output_dir = output_root / case["case_id"]
    default_scan_dir = case_output_dir / "default_scan"
    reviewed_scan_dir = case_output_dir / "reviewed_scan"

    common_kwargs = {
        "target": target,
        "formats": formats,
        "max_depth": max_depth,
        "with_ai": False,
        "emit_console": False,
    }

    print(f"[case] {case['case_id']}: default scan...")
    default_result = run_manual_scan(
        custom_rules_path=None,
        output_dir=default_scan_dir,
        **common_kwargs,
    )

    print(f"[case] {case['case_id']}: reviewed bundle overlay scan...")
    reviewed_result = run_manual_scan(
        custom_rules_path=None,
        append_rules_paths=[reviewed_rules],
        output_dir=reviewed_scan_dir,
        **common_kwargs,
    )

    default_report_path = select_report_path(default_result["written_reports"], ".json")
    reviewed_report_path = select_report_path(reviewed_result["written_reports"], ".json")
    summary = build_comparison_summary(
        target=target,
        reviewed_rules=reviewed_rules,
        output_dir=case_output_dir,
        default_report_path=default_report_path,
        reviewed_report_path=reviewed_report_path,
        mismatch_limit=mismatch_limit,
    )

    summary_path = case_output_dir / "comparison_summary.json"
    write_summary(summary, summary_path)

    return {
        "case_id": case["case_id"],
        "family": case["family"],
        "goal": case.get("goal", ""),
        "target": str(target),
        "reviewed_rules": str(reviewed_rules),
        "comparison_summary_path": str(summary_path),
        "default_findings": summary["default"]["total_findings"],
        "reviewed_findings": summary["reviewed"]["total_findings"],
        "finding_delta": summary["comparison"]["finding_delta"],
        "unique_delta": summary["comparison"]["unique_delta"],
        "coverage_delta": summary["comparison"]["coverage_delta"],
        "default_mismatches": summary["default"]["mismatch_count"],
        "reviewed_mismatches": summary["reviewed"]["mismatch_count"],
        "default_by_sink_pattern": summary["default"]["by_sink_pattern"],
        "reviewed_by_sink_pattern": summary["reviewed"]["by_sink_pattern"],
        "added_keys": summary["comparison"]["added_keys"],
        "removed_keys": summary["comparison"]["removed_keys"],
        "added_coverage_keys": summary["comparison"]["added_coverage_keys"],
        "removed_coverage_keys": summary["comparison"]["removed_coverage_keys"],
    }


def aggregate_case_results(
    case_results: list[dict[str, Any]],
    *,
    manifest_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Aggregate per-case benchmark results into one JSON-friendly payload."""
    default_findings = sum(item["default_findings"] for item in case_results)
    reviewed_findings = sum(item["reviewed_findings"] for item in case_results)
    finding_delta = reviewed_findings - default_findings
    unique_delta = sum(item["unique_delta"] for item in case_results)
    coverage_delta = sum(item["coverage_delta"] for item in case_results)
    mismatch_delta = sum(
        item["reviewed_mismatches"] - item["default_mismatches"] for item in case_results
    )

    by_family_default = Counter()
    by_family_reviewed = Counter()
    by_case_delta = {}
    by_case_unique_delta = {}
    by_case_coverage_delta = {}

    for item in case_results:
        by_family_default[item["family"]] += item["default_findings"]
        by_family_reviewed[item["family"]] += item["reviewed_findings"]
        by_case_delta[item["case_id"]] = item["finding_delta"]
        by_case_unique_delta[item["case_id"]] = item["unique_delta"]
        by_case_coverage_delta[item["case_id"]] = item["coverage_delta"]

    return {
        "schema_version": "aegis-reviewed-bundle-benchmark-result-v1",
        "manifest_path": str(manifest_path),
        "output_dir": str(output_dir),
        "generated_at": datetime.now().isoformat(),
        "case_count": len(case_results),
        "cases": case_results,
        "aggregate": {
            "default_findings": default_findings,
            "reviewed_findings": reviewed_findings,
            "finding_delta": finding_delta,
            "unique_delta": unique_delta,
            "coverage_delta": coverage_delta,
            "mismatch_delta": mismatch_delta,
            "by_family_default": dict(by_family_default),
            "by_family_reviewed": dict(by_family_reviewed),
            "by_case_delta": by_case_delta,
            "by_case_unique_delta": by_case_unique_delta,
            "by_case_coverage_delta": by_case_coverage_delta,
        },
    }


def render_markdown(summary: dict[str, Any]) -> str:
    """Render a lightweight Markdown report for the benchmark run."""
    aggregate = summary["aggregate"]
    lines = [
        "# Reviewed Bundle Benchmark V1",
        "",
        f"- Manifest: `{summary['manifest_path']}`",
        f"- Output dir: `{summary['output_dir']}`",
        f"- Generated at: `{summary['generated_at']}`",
        "",
        "## Aggregate",
        "",
        "| Metric | Default | Reviewed | Delta |",
        "|---|---:|---:|---:|",
        f"| Findings | {aggregate['default_findings']} | {aggregate['reviewed_findings']} | {aggregate['finding_delta']:+d} |",
        f"| Unique sink keys | - | - | {aggregate['unique_delta']:+d} |",
        f"| Coverage-equivalent keys | - | - | {aggregate['coverage_delta']:+d} |",
        f"| Source-pattern mismatches | - | - | {aggregate['mismatch_delta']:+d} |",
        "",
        "## Cases",
        "",
        "| Case | Family | Default | Reviewed | Delta | Unique Delta | Coverage Delta |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]

    for item in summary["cases"]:
        lines.append(
            f"| `{item['case_id']}` | `{item['family']}` | "
            f"{item['default_findings']} | {item['reviewed_findings']} | "
            f"{item['finding_delta']:+d} | {item['unique_delta']:+d} | "
            f"{item['coverage_delta']:+d} |"
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
        ]
    )

    for item in summary["cases"]:
        lines.append(f"### `{item['case_id']}`")
        if item.get("goal"):
            lines.append(f"- Goal: {item['goal']}")
        lines.append(f"- Target: `{item['target']}`")
        lines.append(f"- Reviewed rules: `{item['reviewed_rules']}`")
        lines.append(f"- Comparison summary: `{item['comparison_summary_path']}`")
        if item["added_keys"]:
            lines.append("- Added keys:")
            for key in item["added_keys"]:
                lines.append(f"  - `{key}`")
        if item["removed_keys"]:
            lines.append("- Removed keys:")
            for key in item["removed_keys"]:
                lines.append(f"  - `{key}`")
        if item["added_coverage_keys"]:
            lines.append("- Added coverage-equivalent keys:")
            for key in item["added_coverage_keys"]:
                lines.append(f"  - `{key}`")
        if item["removed_coverage_keys"]:
            lines.append("- Removed coverage-equivalent keys:")
            for key in item["removed_coverage_keys"]:
                lines.append(f"  - `{key}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_benchmark_outputs(summary: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write JSON and Markdown outputs for one benchmark run."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "benchmark_summary.json"
    markdown_path = output_dir / "benchmark_summary.md"

    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    return json_path, markdown_path


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark over all selected manifest cases."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest.resolve())
        cases = resolve_manifest_cases(manifest, selected_case_ids=args.case)
        output_dir = (args.output_dir or default_output_dir()).resolve()
        formats = ensure_report_formats(args.format or ["markdown"])

        case_results = []
        for case in cases:
            case_results.append(
                run_benchmark_case(
                    case=case,
                    output_root=output_dir,
                    formats=formats,
                    max_depth=args.max_depth,
                    mismatch_limit=args.mismatch_limit,
                )
            )

        summary = aggregate_case_results(
            case_results,
            manifest_path=args.manifest.resolve(),
            output_dir=output_dir,
        )
        json_path, markdown_path = write_benchmark_outputs(summary, output_dir)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except RuntimeError as exc:
        print(f"[error] {exc}")
        print("Run `python scripts/doctor_env.py` and install requirements.txt first.")
        return 1
    except ValueError as exc:
        parser.error(str(exc))

    aggregate = summary["aggregate"]
    print("Reviewed Bundle Benchmark V1:")
    print(f"  - cases: {summary['case_count']}")
    print(
        "  - findings: "
        f"{aggregate['default_findings']} -> {aggregate['reviewed_findings']} "
        f"(delta {aggregate['finding_delta']:+d})"
    )
    print(f"  - unique sink delta: {aggregate['unique_delta']:+d}")
    print(f"  - coverage-equivalent delta: {aggregate['coverage_delta']:+d}")
    print(f"  - mismatch delta: {aggregate['mismatch_delta']:+d}")
    print(f"  - json: {json_path}")
    print(f"  - markdown: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

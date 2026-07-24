"""Inspect one or two Aegis-SAST JSON reports for noise and regression review.

Examples:
  python scripts/analyze_scan_report.py reports/manual_targets/run/aegis_sast_report.json
  python scripts/analyze_scan_report.py old_report.json new_report.json
  python scripts/analyze_scan_report.py report.json --max-items 15 --show-mismatches
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Inspect one or two Aegis-SAST JSON reports.",
    )
    parser.add_argument(
        "reports",
        nargs="+",
        type=Path,
        help="One report for summary mode, or two reports for comparison mode.",
    )
    parser.add_argument(
        "--max-items",
        type=int,
        default=10,
        help="Maximum number of rows to print in each top-N section.",
    )
    parser.add_argument(
        "--show-mismatches",
        action="store_true",
        help=(
            "Print heuristic source-pattern mismatches where the source snippet "
            "does not visibly mention the source pattern."
        ),
    )
    return parser


def load_report(path: Path) -> dict[str, Any]:
    """Load one JSON report from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def detection_metadata(finding: dict[str, Any]) -> dict[str, Any]:
    """Return nested detection metadata when present."""
    metadata = finding.get("metadata", {})
    detection = metadata.get("detection", {})
    if isinstance(detection, dict):
        return detection
    return {}


def triage_status(finding: dict[str, Any]) -> str:
    """Return the finding triage status or a stable placeholder."""
    return finding.get("triage_status") or "unknown"


def sink_location(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the sink location payload from the evidence bundle."""
    return finding.get("evidence", {}).get("sink", {}) or {}


def source_location(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the source location payload from the evidence bundle."""
    return finding.get("evidence", {}).get("source", {}) or {}


def dedupe_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    """Build the same sink-oriented dedupe key used by the detector."""
    detection = detection_metadata(finding)
    sink = sink_location(finding)
    return (
        finding.get("file"),
        finding.get("line"),
        sink.get("column"),
        finding.get("type"),
        detection.get("sink_function"),
        detection.get("sink_pattern"),
    )


def summarize_report(report: dict[str, Any], report_path: Path) -> dict[str, Any]:
    """Extract the high-signal stats from one report."""
    findings = report.get("findings", [])
    by_type = Counter()
    by_severity = Counter()
    by_triage = Counter()
    by_source_pattern = Counter()
    by_sink_pattern = Counter()
    by_sink_function = Counter()
    duplicate_groups = Counter()

    for finding in findings:
        detection = detection_metadata(finding)
        by_type[finding.get("type") or "UNKNOWN"] += 1
        by_severity[finding.get("severity") or "UNKNOWN"] += 1
        by_triage[triage_status(finding)] += 1
        by_source_pattern[detection.get("source_pattern") or "UNKNOWN"] += 1
        by_sink_pattern[detection.get("sink_pattern") or "UNKNOWN"] += 1
        by_sink_function[detection.get("sink_function") or "UNKNOWN"] += 1
        duplicate_groups[dedupe_key(finding)] += 1

    duplicate_items = [
        {"key": key, "count": count}
        for key, count in duplicate_groups.most_common()
        if count > 1
    ]

    return {
        "path": str(report_path),
        "target": report.get("scan_metadata", {}).get("target"),
        "files_scanned": report.get("scan_metadata", {}).get("files_scanned", 0),
        "total_findings": len(findings),
        "by_type": by_type,
        "by_severity": by_severity,
        "by_triage": by_triage,
        "by_source_pattern": by_source_pattern,
        "by_sink_pattern": by_sink_pattern,
        "by_sink_function": by_sink_function,
        "duplicate_groups": duplicate_items,
        "duplicate_delta": len(findings) - len(duplicate_groups),
        "unique_finding_keys": set(duplicate_groups.keys()),
    }


def compare_summaries(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Compare two report summaries using deduped sink keys."""
    old_keys = old["unique_finding_keys"]
    new_keys = new["unique_finding_keys"]

    return {
        "old_total": old["total_findings"],
        "new_total": new["total_findings"],
        "finding_delta": new["total_findings"] - old["total_findings"],
        "old_unique": len(old_keys),
        "new_unique": len(new_keys),
        "unique_delta": len(new_keys) - len(old_keys),
        "removed_keys": old_keys - new_keys,
        "added_keys": new_keys - old_keys,
        "by_type_delta": _counter_delta(old["by_type"], new["by_type"]),
        "by_sink_pattern_delta": _counter_delta(
            old["by_sink_pattern"],
            new["by_sink_pattern"],
        ),
    }


def find_source_pattern_mismatches(
    report: dict[str, Any],
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return heuristic source-attribution mismatches for quick manual review."""
    mismatches = []
    for finding in report.get("findings", []):
        detection = detection_metadata(finding)
        source_pattern = detection.get("source_pattern") or ""
        if not source_pattern:
            continue

        source = source_location(finding)
        snippet = source.get("snippet") or ""
        if _snippet_mentions_pattern(snippet, source_pattern):
            continue

        mismatches.append(
            {
                "file": finding.get("file"),
                "line": finding.get("line"),
                "type": finding.get("type"),
                "source_line": source.get("line"),
                "source_pattern": source_pattern,
                "source_snippet": snippet,
            }
        )

    return mismatches[: max(limit, 0)]


def print_summary(summary: dict[str, Any], max_items: int) -> None:
    """Print one report summary."""
    print(f"Report: {summary['path']}")
    print(f"  - target: {summary.get('target') or 'unknown'}")
    print(f"  - files scanned: {summary['files_scanned']}")
    print(f"  - total findings: {summary['total_findings']}")
    print(
        "  - severity: "
        + _format_counter(
            summary["by_severity"],
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"],
        )
    )
    print(
        "  - triage: "
        + _format_counter(
            summary["by_triage"],
            ["confirmed", "likely", "needs-review", "suppressed", "unknown"],
        )
    )
    print(
        "  - duplicate delta: "
        f"{summary['duplicate_delta']} "
        f"({len(summary['duplicate_groups'])} duplicate groups)"
    )

    print_top_section("Top types", summary["by_type"], max_items)
    print_top_section("Top source patterns", summary["by_source_pattern"], max_items)
    print_top_section("Top sink patterns", summary["by_sink_pattern"], max_items)
    print_top_section("Top sink functions", summary["by_sink_function"], max_items)

    if summary["duplicate_groups"]:
        print("Top duplicate groups:")
        for item in summary["duplicate_groups"][:max_items]:
            file_path, line, column, vuln_type, sink_function, sink_pattern = item["key"]
            print(
                "  - "
                f"{item['count']}x | {vuln_type} | {sink_function or 'unknown'} | "
                f"{file_path}:{line}:{column} | pattern={sink_pattern or 'unknown'}"
            )


def print_comparison(
    old_summary: dict[str, Any],
    new_summary: dict[str, Any],
    comparison: dict[str, Any],
    max_items: int,
) -> None:
    """Print a side-by-side comparison for two reports."""
    print("Comparison:")
    print(f"  - old: {old_summary['path']}")
    print(f"  - new: {new_summary['path']}")
    print(
        "  - total findings: "
        f"{comparison['old_total']} -> {comparison['new_total']} "
        f"(delta {comparison['finding_delta']:+d})"
    )
    print(
        "  - unique finding keys: "
        f"{comparison['old_unique']} -> {comparison['new_unique']} "
        f"(delta {comparison['unique_delta']:+d})"
    )
    print(f"  - removed sink keys: {len(comparison['removed_keys'])}")
    print(f"  - added sink keys: {len(comparison['added_keys'])}")

    print_delta_section("Type deltas", comparison["by_type_delta"], max_items)
    print_delta_section(
        "Sink pattern deltas",
        comparison["by_sink_pattern_delta"],
        max_items,
    )


def print_mismatches(report: dict[str, Any], report_path: Path, max_items: int) -> None:
    """Print heuristic source-pattern mismatches."""
    mismatches = find_source_pattern_mismatches(report, limit=max_items)
    print(f"Heuristic source mismatches: {len(mismatches)} shown")
    for mismatch in mismatches:
        print(
            "  - "
            f"{mismatch['type']} | {mismatch['file']}:{mismatch['line']} "
            f"| source_pattern={mismatch['source_pattern']} "
            f"| source_line={mismatch['source_line']} "
            f"| snippet={mismatch['source_snippet']}"
        )


def print_top_section(title: str, counter: Counter, max_items: int) -> None:
    """Print one Top-N counter section."""
    print(f"{title}:")
    for key, count in counter.most_common(max_items):
        print(f"  - {key}: {count}")


def print_delta_section(title: str, delta: Counter, max_items: int) -> None:
    """Print one Top-N delta section, largest magnitude first."""
    print(f"{title}:")
    for key, count in sorted(
        delta.items(),
        key=lambda item: (-abs(item[1]), item[0]),
    )[:max_items]:
        print(f"  - {key}: {count:+d}")


def _counter_delta(old: Counter, new: Counter) -> Counter:
    """Return `new - old` while keeping zero-free keys only."""
    keys = set(old) | set(new)
    return Counter({key: new.get(key, 0) - old.get(key, 0) for key in keys if new.get(key, 0) != old.get(key, 0)})


def _format_counter(counter: Counter, ordered_keys: Iterable[str]) -> str:
    """Render selected counter keys in one compact line."""
    return ", ".join(f"{key}={counter.get(key, 0)}" for key in ordered_keys)


def _snippet_mentions_pattern(snippet: str, pattern: str) -> bool:
    """Check whether the source snippet visibly mentions the source pattern."""
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", pattern)
    snippet_lower = snippet.lower()
    signal_tokens = [
        token.lower()
        for token in tokens
        if len(token) >= 3 and token.lower() not in {"request"}
    ]
    if not signal_tokens:
        return True
    return any(token in snippet_lower for token in signal_tokens)


def main(argv: list[str] | None = None) -> int:
    """Run summary or comparison mode."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if len(args.reports) not in {1, 2}:
        parser.error("Provide exactly one or two JSON reports.")

    missing = [path for path in args.reports if not path.exists()]
    if missing:
        parser.error(f"Missing report(s): {', '.join(str(path) for path in missing)}")

    reports = [load_report(path) for path in args.reports]
    summaries = [
        summarize_report(report, path)
        for report, path in zip(reports, args.reports)
    ]

    if len(summaries) == 1:
        print_summary(summaries[0], args.max_items)
        if args.show_mismatches:
            print_mismatches(reports[0], args.reports[0], args.max_items)
        return 0

    print_summary(summaries[0], args.max_items)
    print()
    print_summary(summaries[1], args.max_items)
    print()
    print_comparison(
        summaries[0],
        summaries[1],
        compare_summaries(summaries[0], summaries[1]),
        args.max_items,
    )

    if args.show_mismatches:
        print()
        print(f"Mismatch review for old report: {args.reports[0]}")
        print_mismatches(reports[0], args.reports[0], args.max_items)
        print()
        print(f"Mismatch review for new report: {args.reports[1]}")
        print_mismatches(reports[1], args.reports[1], args.max_items)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

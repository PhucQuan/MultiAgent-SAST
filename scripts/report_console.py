"""Terminal-first report console for browsing and cleaning Aegis-SAST runs.

Examples:
  python scripts/report_console.py runs
  python scripts/report_console.py show last
  python scripts/report_console.py show reports/manual_targets/pytorch_20260730_125509
  python scripts/report_console.py clean --collection manual-targets --keep 2
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ModuleNotFoundError:  # pragma: no cover - depends on runtime environment
    Console = None
    Panel = None
    Table = None


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from analyze_scan_report import detection_metadata, load_report, summarize_report  # noqa: E402


if Console is None:  # pragma: no cover - fallback only used in thin environments
    class _PlainConsole:
        def print(self, value: object = "") -> None:
            rendered = str(value)
            rendered = re.sub(r"\[/?[^\]]+\]", "", rendered)
            print(rendered)

    class _PlainPanel:
        def __init__(self, content: str):
            self.content = content

        def __str__(self) -> str:
            return self.content

        @classmethod
        def fit(cls, content: str, border_style: str | None = None):
            return cls(content)

    class _PlainTable:
        def __init__(self, title: str | None = None, **_: object):
            self.title = title
            self.columns: list[str] = []
            self.rows: list[tuple[str, ...]] = []

        def add_column(self, label: str, **_: object) -> None:
            self.columns.append(label)

        def add_row(self, *values: object) -> None:
            self.rows.append(tuple(str(value) for value in values))

        def __str__(self) -> str:
            lines: list[str] = []
            if self.title:
                lines.append(self.title)
            if self.columns:
                lines.append(" | ".join(self.columns))
                lines.append("-+-".join("-" * len(column) for column in self.columns))
            for row in self.rows:
                lines.append(" | ".join(row))
            return "\n".join(lines)

    console = _PlainConsole()
    Panel = _PlainPanel
    Table = _PlainTable
else:
    console = Console()
TIMESTAMPED_RUN_RE = re.compile(r"^(?P<prefix>.+)_\d{8}_\d{6}$")
RUN_COLLECTIONS = {
    "manual-targets": REPO_ROOT / "reports" / "manual_targets",
    "rule-review-smoke": REPO_ROOT / "reports" / "rule_review_smoke",
    "reviewed-benchmark": REPO_ROOT / "reports" / "benchmark" / "reviewed_bundle_v1",
    "semgrep-baseline": REPO_ROOT / "reports" / "benchmark" / "semgrep_baseline_v1",
}


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Browse and clean Aegis-SAST report artifacts in the terminal.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    runs_parser = subparsers.add_parser("runs", help="List recent run directories")
    runs_parser.add_argument(
        "--collection",
        choices=[*RUN_COLLECTIONS.keys(), "all"],
        default="manual-targets",
        help="Which report collection to inspect.",
    )
    runs_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of runs to display.",
    )
    runs_parser.add_argument(
        "--target-prefix",
        help="Optional manual-target prefix filter such as vulnerable_rce.py or pytorch.",
    )

    show_parser = subparsers.add_parser("show", help="Show one report or benchmark summary")
    show_parser.add_argument(
        "report",
        nargs="?",
        default="last",
        help="Report JSON path, run directory, or the literal 'last'.",
    )
    show_parser.add_argument(
        "--collection",
        choices=[*RUN_COLLECTIONS.keys(), "all"],
        default="manual-targets",
        help="Collection used when resolving 'last'.",
    )
    show_parser.add_argument(
        "--max-findings",
        type=int,
        default=8,
        help="Maximum findings to show in the compact findings table.",
    )
    show_parser.add_argument(
        "--finding",
        type=int,
        help="Optional 1-based finding index for a detailed view in manual reports.",
    )

    clean_parser = subparsers.add_parser("clean", help="Delete older run directories")
    clean_parser.add_argument(
        "--collection",
        choices=[*RUN_COLLECTIONS.keys(), "all"],
        default="manual-targets",
        help="Which report collection to clean.",
    )
    clean_parser.add_argument(
        "--keep",
        type=int,
        default=2,
        help="How many recent runs to keep per target prefix or collection.",
    )
    clean_parser.add_argument(
        "--target-prefix",
        help="Optional manual-target prefix filter such as vulnerable_rce.py or pytorch.",
    )
    clean_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the run directories that would be removed without deleting them.",
    )

    return parser


def report_kind(report: dict[str, Any]) -> str:
    """Classify one loaded JSON payload."""
    schema_version = report.get("schema_version")
    if schema_version == "aegis-reviewed-bundle-benchmark-result-v1":
        return "reviewed-benchmark"
    if schema_version == "aegis-semgrep-baseline-result-v1":
        return "semgrep-baseline"
    if all(key in report for key in ["default", "reviewed", "comparison"]):
        return "comparison-summary"
    if "scan_metadata" in report and "findings" in report:
        return "manual-report"
    return "unknown"


def find_primary_report_path(run_dir: Path) -> Path:
    """Return the primary JSON artifact inside one run directory."""
    candidates = [
        run_dir / "comparison_summary.json",
        run_dir / "benchmark_summary.json",
        run_dir / "semgrep_baseline_summary.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    json_reports = sorted(run_dir.glob("aegis_sast_report_*.json"))
    if json_reports:
        return json_reports[-1]

    raise FileNotFoundError(f"Could not find a primary JSON report in {run_dir}")


def discover_run_directories(
    collection: str,
    *,
    target_prefix: str | None = None,
) -> list[Path]:
    """Return known run directories for one collection."""
    if collection == "all":
        runs: list[Path] = []
        for name in RUN_COLLECTIONS:
            runs.extend(discover_run_directories(name, target_prefix=target_prefix))
        runs.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
        return runs

    root = RUN_COLLECTIONS[collection]
    if not root.exists():
        return []

    runs: list[Path] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if collection == "manual-targets":
            match = TIMESTAMPED_RUN_RE.match(child.name)
            if not match:
                continue
            if target_prefix and match.group("prefix") != target_prefix:
                continue
        runs.append(child)

    runs.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
    return runs


def resolve_report_path(report_arg: str, *, collection: str) -> Path:
    """Resolve a report selector into one concrete JSON report path."""
    if report_arg in {"last", "latest"}:
        runs = discover_run_directories(collection)
        if not runs:
            raise FileNotFoundError(f"No runs found for collection {collection!r}.")
        return find_primary_report_path(runs[0])

    candidate = Path(report_arg)
    if not candidate.is_absolute():
        candidate = (REPO_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    if candidate.is_dir():
        return find_primary_report_path(candidate)
    if candidate.exists():
        return candidate
    raise FileNotFoundError(f"Report path does not exist: {candidate}")


def print_runs_table(
    collection: str,
    *,
    limit: int,
    target_prefix: str | None = None,
) -> None:
    """Render recent runs in a compact terminal table."""
    run_dirs = discover_run_directories(collection, target_prefix=target_prefix)
    if not run_dirs:
        console.print(f"[yellow]No runs found for collection '{collection}'.[/yellow]")
        return

    table = Table(title="Aegis Report Runs", show_header=True, header_style="bold cyan")
    table.add_column("Collection", style="cyan")
    table.add_column("Run")
    table.add_column("Updated")
    table.add_column("Primary JSON")

    for run_dir in run_dirs[: max(limit, 0)]:
        collection_name = infer_collection_name(run_dir)
        primary = find_primary_report_path(run_dir)
        updated = datetime.fromtimestamp(primary.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        table.add_row(collection_name, run_dir.name, updated, str(primary.relative_to(REPO_ROOT)))

    console.print(table)


def print_report_overview(
    report_path: Path,
    *,
    max_findings: int = 8,
    finding_index: int | None = None,
    preview_only: bool = False,
) -> None:
    """Render one report or benchmark summary in the terminal."""
    report = load_report(report_path)
    kind = report_kind(report)

    if kind == "manual-report":
        _print_manual_report(
            report_path,
            report,
            max_findings=max_findings,
            finding_index=finding_index,
            preview_only=preview_only,
        )
        return
    if kind == "reviewed-benchmark":
        _print_reviewed_benchmark(report_path, report)
        return
    if kind == "semgrep-baseline":
        _print_semgrep_baseline(report_path, report)
        return
    if kind == "comparison-summary":
        _print_comparison_summary(report_path, report)
        return

    console.print(f"[red]Unsupported report shape:[/red] {report_path}")


def _print_manual_report(
    report_path: Path,
    report: dict[str, Any],
    *,
    max_findings: int,
    finding_index: int | None,
    preview_only: bool = False,
) -> None:
    """Render one scan JSON report."""
    metadata = report.get("scan_metadata", {})
    summary = summarize_report(report, report_path)
    header_lines = ["[bold cyan]Aegis Manual Report[/bold cyan]"]
    if preview_only:
        header_lines.append("[dim]Preview only (--no-save)[/dim]")
    else:
        header_lines.append(f"[dim]{report_path}[/dim]")
    header_lines.append(f"Target: {metadata.get('target', 'unknown')}")

    console.print(
        Panel.fit(
            "\n".join(header_lines),
            border_style="cyan",
        )
    )

    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Field", style="green")
    summary_table.add_column("Value")
    summary_table.add_row("Files", str(metadata.get("files_scanned", 0)))
    summary_table.add_row("Findings", str(summary["total_findings"]))
    summary_table.add_row(
        "Severity",
        ", ".join(
            f"{key}={summary['by_severity'].get(key, 0)}"
            for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        ),
    )
    summary_table.add_row(
        "Triage",
        ", ".join(
            f"{key}={summary['by_triage'].get(key, 0)}"
            for key in ["confirmed", "likely", "needs-review", "suppressed"]
        ),
    )
    console.print(summary_table)

    type_table = Table(title="Top Finding Types", show_header=True, header_style="bold magenta")
    type_table.add_column("Type", style="magenta")
    type_table.add_column("Count", justify="right")
    for vuln_type, count in Counter(summary["by_type"]).most_common(8):
        type_table.add_row(vuln_type, str(count))
    console.print(type_table)

    findings = report.get("findings", [])
    findings_table = Table(title="Findings", show_header=True, header_style="bold yellow")
    findings_table.add_column("#", justify="right", style="yellow")
    findings_table.add_column("Severity")
    findings_table.add_column("Type")
    findings_table.add_column("Triage")
    findings_table.add_column("Location")
    findings_table.add_column("Sink")
    for index, finding in enumerate(findings[: max(max_findings, 0)], start=1):
        detection = detection_metadata(finding)
        location = f"{Path(finding.get('file', 'unknown')).name}:{finding.get('line', '?')}"
        sink_name = detection.get("sink_function") or detection.get("sink_pattern") or "unknown"
        findings_table.add_row(
            str(index),
            finding.get("severity", "UNKNOWN"),
            finding.get("type", "UNKNOWN"),
            finding.get("triage_status", "unknown"),
            location,
            sink_name,
        )
    console.print(findings_table)

    if finding_index is not None:
        if finding_index < 1 or finding_index > len(findings):
            raise ValueError(
                f"finding index must be between 1 and {len(findings)} for {report_path}"
            )
        _print_manual_finding_detail(findings[finding_index - 1], finding_index)


def _print_manual_finding_detail(finding: dict[str, Any], finding_index: int) -> None:
    """Render one detailed manual finding view."""
    evidence = finding.get("evidence", {})
    summary = evidence.get("summary", {})
    source = evidence.get("source", {})
    sink = evidence.get("sink", {})
    path_summary = summary.get("path_summary", [])

    console.print(
        Panel.fit(
            (
                f"[bold red]Finding #{finding_index}[/bold red]\n"
                f"{finding.get('type', 'UNKNOWN')} | {finding.get('severity', 'UNKNOWN')} | "
                f"{finding.get('triage_status', 'unknown')}"
            ),
            border_style="red",
        )
    )

    detail_table = Table(show_header=False, box=None)
    detail_table.add_column("Field", style="green")
    detail_table.add_column("Value")
    detail_table.add_row("File", finding.get("file", "unknown"))
    detail_table.add_row("Line", str(finding.get("line", "?")))
    detail_table.add_row("Source", f"{source.get('file')}:{source.get('line')} | {source.get('snippet', '')}")
    detail_table.add_row("Sink", f"{sink.get('file')}:{sink.get('line')} | {sink.get('snippet', '')}")
    detail_table.add_row("Recommendation", finding.get("recommendation") or "n/a")
    console.print(detail_table)

    if path_summary:
        console.print("[bold]Path Summary[/bold]")
        for index, step in enumerate(path_summary, start=1):
            console.print(f"  {index}. {step}")


def _print_reviewed_benchmark(report_path: Path, report: dict[str, Any]) -> None:
    """Render one reviewed-bundle benchmark summary."""
    aggregate = report.get("aggregate", {})
    console.print(
        Panel.fit(
            (
                "[bold cyan]Reviewed Bundle Benchmark[/bold cyan]\n"
                f"[dim]{report_path}[/dim]"
            ),
            border_style="cyan",
        )
    )

    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Field", style="green")
    summary_table.add_column("Value")
    summary_table.add_row("Cases", str(report.get("case_count", 0)))
    summary_table.add_row(
        "Findings",
        (
            f"{aggregate.get('default_findings', 0)} -> "
            f"{aggregate.get('reviewed_findings', 0)} "
            f"(delta {aggregate.get('finding_delta', 0):+d})"
        ),
    )
    summary_table.add_row("Unique Delta", f"{aggregate.get('unique_delta', 0):+d}")
    summary_table.add_row("Coverage Delta", f"{aggregate.get('coverage_delta', 0):+d}")
    summary_table.add_row("Mismatch Delta", f"{aggregate.get('mismatch_delta', 0):+d}")
    console.print(summary_table)

    case_table = Table(title="Cases", show_header=True, header_style="bold magenta")
    case_table.add_column("Case", style="magenta")
    case_table.add_column("Family")
    case_table.add_column("Default", justify="right")
    case_table.add_column("Reviewed", justify="right")
    case_table.add_column("Delta", justify="right")
    for case in report.get("cases", []):
        case_table.add_row(
            case.get("case_id", "unknown"),
            case.get("family", "unknown"),
            str(case.get("default_findings", 0)),
            str(case.get("reviewed_findings", 0)),
            f"{case.get('finding_delta', 0):+d}",
        )
    console.print(case_table)


def _print_comparison_summary(report_path: Path, report: dict[str, Any]) -> None:
    """Render one side-by-side comparison summary."""
    comparison = report.get("comparison", {})
    default_summary = report.get("default", {})
    reviewed_summary = report.get("reviewed", {})

    console.print(
        Panel.fit(
            (
                "[bold cyan]Reviewed Bundle Comparison[/bold cyan]\n"
                f"[dim]{report_path}[/dim]"
            ),
            border_style="cyan",
        )
    )

    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Field", style="green")
    summary_table.add_column("Value")
    summary_table.add_row("Target", report.get("target", "unknown"))
    summary_table.add_row("Default Findings", str(default_summary.get("total_findings", 0)))
    summary_table.add_row("Reviewed Findings", str(reviewed_summary.get("total_findings", 0)))
    summary_table.add_row("Finding Delta", f"{comparison.get('finding_delta', 0):+d}")
    summary_table.add_row("Unique Delta", f"{comparison.get('unique_delta', 0):+d}")
    summary_table.add_row("Coverage Delta", f"{comparison.get('coverage_delta', 0):+d}")
    console.print(summary_table)


def _print_semgrep_baseline(report_path: Path, report: dict[str, Any]) -> None:
    """Render one Semgrep baseline summary."""
    aggregate = report.get("aggregate", {})
    console.print(
        Panel.fit(
            (
                "[bold cyan]Semgrep Baseline[/bold cyan]\n"
                f"[dim]{report_path}[/dim]"
            ),
            border_style="cyan",
        )
    )

    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Field", style="green")
    summary_table.add_column("Value")
    summary_table.add_row("Cases", str(report.get("case_count", 0)))
    summary_table.add_row("Results", str(aggregate.get("result_count", 0)))
    summary_table.add_row("Reported Errors", str(aggregate.get("error_count", 0)))
    summary_table.add_row("Files Scanned", str(aggregate.get("files_scanned", 0)))
    console.print(summary_table)

    case_table = Table(title="Cases", show_header=True, header_style="bold magenta")
    case_table.add_column("Case", style="magenta")
    case_table.add_column("Family")
    case_table.add_column("Results", justify="right")
    case_table.add_column("Errors", justify="right")
    for case in report.get("cases", []):
        case_table.add_row(
            case.get("case_id", "unknown"),
            case.get("family", "unknown"),
            str(case.get("result_count", 0)),
            str(case.get("error_count", 0)),
        )
    console.print(case_table)


def infer_collection_name(run_dir: Path) -> str:
    """Return the collection name inferred from one run directory."""
    for name, root in RUN_COLLECTIONS.items():
        try:
            run_dir.resolve().relative_to(root.resolve())
            return name
        except ValueError:
            continue
    return "unknown"


def select_cleanup_directories(
    collection: str,
    *,
    keep: int,
    target_prefix: str | None = None,
) -> list[Path]:
    """Return run directories that should be removed for one collection."""
    if keep < 0:
        raise ValueError("--keep must be zero or greater.")

    if collection == "all":
        candidates: list[Path] = []
        for name in RUN_COLLECTIONS:
            candidates.extend(
                select_cleanup_directories(
                    name,
                    keep=keep,
                    target_prefix=target_prefix,
                )
            )
        candidates.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
        return candidates

    run_dirs = discover_run_directories(collection, target_prefix=target_prefix)
    if collection != "manual-targets":
        return run_dirs[keep:]

    grouped: dict[str, list[Path]] = {}
    for run_dir in run_dirs:
        match = TIMESTAMPED_RUN_RE.match(run_dir.name)
        if not match:
            continue
        prefix = match.group("prefix")
        grouped.setdefault(prefix, []).append(run_dir)

    stale_dirs: list[Path] = []
    for prefix, group in grouped.items():
        if target_prefix and prefix != target_prefix:
            continue
        group.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
        stale_dirs.extend(group[keep:])
    return stale_dirs


def clean_run_directories(
    collection: str,
    *,
    keep: int,
    target_prefix: str | None = None,
    dry_run: bool = False,
) -> list[Path]:
    """Delete older run directories and return the affected paths."""
    stale_dirs = select_cleanup_directories(
        collection,
        keep=keep,
        target_prefix=target_prefix,
    )
    for stale_dir in stale_dirs:
        resolved = stale_dir.resolve()
        if not str(resolved).startswith(str(REPO_ROOT.resolve())):
            raise ValueError(f"Refusing to clean outside the workspace: {resolved}")
        if not dry_run:
            shutil.rmtree(resolved)
    return stale_dirs


def main(argv: list[str] | None = None) -> int:
    """Run the terminal report console."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "runs":
            print_runs_table(
                args.collection,
                limit=args.limit,
                target_prefix=args.target_prefix,
            )
            return 0

        if args.command == "show":
            report_path = resolve_report_path(args.report, collection=args.collection)
            print_report_overview(
                report_path,
                max_findings=args.max_findings,
                finding_index=args.finding,
            )
            return 0

        if args.command == "clean":
            stale_dirs = clean_run_directories(
                args.collection,
                keep=args.keep,
                target_prefix=args.target_prefix,
                dry_run=args.dry_run,
            )
            if not stale_dirs:
                console.print("[green]No old run directories matched the cleanup rules.[/green]")
                return 0
            action = "Would remove" if args.dry_run else "Removed"
            console.print(f"[bold cyan]{action} {len(stale_dirs)} run directorie(s).[/bold cyan]")
            for path in stale_dirs:
                console.print(f"  - {path}")
            return 0
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

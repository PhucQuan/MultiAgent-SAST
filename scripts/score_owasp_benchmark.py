"""Score one Aegis JSON report against OWASP Benchmark expected results.

Examples:
  python scripts/score_owasp_benchmark.py ^
    --report reports/manual_targets/benchmark_python/aegis_sast_report.json ^
    --expected-results D:\\BenchmarkPython\\expectedresults-0.1.csv

  python scripts/score_owasp_benchmark.py ^
    --report reports/manual_targets/benchmark_java/aegis_sast_report.json ^
    --expected-results D:\\BenchmarkJava\\expectedresults-1.2.csv ^
    --family COMMAND_INJECTION --family PATH_TRAVERSAL --family SQL_INJECTION
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ModuleNotFoundError:  # pragma: no cover - runtime environment dependent
    Console = None
    Panel = None
    Table = None


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


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


CASE_ID_RE = re.compile(r"(BenchmarkTest\d+)", re.IGNORECASE)
OWASP_CATEGORY_TO_FAMILY = {
    "cmdi": "COMMAND_INJECTION",
    "codeinj": "CODE_INJECTION",
    "deserialization": "INSECURE_DESERIALIZATION",
    "ldapi": "LDAP_INJECTION",
    "pathtraver": "PATH_TRAVERSAL",
    "redirect": "OPEN_REDIRECT",
    "sqli": "SQL_INJECTION",
    "ssrf": "SSRF",
    "xpathi": "XPATH_INJECTION",
    "xss": "XSS",
    "xxe": "XXE",
}
MODE_FILTERS: dict[str, Callable[[dict[str, Any]], bool]] = {
    "all": lambda finding: True,
    "visible": lambda finding: (finding.get("triage_status") or "") != "suppressed",
    "high-confidence": lambda finding: (finding.get("triage_status") or "") in {
        "confirmed",
        "likely",
    },
}
MODE_LABELS = {
    "all": "All findings",
    "visible": "Visible after triage",
    "high-confidence": "High confidence",
}


class ExpectedCase(NamedTuple):
    """One expected benchmark case from the OWASP CSV."""

    case_id: str
    category: str
    family: str | None
    vulnerable: bool
    cwe: str | None = None


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Score one Aegis-SAST JSON report against an OWASP Benchmark "
            "expectedresults CSV."
        ),
    )
    parser.add_argument(
        "--report",
        type=Path,
        required=True,
        help="Path to one Aegis JSON report.",
    )
    parser.add_argument(
        "--expected-results",
        type=Path,
        required=True,
        help="Path to OWASP expectedresults-*.csv.",
    )
    parser.add_argument(
        "--family",
        action="append",
        default=[],
        help=(
            "Optional repeatable Aegis family filter such as PATH_TRAVERSAL, "
            "COMMAND_INJECTION, SQL_INJECTION."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "Directory for score artifacts. Defaults to "
            "reports/benchmark/owasp/<dataset>_<timestamp>."
        ),
    )
    parser.add_argument(
        "--max-case-list",
        type=int,
        default=20,
        help="Maximum false-positive / false-negative case IDs kept per family.",
    )
    return parser


def default_output_dir(expected_results_path: Path) -> Path:
    """Build a stable output directory for one benchmark score run."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dataset_name = expected_results_path.resolve().parent.name.replace(" ", "_")
    return REPO_ROOT / "reports" / "benchmark" / "owasp" / f"{dataset_name}_{timestamp}"


def load_report(path: Path) -> dict[str, Any]:
    """Load one JSON report from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def load_expected_cases(path: Path) -> list[ExpectedCase]:
    """Load the OWASP expected-results CSV into structured cases."""
    if not path.exists():
        raise FileNotFoundError(f"Expected-results CSV does not exist: {path}")

    cases: list[ExpectedCase] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row:
                continue
            first = row[0].strip()
            if not first or first.startswith("#"):
                continue
            if len(row) < 4:
                raise ValueError(f"Malformed expected-results row: {row!r}")

            category = row[1].strip()
            family = OWASP_CATEGORY_TO_FAMILY.get(category)
            cases.append(
                ExpectedCase(
                    case_id=first,
                    category=category,
                    family=family,
                    vulnerable=row[2].strip().lower() == "true",
                    cwe=row[3].strip() or None,
                )
            )

    if not cases:
        raise ValueError(f"No benchmark cases were loaded from: {path}")
    return cases


def normalize_family_name(value: str | None) -> str | None:
    """Return a stable Aegis family name when one is recognizable."""
    if not value:
        return None
    normalized = value.strip().upper().replace("-", "_")
    return normalized or None


def extract_case_id(payload: dict[str, Any]) -> str | None:
    """Extract a BenchmarkTest identifier from a finding payload."""
    candidates = [
        payload.get("file"),
        payload.get("path"),
        payload.get("message"),
        payload.get("evidence", {}).get("sink", {}).get("file"),
        payload.get("evidence", {}).get("source", {}).get("file"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        match = CASE_ID_RE.search(str(candidate))
        if match:
            return match.group(1)
    return None


def family_candidates_from_report(report: dict[str, Any]) -> set[str]:
    """Return mapped family names present in the current report."""
    families = set()
    for finding in report.get("findings", []):
        family = normalize_family_name(finding.get("type"))
        if family:
            families.add(family)
    return families


def expected_family_candidates(expected_cases: Iterable[ExpectedCase]) -> set[str]:
    """Return mapped family names present in the benchmark CSV."""
    return {
        case.family
        for case in expected_cases
        if case.family
    }


def resolve_families(
    report: dict[str, Any],
    expected_cases: list[ExpectedCase],
    families: Iterable[str] | None = None,
) -> list[str]:
    """Resolve which Aegis families should be scored for this run."""
    requested = [
        normalize_family_name(item)
        for item in (families or [])
        if normalize_family_name(item)
    ]
    if requested:
        return list(dict.fromkeys(requested))

    candidates = expected_family_candidates(expected_cases) | family_candidates_from_report(report)
    return sorted(candidates)


def findings_for_mode(
    report: dict[str, Any],
    *,
    mode_name: str,
    selected_families: set[str],
) -> list[dict[str, Any]]:
    """Filter report findings into one scoring mode."""
    predicate = MODE_FILTERS[mode_name]
    filtered: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        family = normalize_family_name(finding.get("type"))
        if family not in selected_families:
            continue
        case_id = extract_case_id(finding)
        if not case_id or not predicate(finding):
            continue
        filtered.append(
            {
                **finding,
                "_family": family,
                "_case_id": case_id,
            }
        )
    return filtered


def _safe_divide(numerator: float, denominator: float) -> float:
    """Return a stable zero-safe division."""
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def _rounded_metric(value: float) -> float:
    """Round metrics so JSON/Markdown stay readable."""
    return round(value, 4)


def score_family(
    family: str,
    expected_cases: list[ExpectedCase],
    findings: list[dict[str, Any]],
    *,
    max_case_list: int,
) -> dict[str, Any]:
    """Score one family at the case level."""
    family_cases = [case for case in expected_cases if case.family == family]
    all_expected_case_ids = {case.case_id for case in expected_cases}
    true_case_ids = {case.case_id for case in family_cases if case.vulnerable}
    false_case_ids = all_expected_case_ids - true_case_ids
    detected_case_ids = {
        finding["_case_id"]
        for finding in findings
        if finding["_family"] == family
    }

    true_positives = sorted(true_case_ids & detected_case_ids)
    false_positives = sorted(false_case_ids & detected_case_ids)
    false_negatives = sorted(true_case_ids - detected_case_ids)
    true_negatives = sorted(false_case_ids - detected_case_ids)
    unexpected_case_ids = sorted(detected_case_ids - (true_case_ids | false_case_ids))

    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)
    tn = len(true_negatives)
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(2 * precision * recall, precision + recall)

    return {
        "family": family,
        "expected_true_case_count": len(true_case_ids),
        "expected_false_case_count": len(false_case_ids),
        "expected_case_count": len(all_expected_case_ids),
        "detected_case_count": len(detected_case_ids),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": _rounded_metric(precision),
        "recall": _rounded_metric(recall),
        "f1": _rounded_metric(f1),
        "true_positive_cases": true_positives[:max_case_list],
        "false_positive_cases": false_positives[:max_case_list],
        "false_negative_cases": false_negatives[:max_case_list],
        "unexpected_case_ids": unexpected_case_ids[:max_case_list],
    }


def aggregate_family_scores(family_scores: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-family scores into one JSON-friendly summary."""
    tp = sum(item["tp"] for item in family_scores)
    fp = sum(item["fp"] for item in family_scores)
    fn = sum(item["fn"] for item in family_scores)
    tn = sum(item["tn"] for item in family_scores)
    detected_case_count = sum(item["detected_case_count"] for item in family_scores)
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(2 * precision * recall, precision + recall)

    return {
        "expected_true_case_count": sum(
            item["expected_true_case_count"] for item in family_scores
        ),
        "expected_false_case_count": sum(
            item["expected_false_case_count"] for item in family_scores
        ),
        "expected_case_count": sum(item["expected_case_count"] for item in family_scores),
        "detected_case_count": detected_case_count,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": _rounded_metric(precision),
        "recall": _rounded_metric(recall),
        "f1": _rounded_metric(f1),
    }


def score_report(
    report: dict[str, Any],
    expected_cases: list[ExpectedCase],
    *,
    families: Iterable[str] | None = None,
    max_case_list: int = 20,
) -> dict[str, Any]:
    """Score one report against the benchmark expected-results CSV."""
    selected_families = resolve_families(report, expected_cases, families=families)
    selected_family_set = set(selected_families)

    modes: dict[str, Any] = {}
    for mode_name in MODE_FILTERS:
        mode_findings = findings_for_mode(
            report,
            mode_name=mode_name,
            selected_families=selected_family_set,
        )
        family_scores = [
            score_family(
                family,
                expected_cases,
                mode_findings,
                max_case_list=max_case_list,
            )
            for family in selected_families
        ]
        modes[mode_name] = {
            "family_count": len(family_scores),
            "finding_count": len(mode_findings),
            "families": family_scores,
            "aggregate": aggregate_family_scores(family_scores),
            "triage_status_counts": dict(
                Counter(
                    (finding.get("triage_status") or "unknown")
                    for finding in mode_findings
                )
            ),
        }

    category_counts = Counter(case.category for case in expected_cases)
    return {
        "schema_version": "aegis-owasp-benchmark-score-v1",
        "generated_at": datetime.now().isoformat(),
        "target": report.get("scan_metadata", {}).get("target"),
        "files_scanned": report.get("scan_metadata", {}).get("files_scanned", 0),
        "total_findings": len(report.get("findings", [])),
        "expected_case_count": len(expected_cases),
        "supported_expected_case_count": sum(
            1 for case in expected_cases if case.family in selected_family_set
        ),
        "families": selected_families,
        "expected_category_counts": dict(category_counts),
        "modes": modes,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    """Render one Markdown benchmark summary."""
    lines = [
        "# OWASP Benchmark Score",
        "",
        f"- Target: `{summary.get('target') or 'unknown'}`",
        f"- Files scanned: {summary.get('files_scanned', 0)}",
        f"- Report findings: {summary.get('total_findings', 0)}",
        f"- Expected cases loaded: {summary.get('expected_case_count', 0)}",
        f"- Expected cases scored: {summary.get('supported_expected_case_count', 0)}",
        f"- Families: {', '.join(summary.get('families', [])) or 'none'}",
        "",
    ]

    for mode_name, mode_summary in summary["modes"].items():
        aggregate = mode_summary["aggregate"]
        lines.extend(
            [
                f"## Mode: {mode_name}",
                "",
                "| Metric | Value |",
                "|---|---:|",
                f"| Findings kept | {mode_summary['finding_count']} |",
                f"| TP | {aggregate['tp']} |",
                f"| FP | {aggregate['fp']} |",
                f"| FN | {aggregate['fn']} |",
                f"| Precision | {aggregate['precision']:.4f} |",
                f"| Recall | {aggregate['recall']:.4f} |",
                f"| F1 | {aggregate['f1']:.4f} |",
                "",
                "| Family | Expected True | Expected False | Detected | TP | FP | FN | Precision | Recall | F1 |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for item in mode_summary["families"]:
            lines.append(
                f"| `{item['family']}` | {item['expected_true_case_count']} | "
                f"{item['expected_false_case_count']} | {item['detected_case_count']} | "
                f"{item['tp']} | {item['fp']} | {item['fn']} | "
                f"{item['precision']:.4f} | {item['recall']:.4f} | {item['f1']:.4f} |"
            )

        lines.append("")
        for item in mode_summary["families"]:
            fp_cases = ", ".join(item["false_positive_cases"]) or "none"
            fn_cases = ", ".join(item["false_negative_cases"]) or "none"
            lines.append(f"- `{item['family']}` FP cases: {fp_cases}")
            lines.append(f"- `{item['family']}` FN cases: {fn_cases}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_outputs(summary: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write JSON and Markdown outputs for one score run."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "owasp_score_summary.json"
    markdown_path = output_dir / "owasp_score_summary.md"
    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    return json_path, markdown_path


def print_score_overview(
    *,
    summary: dict[str, Any],
    report_path: Path,
    expected_results_path: Path,
    json_path: Path,
    markdown_path: Path,
) -> None:
    """Render a compact terminal summary for one OWASP score run."""
    console.print(
        Panel.fit(
            (
                "[bold cyan]OWASP Benchmark Score[/bold cyan]\n"
                f"[dim]{report_path}[/dim]"
            ),
            border_style="cyan",
        )
    )

    overview = Table(show_header=False, box=None)
    overview.add_column("Field", style="green")
    overview.add_column("Value")
    overview.add_row("Expected CSV", str(expected_results_path))
    overview.add_row("Families", ", ".join(summary.get("families", [])) or "none")
    overview.add_row("Files scanned", str(summary.get("files_scanned", 0)))
    overview.add_row("Report findings", str(summary.get("total_findings", 0)))
    overview.add_row("Expected cases", str(summary.get("supported_expected_case_count", 0)))
    console.print(overview)

    aggregate_table = Table(
        title="Aggregate Score",
        show_header=True,
        header_style="bold magenta",
    )
    aggregate_table.add_column("Mode", style="magenta")
    aggregate_table.add_column("TP", justify="right")
    aggregate_table.add_column("FP", justify="right")
    aggregate_table.add_column("FN", justify="right")
    aggregate_table.add_column("Precision", justify="right")
    aggregate_table.add_column("Recall", justify="right")
    aggregate_table.add_column("F1", justify="right")

    for mode_name in ["all", "visible", "high-confidence"]:
        mode_summary = summary["modes"][mode_name]["aggregate"]
        aggregate_table.add_row(
            MODE_LABELS[mode_name],
            str(mode_summary["tp"]),
            str(mode_summary["fp"]),
            str(mode_summary["fn"]),
            f"{mode_summary['precision']:.4f}",
            f"{mode_summary['recall']:.4f}",
            f"{mode_summary['f1']:.4f}",
        )
    console.print(aggregate_table)

    family_table = Table(
        title="Per Family (All Findings)",
        show_header=True,
        header_style="bold yellow",
    )
    family_table.add_column("Family", style="yellow")
    family_table.add_column("TP", justify="right")
    family_table.add_column("FP", justify="right")
    family_table.add_column("FN", justify="right")
    family_table.add_column("Precision", justify="right")
    family_table.add_column("Recall", justify="right")
    family_table.add_column("F1", justify="right")

    for family_summary in summary["modes"]["all"]["families"]:
        family_table.add_row(
            family_summary["family"],
            str(family_summary["tp"]),
            str(family_summary["fp"]),
            str(family_summary["fn"]),
            f"{family_summary['precision']:.4f}",
            f"{family_summary['recall']:.4f}",
            f"{family_summary['f1']:.4f}",
        )
    console.print(family_table)

    artifact_table = Table(show_header=False, box=None)
    artifact_table.add_column("Artifact", style="green")
    artifact_table.add_column("Path")
    artifact_table.add_row("JSON", str(json_path))
    artifact_table.add_row("Markdown", str(markdown_path))
    console.print(artifact_table)


def main(argv: list[str] | None = None) -> int:
    """Score one report against an OWASP expected-results CSV."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report_path = args.report.resolve()
        expected_results_path = args.expected_results.resolve()
        if not report_path.exists():
            raise FileNotFoundError(f"Report does not exist: {report_path}")

        summary = score_report(
            load_report(report_path),
            load_expected_cases(expected_results_path),
            families=args.family,
            max_case_list=args.max_case_list,
        )
        output_dir = (args.output_dir or default_output_dir(expected_results_path)).resolve()
        json_path, markdown_path = write_outputs(summary, output_dir)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except ValueError as exc:
        parser.error(str(exc))

    print_score_overview(
        summary=summary,
        report_path=report_path,
        expected_results_path=expected_results_path,
        json_path=json_path,
        markdown_path=markdown_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

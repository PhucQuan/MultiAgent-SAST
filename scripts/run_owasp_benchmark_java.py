"""Run Aegis-SAST against OWASP BenchmarkJava and compute score metrics."""

import argparse
import csv
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis_sast.analysis.rule_engine import RuleEngine
from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector


BENCHMARK_REPO = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
SUPPORTED_CATEGORY_TO_VULN_TYPE = {
    "cmdi": "COMMAND_INJECTION",
    "pathtraver": "PATH_TRAVERSAL",
    "sqli": "SQL_INJECTION",
    "xss": "XSS",
}
VULN_TYPE_TO_CATEGORY = {value: key for key, value in SUPPORTED_CATEGORY_TO_VULN_TYPE.items()}


@dataclass
class ExpectedCase:
    """Ground truth row from expectedresults-1.2.csv."""

    test_name: str
    category: str
    vulnerable: bool
    cwe: str


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark-root",
        type=Path,
        default=Path("/tmp/BenchmarkJava"),
        help="Path to OWASP BenchmarkJava checkout.",
    )
    parser.add_argument(
        "--clone-if-missing",
        action="store_true",
        help="Clone BenchmarkJava into --benchmark-root when missing.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "benchmarks" / "owasp_benchmark_java",
        help="Directory for JSON and CSV results.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Aegis-SAST detector max analysis depth.",
    )
    args = parser.parse_args()

    if not args.benchmark_root.exists():
        if not args.clone_if_missing:
            raise SystemExit(
                f"{args.benchmark_root} does not exist. Re-run with --clone-if-missing."
            )
        _clone_benchmark(args.benchmark_root)

    summary = run_benchmark(
        benchmark_root=args.benchmark_root,
        out_dir=args.out_dir,
        max_depth=args.max_depth,
    )
    print(json.dumps(summary["score"], indent=2, sort_keys=True))
    print(f"Wrote JSON: {summary['paths']['json']}")
    print(f"Wrote CSV: {summary['paths']['csv']}")


def run_benchmark(
    *,
    benchmark_root: Path,
    out_dir: Path,
    max_depth: int = 5,
) -> dict:
    """Run the scanner and write benchmark score artifacts."""
    expected_path = benchmark_root / "expectedresults-1.2.csv"
    source_root = benchmark_root / "src" / "main" / "java"
    if not expected_path.exists():
        raise FileNotFoundError(f"Missing OWASP expected results: {expected_path}")
    if not source_root.exists():
        raise FileNotFoundError(f"Missing OWASP Java sources: {source_root}")

    started_at = datetime.now(timezone.utc)
    expected_cases = load_expected_results(expected_path)
    scan_result = VulnerabilityDetector(RuleEngine(), max_depth).analyze_directory(source_root)
    predictions = predictions_by_test_name(scan_result.vulnerabilities)
    rows = build_score_rows(expected_cases, predictions)
    score = build_score_summary(rows, scan_result.files_scanned, len(scan_result.errors))
    finished_at = datetime.now(timezone.utc)
    score["duration_seconds"] = (finished_at - started_at).total_seconds()
    score["benchmark_commit"] = _git_rev_parse(benchmark_root)
    score["benchmark_source"] = BENCHMARK_REPO
    score["started_at"] = started_at.isoformat()
    score["finished_at"] = finished_at.isoformat()

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "aegis_owasp_benchmark_java_score.json"
    csv_path = out_dir / "aegis_owasp_benchmark_java_cases.csv"
    json_path.write_text(
        json.dumps(
            {
                "score": score,
                "cases": rows,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    write_case_csv(csv_path, rows)
    return {
        "score": score,
        "cases": rows,
        "paths": {
            "json": str(json_path),
            "csv": str(csv_path),
        },
    }


def load_expected_results(path: Path) -> List[ExpectedCase]:
    """Load OWASP Benchmark expected results."""
    cases: List[ExpectedCase] = []
    with path.open(encoding="utf-8") as handle:
        for raw_line in handle:
            if raw_line.startswith("#") or not raw_line.strip():
                continue
            test_name, category, vulnerable, cwe = [part.strip() for part in raw_line.split(",")]
            cases.append(
                ExpectedCase(
                    test_name=test_name,
                    category=category,
                    vulnerable=vulnerable.lower() == "true",
                    cwe=cwe,
                )
            )
    return cases


def predictions_by_test_name(vulnerabilities: Iterable[object]) -> Dict[str, Set[str]]:
    """Map BenchmarkTestNNNNN to predicted OWASP categories."""
    predictions: Dict[str, Set[str]] = {}
    for vulnerability in vulnerabilities:
        file_path = vulnerability.dataflow.sink.location.file_path
        match = re.search(r"(BenchmarkTest\d{5})\.java$", file_path)
        if not match:
            continue
        category = VULN_TYPE_TO_CATEGORY.get(vulnerability.vuln_type.value)
        if not category:
            continue
        predictions.setdefault(match.group(1), set()).add(category)
    return predictions


def build_score_rows(
    expected_cases: Iterable[ExpectedCase],
    predictions: Dict[str, Set[str]],
) -> List[dict]:
    """Build per-case scoring rows."""
    rows = []
    for case in expected_cases:
        predicted_categories = sorted(predictions.get(case.test_name, set()))
        category_predicted = case.category in predicted_categories
        supported_category = case.category in SUPPORTED_CATEGORY_TO_VULN_TYPE
        if category_predicted and case.vulnerable:
            outcome = "TP"
        elif category_predicted and not case.vulnerable:
            outcome = "FP"
        elif not category_predicted and case.vulnerable:
            outcome = "FN"
        else:
            outcome = "TN"

        rows.append(
            {
                "test_name": case.test_name,
                "category": case.category,
                "cwe": case.cwe,
                "expected_vulnerable": case.vulnerable,
                "supported_category": supported_category,
                "predicted_categories": predicted_categories,
                "predicted_for_expected_category": category_predicted,
                "outcome": outcome,
            }
        )
    return rows


def build_score_summary(rows: List[dict], files_scanned: int, error_count: int) -> dict:
    """Compute overall, supported-only, and per-category benchmark metrics."""
    return {
        "files_scanned": files_scanned,
        "scanner_error_count": error_count,
        "all_categories": _metrics_for_rows(rows),
        "supported_categories": _metrics_for_rows(
            [row for row in rows if row["supported_category"]]
        ),
        "per_category": {
            category: _metrics_for_rows([row for row in rows if row["category"] == category])
            for category in sorted({row["category"] for row in rows})
        },
        "supported_category_mapping": SUPPORTED_CATEGORY_TO_VULN_TYPE,
    }


def write_case_csv(path: Path, rows: List[dict]) -> None:
    """Write per-case score rows as CSV."""
    fieldnames = [
        "test_name",
        "category",
        "cwe",
        "expected_vulnerable",
        "supported_category",
        "predicted_categories",
        "predicted_for_expected_category",
        "outcome",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            csv_row = dict(row)
            csv_row["predicted_categories"] = "|".join(row["predicted_categories"])
            writer.writerow(csv_row)


def _metrics_for_rows(rows: List[dict]) -> dict:
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for row in rows:
        counts[row["outcome"]] += 1
    tp = counts["TP"]
    fp = counts["FP"]
    tn = counts["TN"]
    fn = counts["FN"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "total": len(rows),
        **counts,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "accuracy": accuracy,
        "f1": f1,
    }


def _clone_benchmark(target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", BENCHMARK_REPO, str(target)],
        check=True,
    )


def _git_rev_parse(repo_root: Path) -> Optional[str]:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    except Exception:
        return None


if __name__ == "__main__":
    main()

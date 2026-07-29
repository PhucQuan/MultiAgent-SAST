"""Evaluate AI experiment raw JSONL against ground-truth sidecar labels."""

import argparse
import json
from pathlib import Path


POSITIVE_STATUSES = {"confirmed", "likely"}
SUPPRESSED_STATUSES = {"suppressed"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True, help="Raw experiment JSONL.")
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Evaluation summary JSON path.",
    )
    args = parser.parse_args()

    rows = _read_jsonl(args.raw)
    summary = evaluate_rows(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote evaluation summary to {args.out}")


def evaluate_rows(rows: list[dict]) -> dict:
    """Compute benchmark-oriented metrics from raw experiment rows."""
    labeled = [row for row in rows if _ground_truth_value(row) is not None]
    true_positive_predictions = 0
    positive_predictions = 0
    false_positive_count = 0
    suppressed_false_positives = 0
    suppressed_true_positives = 0

    by_language: dict[str, dict[str, int]] = {}
    by_vuln_type: dict[str, dict[str, int]] = {}

    for row in labeled:
        predicted = row["predicted_status"]
        truth = bool(_ground_truth_value(row))
        if predicted in POSITIVE_STATUSES:
            positive_predictions += 1
            if truth:
                true_positive_predictions += 1
        if not truth:
            false_positive_count += 1
            if predicted in SUPPRESSED_STATUSES:
                suppressed_false_positives += 1
        if truth and predicted in SUPPRESSED_STATUSES:
            suppressed_true_positives += 1

        _increment_breakdown(by_language, row["language"], predicted)
        _increment_breakdown(by_vuln_type, row["vuln_type"], predicted)

    precision = true_positive_predictions / positive_predictions if positive_predictions else 0.0
    fp_reduction = (
        suppressed_false_positives / false_positive_count if false_positive_count else 0.0
    )
    suppression_error_rate = (
        suppressed_true_positives / sum(1 for row in labeled if bool(_ground_truth_value(row)))
        if labeled
        else 0.0
    )

    return {
        "total_rows": len(rows),
        "labeled_rows": len(labeled),
        "precision_proxy": precision,
        "false_positive_count": false_positive_count,
        "suppressed_false_positive_count": suppressed_false_positives,
        "false_positive_reduction_rate": fp_reduction,
        "suppressed_true_positive_count": suppressed_true_positives,
        "suppression_error_rate": suppression_error_rate,
        "by_language": by_language,
        "by_vuln_type": by_vuln_type,
    }


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _ground_truth_value(row: dict):
    truth = row.get("ground_truth") or {}
    return truth.get("ground_truth_vuln")


def _increment_breakdown(target: dict[str, dict[str, int]], key: str, status: str) -> None:
    target.setdefault(key, {})
    target[key][status] = target[key].get(status, 0) + 1


if __name__ == "__main__":
    main()

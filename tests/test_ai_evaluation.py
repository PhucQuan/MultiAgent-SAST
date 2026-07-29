"""Tests for AI experiment evaluation metrics."""

import json
import subprocess
import sys
from pathlib import Path

from scripts.evaluate_ai_results import evaluate_rows


ROOT = Path(__file__).resolve().parents[1]


def test_evaluate_rows_computes_fp_reduction_and_precision_proxy():
    rows = [
        {
            "language": "python",
            "vuln_type": "COMMAND_INJECTION",
            "predicted_status": "confirmed",
            "ground_truth": {"ground_truth_vuln": True},
        },
        {
            "language": "javascript",
            "vuln_type": "SQL_INJECTION",
            "predicted_status": "suppressed",
            "ground_truth": {"ground_truth_vuln": False},
        },
    ]

    summary = evaluate_rows(rows)

    assert summary["precision_proxy"] == 1.0
    assert summary["false_positive_reduction_rate"] == 1.0
    assert summary["suppression_error_rate"] == 0.0
    assert summary["by_language"]["python"]["confirmed"] == 1


def test_evaluation_script_reads_raw_jsonl(tmp_path):
    raw = tmp_path / "raw.jsonl"
    out = tmp_path / "summary.json"
    raw.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "language": "python",
                        "vuln_type": "COMMAND_INJECTION",
                        "predicted_status": "likely",
                        "ground_truth": {"ground_truth_vuln": True},
                    }
                ),
                json.dumps(
                    {
                        "language": "php",
                        "vuln_type": "XSS",
                        "predicted_status": "needs-review",
                        "ground_truth": {"ground_truth_vuln": None},
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "evaluate_ai_results.py"),
            "--raw",
            str(raw),
            "--out",
            str(out),
        ],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Wrote evaluation summary" in result.stdout
    assert json.loads(out.read_text(encoding="utf-8"))["labeled_rows"] == 1

"""Tests for configured AI experiment runner."""

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ai_experiment_runner_writes_raw_results_and_summary(tmp_path):
    config = ROOT / "benchmarks" / "ai_experiments" / "e3_workflow_ablation.json"

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_ai_experiments.py"),
            "--config",
            str(config),
            "--out-dir",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )

    raw_path = tmp_path / "E3-workflow-ablation-mock.jsonl"
    summary_path = tmp_path / "E3-workflow-ablation-mock.summary.json"
    assert "Wrote raw results" in result.stdout
    assert raw_path.exists()
    assert summary_path.exists()

    rows = [json.loads(line) for line in raw_path.read_text(encoding="utf-8").splitlines()]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert len(rows) == 4
    assert summary["total_rows"] == 4
    assert set(summary["language_status_counts"]) == {"python", "javascript", "java", "php"}

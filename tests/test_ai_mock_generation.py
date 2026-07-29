"""Tests for synthetic AI mock fixture generation."""

import json
import subprocess
import sys
from pathlib import Path

from aegis_sast.ai.fixtures import load_ai_fixture_directory, load_ground_truth


ROOT = Path(__file__).resolve().parents[1]


def test_generate_ai_mock_fixtures_creates_25_valid_cases(tmp_path):
    out = tmp_path / "ai_findings"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_ai_mock_fixtures.py"),
            "--out",
            str(out),
        ],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )

    fixtures = []
    for language in ("python", "javascript", "java", "php"):
        fixtures.extend(load_ai_fixture_directory(out / language))
    truth = load_ground_truth(out / "ground_truth.jsonl")

    assert "Wrote 25 synthetic AI fixtures" in result.stdout
    assert len(fixtures) == 25
    assert len(truth) == 25
    assert {fixture.finding.language for fixture in fixtures} == {
        "python",
        "javascript",
        "java",
        "php",
    }


def test_generated_dataset_runs_through_experiment_and_evaluator(tmp_path):
    fixtures_dir = tmp_path / "ai_findings"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_ai_mock_fixtures.py"),
            "--out",
            str(fixtures_dir),
        ],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )
    config = tmp_path / "experiment.json"
    config.write_text(
        json.dumps(
            {
                "experiment_id": "synthetic-25-test",
                "fixtures": str(fixtures_dir),
                "mode": "multi-node-workflow",
                "run_count": 1,
                "prompt_version": "deterministic-node-v1",
                "knowledge_version": "cwe-cards-v1",
            }
        ),
        encoding="utf-8",
    )
    results_dir = tmp_path / "results"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_ai_experiments.py"),
            "--config",
            str(config),
            "--out-dir",
            str(results_dir),
        ],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )
    raw = results_dir / "synthetic-25-test.jsonl"
    evaluation = tmp_path / "evaluation.json"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "evaluate_ai_results.py"),
            "--raw",
            str(raw),
            "--out",
            str(evaluation),
        ],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )

    summary = json.loads(evaluation.read_text(encoding="utf-8"))
    assert summary["total_rows"] == 25
    assert summary["labeled_rows"] >= 15

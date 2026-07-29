"""Tests for AI mock-data fixture loading."""

from pathlib import Path

import pytest

from aegis_sast.ai.fixtures import (
    AIFixtureLoadError,
    load_ai_fixture,
    load_ai_fixture_directory,
    load_ground_truth,
    validate_ai_fixture_batch,
)


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "ai_findings"


def test_ai_fixture_loader_reads_valid_fixtures_without_ground_truth_leakage():
    """Mock data should validate through the same contract on all four languages."""
    fixtures = []
    for language in ("python", "javascript", "java", "php"):
        fixtures.extend(load_ai_fixture_directory(FIXTURE_ROOT / language))

    assert {fixture.finding.language for fixture in fixtures} == {
        "python",
        "javascript",
        "java",
        "php",
    }
    assert all(fixture.finding.finding_id == fixture.evidence.finding_id for fixture in fixtures)
    assert all(not hasattr(fixture, "ground_truth") for fixture in fixtures)


def test_ai_fixture_batch_reports_missing_optional_fields():
    """Batch validation should return a compact coverage report."""
    fixtures, missing_counts = validate_ai_fixture_batch(FIXTURE_ROOT / "python")

    assert len(fixtures) == 1
    assert missing_counts == {
        "benchmark_metadata": 0,
        "cwe_id": 0,
        "graph_metadata_notes": 0,
    }


def test_invalid_ai_fixture_reports_mismatched_finding_id():
    """Evidence belonging to a different finding must fail validation."""
    with pytest.raises(AIFixtureLoadError) as error:
        load_ai_fixture_directory(FIXTURE_ROOT / "invalid")

    assert "finding.finding_id must match evidence.finding_id" in str(error.value)


def test_ground_truth_is_loaded_from_jsonl_sidecar():
    """Ground truth must remain separate from AI-visible payloads."""
    truth = load_ground_truth(FIXTURE_ROOT / "ground_truth.jsonl")
    fixture = load_ai_fixture(FIXTURE_ROOT / "python" / "command_injection_tp.json")

    assert truth["PY-CMD-001"]["expected_status"] == "confirmed"
    assert fixture.benchmark is not None
    assert fixture.benchmark.ground_truth_vuln is None

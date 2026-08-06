"""Tests for OWASP BenchmarkJava scoring helpers."""

from scripts.run_owasp_benchmark_java import (
    ExpectedCase,
    build_score_rows,
    build_score_summary,
)


def test_owasp_benchmark_score_rows_and_summary():
    expected = [
        ExpectedCase("BenchmarkTest00001", "cmdi", True, "78"),
        ExpectedCase("BenchmarkTest00002", "cmdi", False, "78"),
        ExpectedCase("BenchmarkTest00003", "sqli", True, "89"),
        ExpectedCase("BenchmarkTest00004", "hash", True, "328"),
    ]
    predictions = {
        "BenchmarkTest00001": {"cmdi"},
        "BenchmarkTest00002": {"cmdi"},
        "BenchmarkTest00003": set(),
    }

    rows = build_score_rows(expected, predictions)
    summary = build_score_summary(rows, files_scanned=4, error_count=0)

    assert [row["outcome"] for row in rows] == ["TP", "FP", "FN", "FN"]
    assert summary["all_categories"]["TP"] == 1
    assert summary["all_categories"]["FP"] == 1
    assert summary["all_categories"]["FN"] == 2
    assert summary["supported_categories"]["total"] == 3
    assert summary["per_category"]["hash"]["total"] == 1

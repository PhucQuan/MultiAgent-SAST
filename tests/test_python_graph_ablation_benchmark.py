"""Tests for the synthetic Python graph ablation benchmark runner."""

from pathlib import Path

from aegis_sast.benchmarking import (
    PythonGraphAblationBenchmark,
    render_python_graph_ablation_markdown,
)


MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "synthetic"
    / "python_graph_ablation_v1_2"
    / "manifest.json"
)


def test_python_graph_ablation_benchmark_metrics_match_expected_ablation():
    """The benchmark should reflect the intended progression across modes."""
    benchmark = PythonGraphAblationBenchmark.from_manifest(MANIFEST_PATH)
    result = benchmark.run()

    by_mode = {mode.mode: mode for mode in result.modes}

    linear = by_mode["linear_taint_baseline"].metrics
    graph_no_summary = by_mode["graph_core_no_summary"].metrics
    graph_with_summary = by_mode["graph_core_with_summary"].metrics

    assert linear.tp == 2
    assert linear.fp == 4
    assert linear.fn == 0
    assert round(linear.precision, 3) == 0.333
    assert round(linear.recall, 3) == 1.000

    assert graph_no_summary.tp == 1
    assert graph_no_summary.fp == 0
    assert graph_no_summary.fn == 1
    assert round(graph_no_summary.precision, 3) == 1.000
    assert round(graph_no_summary.recall, 3) == 0.500

    assert graph_with_summary.tp == 2
    assert graph_with_summary.fp == 0
    assert graph_with_summary.fn == 0
    assert round(graph_with_summary.precision, 3) == 1.000
    assert round(graph_with_summary.recall, 3) == 1.000
    assert round(graph_with_summary.accuracy, 3) == 1.000


def test_python_graph_ablation_markdown_contains_mode_tables():
    """Markdown rendering should include mode summaries and case rows."""
    benchmark = PythonGraphAblationBenchmark.from_manifest(MANIFEST_PATH)
    result = benchmark.run()
    content = render_python_graph_ablation_markdown(result)

    assert "# Python Graph Ablation Benchmark" in content
    assert "## Mode: `linear_taint_baseline`" in content
    assert "## Mode: `graph_core_with_summary`" in content
    assert "`PY-GRAPH-005`" in content
    assert "local_summary_hits=" in content

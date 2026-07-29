"""Tests for the reviewed-bundle mini benchmark runner."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_benchmark_v1.py"
MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "benchmark"
    / "reviewed_bundle_v1"
    / "cases.json"
)
SQLI_EXTENSION_MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "benchmark"
    / "reviewed_bundle_v1"
    / "cases_sql_injection_extension.json"
)
SSRF_EXTENSION_MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "benchmark"
    / "reviewed_bundle_v1"
    / "cases_ssrf_extension.json"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("run_benchmark_v1", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_load_manifest_and_resolve_cases_find_three_python_v1_cases():
    module = _load_module()
    manifest = module.load_manifest(MANIFEST_PATH)
    cases = module.resolve_manifest_cases(manifest)

    assert manifest["schema_version"] == "aegis-reviewed-bundle-benchmark-v1"
    assert len(cases) == 3
    assert [case["family"] for case in cases] == [
        "COMMAND_INJECTION",
        "PATH_TRAVERSAL",
        "INSECURE_DESERIALIZATION",
    ]


def test_load_manifest_and_resolve_cases_find_one_sqli_extension_case():
    module = _load_module()
    manifest = module.load_manifest(SQLI_EXTENSION_MANIFEST_PATH)
    cases = module.resolve_manifest_cases(manifest)

    assert manifest["schema_version"] == "aegis-reviewed-bundle-benchmark-v1"
    assert len(cases) == 1
    assert cases[0]["case_id"] == "python-sql-injection-extension"
    assert cases[0]["family"] == "SQL_INJECTION"


def test_load_manifest_and_resolve_cases_find_one_ssrf_extension_case():
    module = _load_module()
    manifest = module.load_manifest(SSRF_EXTENSION_MANIFEST_PATH)
    cases = module.resolve_manifest_cases(manifest)

    assert manifest["schema_version"] == "aegis-reviewed-bundle-benchmark-v1"
    assert len(cases) == 1
    assert cases[0]["case_id"] == "python-ssrf-extension"
    assert cases[0]["family"] == "SSRF"


def test_aggregate_case_results_sums_case_deltas_and_families(tmp_path):
    module = _load_module()
    summary = module.aggregate_case_results(
        [
            {
                "case_id": "python-command-injection",
                "family": "COMMAND_INJECTION",
                "default_findings": 7,
                "reviewed_findings": 6,
                "finding_delta": -1,
                "unique_delta": -1,
                "default_mismatches": 0,
                "reviewed_mismatches": 0,
                "goal": "",
                "target": "examples/vulnerable_rce.py",
                "reviewed_rules": "reports/rule_review/command.legacy.yaml",
                "comparison_summary_path": "reports/benchmark/command.json",
                "default_by_sink_pattern": {},
                "reviewed_by_sink_pattern": {},
                "added_keys": [],
                "removed_keys": [],
            },
            {
                "case_id": "python-path-traversal",
                "family": "PATH_TRAVERSAL",
                "default_findings": 3,
                "reviewed_findings": 4,
                "finding_delta": 1,
                "unique_delta": 1,
                "default_mismatches": 0,
                "reviewed_mismatches": 0,
                "goal": "",
                "target": "examples/vulnerable_path_traversal.py",
                "reviewed_rules": "reports/rule_review/path.legacy.yaml",
                "comparison_summary_path": "reports/benchmark/path.json",
                "default_by_sink_pattern": {},
                "reviewed_by_sink_pattern": {},
                "added_keys": [],
                "removed_keys": [],
            },
        ],
        manifest_path=tmp_path / "cases.json",
        output_dir=tmp_path / "outputs",
    )

    aggregate = summary["aggregate"]
    assert summary["case_count"] == 2
    assert aggregate["default_findings"] == 10
    assert aggregate["reviewed_findings"] == 10
    assert aggregate["finding_delta"] == 0
    assert aggregate["unique_delta"] == 0
    assert aggregate["by_family_default"]["COMMAND_INJECTION"] == 7
    assert aggregate["by_family_reviewed"]["PATH_TRAVERSAL"] == 4


def test_render_markdown_contains_aggregate_and_case_rows(tmp_path):
    module = _load_module()
    summary = {
        "manifest_path": str(tmp_path / "cases.json"),
        "output_dir": str(tmp_path / "outputs"),
        "generated_at": "2026-07-28T22:30:00",
        "case_count": 1,
        "cases": [
            {
                "case_id": "python-insecure-deserialization",
                "family": "INSECURE_DESERIALIZATION",
                "goal": "Keep sink coverage stable.",
                "target": "examples/vulnerable_deserialization.py",
                "reviewed_rules": "reports/rule_review/insecure_deserialization_seed/demo.legacy.yaml",
                "comparison_summary_path": "reports/benchmark/deserialization.json",
                "default_findings": 3,
                "reviewed_findings": 3,
                "finding_delta": 0,
                "unique_delta": 0,
                "default_mismatches": 0,
                "reviewed_mismatches": 0,
                "default_by_sink_pattern": {},
                "reviewed_by_sink_pattern": {},
                "added_keys": [],
                "removed_keys": [],
            }
        ],
        "aggregate": {
            "default_findings": 3,
            "reviewed_findings": 3,
            "finding_delta": 0,
            "unique_delta": 0,
            "mismatch_delta": 0,
            "by_family_default": {"INSECURE_DESERIALIZATION": 3},
            "by_family_reviewed": {"INSECURE_DESERIALIZATION": 3},
            "by_case_delta": {"python-insecure-deserialization": 0},
            "by_case_unique_delta": {"python-insecure-deserialization": 0},
        },
    }

    content = module.render_markdown(summary)

    assert "# Reviewed Bundle Benchmark V1" in content
    assert "| Metric | Default | Reviewed | Delta |" in content
    assert "`python-insecure-deserialization`" in content
    assert "Keep sink coverage stable." in content

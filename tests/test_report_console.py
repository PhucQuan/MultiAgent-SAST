"""Tests for the terminal report console helper script."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "report_console.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("report_console", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_report_kind_identifies_manual_and_benchmark_shapes():
    module = _load_module()

    assert module.report_kind({"scan_metadata": {}, "findings": []}) == "manual-report"
    assert (
        module.report_kind({"schema_version": "aegis-reviewed-bundle-benchmark-result-v1"})
        == "reviewed-benchmark"
    )
    assert (
        module.report_kind({"schema_version": "aegis-semgrep-baseline-result-v1"})
        == "semgrep-baseline"
    )


def test_find_primary_report_path_prefers_known_summary_names(tmp_path):
    module = _load_module()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    benchmark_summary = run_dir / "benchmark_summary.json"
    benchmark_summary.write_text("{}", encoding="utf-8")
    fallback_manual = run_dir / "aegis_sast_report_20260730_100000.json"
    fallback_manual.write_text("{}", encoding="utf-8")

    assert module.find_primary_report_path(run_dir) == benchmark_summary


def test_resolve_report_path_last_uses_latest_run_from_selected_collection(tmp_path):
    module = _load_module()
    manual_root = tmp_path / "manual_targets"
    manual_root.mkdir()
    older = manual_root / "demo_20260730_120000"
    newer = manual_root / "demo_20260730_120001"
    older.mkdir()
    newer.mkdir()
    (older / "aegis_sast_report_20260730_120000.json").write_text(
        json.dumps({"scan_metadata": {}, "findings": []}),
        encoding="utf-8",
    )
    latest_report = newer / "aegis_sast_report_20260730_120001.json"
    latest_report.write_text(
        json.dumps({"scan_metadata": {}, "findings": []}),
        encoding="utf-8",
    )

    module.RUN_COLLECTIONS = {
        "manual-targets": manual_root,
        "reviewed-benchmark": tmp_path / "reviewed",
        "semgrep-baseline": tmp_path / "semgrep",
    }

    assert module.resolve_report_path("last", collection="manual-targets") == latest_report


def test_select_cleanup_directories_groups_manual_runs_by_prefix(tmp_path):
    module = _load_module()
    manual_root = tmp_path / "manual_targets"
    manual_root.mkdir()
    keep_demo = manual_root / "demo_20260730_120001"
    stale_demo = manual_root / "demo_20260730_120000"
    keep_other = manual_root / "other_20260730_120000"
    for path in [keep_demo, stale_demo, keep_other]:
        path.mkdir()
        (path / "aegis_sast_report_20260730_120000.json").write_text(
            json.dumps({"scan_metadata": {}, "findings": []}),
            encoding="utf-8",
        )

    module.RUN_COLLECTIONS = {
        "manual-targets": manual_root,
        "reviewed-benchmark": tmp_path / "reviewed",
        "semgrep-baseline": tmp_path / "semgrep",
    }

    stale_dirs = module.select_cleanup_directories("manual-targets", keep=1)

    assert stale_dirs == [stale_demo]


def test_print_manual_report_supports_preview_only(capsys, tmp_path):
    module = _load_module()
    report_path = tmp_path / "preview.json"
    report = {
        "scan_metadata": {
            "target": "examples/vulnerable_rce.py",
            "files_scanned": 1,
        },
        "findings": [],
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")

    module.print_report_overview(report_path, preview_only=True)
    captured = capsys.readouterr()

    assert "Preview only (--no-save)" in captured.out

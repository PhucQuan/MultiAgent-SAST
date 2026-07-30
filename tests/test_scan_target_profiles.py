"""Tests for scan_target exclusion-profile resolution."""

from pathlib import Path

from scripts.scan_target import (
    build_parser,
    resolve_emitted_formats,
    resolve_output_formats,
    resolve_scan_controls,
    select_manual_run_directories_to_cleanup,
)


def test_directory_targets_get_baseline_profile_by_default(tmp_path):
    active_profiles, exclude_dirs, exclude_globs = resolve_scan_controls(
        tmp_path,
        exclude_dirs=[],
        exclude_globs=[],
        exclude_profiles=[],
    )

    assert active_profiles == ["baseline"]
    assert ".venv" in exclude_dirs
    assert "node_modules" in exclude_dirs
    assert "*.min.js" in exclude_globs


def test_focus_profile_adds_review_noise_exclusions(tmp_path):
    active_profiles, exclude_dirs, exclude_globs = resolve_scan_controls(
        tmp_path,
        exclude_dirs=["custom_dir"],
        exclude_globs=["custom/*.snap"],
        exclude_profiles=["focus"],
    )

    assert active_profiles == ["baseline", "focus"]
    assert "tests" in exclude_dirs
    assert "benchmarks" in exclude_dirs
    assert "custom_dir" in exclude_dirs
    assert "*.spec.js" in exclude_globs
    assert "custom/*.snap" in exclude_globs


def test_file_targets_do_not_apply_default_profile():
    active_profiles, exclude_dirs, exclude_globs = resolve_scan_controls(
        Path("sample.py"),
        exclude_dirs=[],
        exclude_globs=[],
        exclude_profiles=[],
    )

    assert active_profiles == []
    assert exclude_dirs == []
    assert exclude_globs == []


def test_no_default_excludes_leaves_only_manual_profile_requests(tmp_path):
    active_profiles, exclude_dirs, exclude_globs = resolve_scan_controls(
        tmp_path,
        exclude_dirs=[],
        exclude_globs=[],
        exclude_profiles=["focus"],
        no_default_excludes=True,
    )

    assert active_profiles == ["focus"]
    assert ".venv" not in exclude_dirs
    assert "tests" in exclude_dirs


def test_parser_accepts_append_rules_option():
    parser = build_parser()
    args = parser.parse_args(
        [
            "sample.py",
            "--append-rules",
            "reports/reviewed.yaml",
            "--append-rules",
            "reports/overlay.yaml",
        ]
    )

    assert args.append_rules == [
        Path("reports/reviewed.yaml"),
        Path("reports/overlay.yaml"),
    ]


def test_resolve_output_formats_uses_artifact_profile_when_no_explicit_formats():
    assert resolve_output_formats([], "minimal") == ["json"]
    assert resolve_output_formats([], "review") == ["json", "markdown"]
    assert resolve_output_formats([], "full") == ["json", "markdown", "sarif"]


def test_resolve_output_formats_preserves_explicit_formats_and_can_force_json():
    assert resolve_output_formats(["markdown"], "full") == ["markdown"]
    assert resolve_output_formats(["markdown"], "full", ensure_json=True) == [
        "json",
        "markdown",
    ]


def test_resolve_emitted_formats_supports_terminal_only_mode():
    assert resolve_emitted_formats([], "minimal", persist_reports=False) == []
    assert resolve_emitted_formats([], "minimal", view_report=True, persist_reports=False) == [
        "json"
    ]
    assert resolve_emitted_formats(["markdown"], "full", persist_reports=False) == []


def test_select_manual_run_directories_to_cleanup_keeps_newest_runs_per_target(tmp_path):
    root = tmp_path / "manual_targets"
    root.mkdir()
    keep_one = root / "demo_20260730_120002"
    keep_two = root / "demo_20260730_120001"
    stale = root / "demo_20260730_120000"
    other = root / "other_20260730_120000"
    for path in [keep_one, keep_two, stale, other]:
        path.mkdir()

    cleaned = select_manual_run_directories_to_cleanup(
        root,
        target_prefix="demo",
        keep_last=2,
    )

    assert cleaned == [stale]
    assert keep_one.exists()
    assert keep_two.exists()
    assert other.exists()
    assert stale.exists()


def test_parser_accepts_no_save_option():
    parser = build_parser()
    args = parser.parse_args(["sample.py", "--view", "--no-save"])

    assert args.view is True
    assert args.no_save is True

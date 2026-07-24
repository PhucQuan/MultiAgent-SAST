"""Tests for scan_target exclusion-profile resolution."""

from pathlib import Path

from scripts.scan_target import resolve_scan_controls


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

#!/usr/bin/env python3
"""Package the final benchmark/demo artifacts for Ánh.

Checks that a set of required files exist, then creates a zip archive at:
    artifacts/final_artifacts_anh.zip

Required includes:
- latest benchmark score summary (JSON)
- latest benchmark score summary (Markdown)
- final benchmark runbook
- final demo integration checklist
- latest JSON/SARIF report files from the benchmark run
"""

from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
OUTPUT_ZIP = ARTIFACTS_DIR / "final_artifacts_anh.zip"

BENCHMARK_SCORE_JSON_CANDIDATES = [
    REPO_ROOT / "reports" / "artifacts_owasp" / "BenchmarkPython_core_score" / "owasp_score_summary.json",
    REPO_ROOT / "reports" / "artifacts_owasp" / "BenchmarkPython_core_score" / "owasp_score_summary.md",
]

REPORT_JSON_CANDIDATES = [
    REPO_ROOT / "reports" / "aegis_sast_report_20260822_194845.json",
    REPO_ROOT / "reports" / "aegis_sast_report_20260822_193544.json",
    REPO_ROOT / "reports" / "aegis_sast_report_20260822_191442.json",
]

REQUIRED_FILES = [
    REPO_ROOT / "BENCHMARK_RUNBOOK.md",
    REPO_ROOT / "DEMO_INTEGRATION_CHECKLIST.md",
]


def find_first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def validate_file(path: Path, label: str) -> Path:
    if not path.exists():
        raise FileNotFoundError(f"Missing required {label}: {path}")
    return path


def build_archive(entries: list[Path], archive_path: Path) -> None:
    ensure_dir(archive_path.parent)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in entries:
            if not path.exists():
                raise FileNotFoundError(f"Archive source missing: {path}")
            relative = path.relative_to(REPO_ROOT)
            zf.write(path, arcname=str(relative).replace("\\", "/"))


def main() -> int:
    print("[INFO] Preparing final benchmark/demo artifact package...")

    benchmark_json = find_first_existing(BENCHMARK_SCORE_JSON_CANDIDATES)
    if benchmark_json is None:
        raise FileNotFoundError(
            "Benchmark score JSON not found. Expected one of: "
            + ", ".join(str(p) for p in BENCHMARK_SCORE_JSON_CANDIDATES)
        )

    benchmark_md = REPO_ROOT / "reports" / "artifacts_owasp" / "BenchmarkPython_core_score" / "owasp_score_summary.md"
    if not benchmark_md.exists():
        raise FileNotFoundError(f"Benchmark score Markdown not found: {benchmark_md}")

    report_json = find_first_existing(REPORT_JSON_CANDIDATES)
    if report_json is None:
        raise FileNotFoundError(
            "Latest report JSON not found. Expected one of: "
            + ", ".join(str(p) for p in REPORT_JSON_CANDIDATES)
        )

    sarif_candidates = list((REPO_ROOT / "reports").rglob("*.sarif"))
    sarif_file = sarif_candidates[0] if sarif_candidates else None

    required_entries = [
        validate_file(p, "required file") for p in REQUIRED_FILES
    ]
    required_entries.extend([
        validate_file(benchmark_json, "benchmark JSON"),
        validate_file(benchmark_md, "benchmark Markdown"),
        validate_file(report_json, "report JSON"),
    ])

    if sarif_file is not None:
        required_entries.append(validate_file(sarif_file, "SARIF report"))
        print(f"[INFO] Found SARIF artifact: {sarif_file}")
    else:
        print("[WARN] No SARIF artifact found; continuing without it.")

    deduped_entries: list[Path] = []
    seen: set[Path] = set()
    for entry in required_entries:
        if entry not in seen:
            deduped_entries.append(entry)
            seen.add(entry)

    print("[INFO] Files to package:")
    for entry in deduped_entries:
        print(f"  - {entry.relative_to(REPO_ROOT)}")

    build_archive(deduped_entries, OUTPUT_ZIP)

    print(f"[SUCCESS] Archive created: {OUTPUT_ZIP}")
    print(f"[INFO] Archive size: {OUTPUT_ZIP.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)

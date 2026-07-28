"""Scan any local file or repository target with a concise manual wrapper.

This script is meant for day-to-day manual testing when you want to point
Aegis-SAST at an arbitrary source tree without remembering the full CLI flags.

Examples:
  python scripts/scan_target.py examples/vulnerable_sqli.py
  python scripts/scan_target.py test_projects/cross_file_app --format json --format sarif
  python scripts/scan_target.py C:\\path\\to\\repo --with-ai --output-dir reports/manual/custom
  python scripts/scan_target.py D:\\repo --exclude-dir test --exclude-dir third_party --progress-every 50
  python scripts/scan_target.py D:\\repo --exclude-profile focus --progress-every 50
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


EXCLUDE_PROFILES = {
    "baseline": {
        "description": "Skip dependency, cache, and build-output directories by default.",
        "dirs": [
            ".git",
            ".hg",
            ".svn",
            ".venv",
            "venv",
            "env",
            "node_modules",
            "vendor",
            "third_party",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".tox",
            ".nox",
            "dist",
            "build",
            "target",
            "coverage",
            ".cache",
            ".next",
            ".nuxt",
            ".parcel-cache",
            ".yarn",
            ".pnpm-store",
            "out",
            "tmp",
        ],
        "globs": [
            "*.min.js",
            "*.bundle.js",
            "*_pb2.py",
            "*.generated.*",
            "*.gen.*",
        ],
    },
    "focus": {
        "description": "Further suppress tests, benchmarks, fixtures, and generated/codegen trees.",
        "dirs": [
            "test",
            "tests",
            "testing",
            "benchmarks",
            "benchmark",
            "fixtures",
            "generated",
            "gen",
            "codegen",
            "examples",
            "samples",
        ],
        "globs": [
            "*/test_*.py",
            "*/*_test.py",
            "*.spec.js",
            "*.test.js",
            "*.snap",
            "*/conftest.py",
            "*/bench_*.py",
            "*/*_benchmark.py",
        ],
    },
}
DEFAULT_EXCLUDE_PROFILES = ("baseline",)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for manual scans."""
    parser = argparse.ArgumentParser(
        description="Manual wrapper to scan any local file or repository target.",
    )
    parser.add_argument("target", type=Path, help="File or directory to scan")
    parser.add_argument(
        "--rules",
        type=Path,
        help="Optional custom YAML/JSON rules file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for generated reports. Defaults to reports/manual_targets/<target>-<timestamp>",
    )
    parser.add_argument(
        "--format",
        action="append",
        choices=["json", "markdown", "sarif"],
        default=[],
        help="Repeatable report format selector. Defaults to json + markdown + sarif.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum analysis depth for detector-level taint tracking.",
    )
    parser.add_argument(
        "--with-ai",
        action="store_true",
        help="Enable Gemini verification if requirements-ai and GEMINI_API_KEY are available.",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Repeatable directory-name exclusion such as test, third_party, or build.",
    )
    parser.add_argument(
        "--exclude-glob",
        action="append",
        default=[],
        help="Repeatable relative-path glob exclusion such as *.min.js or docs/generated/*.",
    )
    parser.add_argument(
        "--exclude-profile",
        action="append",
        choices=sorted(EXCLUDE_PROFILES.keys()),
        default=[],
        help=(
            "Repeatable exclusion preset. Directory scans apply the conservative "
            "'baseline' profile by default unless --no-default-excludes is set."
        ),
    )
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Disable the automatic baseline exclusion profile for directory scans.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Print scan progress every N processed files when the target is a directory.",
    )
    return parser


def default_output_dir(target: Path) -> Path:
    """Build a stable default output directory for one manual scan."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = target.resolve().name if target.exists() else target.name
    safe_name = safe_name.replace(" ", "_")
    return REPO_ROOT / "reports" / "manual_targets" / f"{safe_name}_{timestamp}"


def print_analyzer_status(registry) -> None:
    """Display which analyzers are currently active."""
    enabled = set(registry.get_supported_languages())
    failures = registry.get_import_failures()

    print("Analyzer availability:")
    for language in ["python", "javascript", "java", "php"]:
        if language in enabled:
            print(f"  - {language}: enabled")
        else:
            detail = failures.get(language, "not registered")
            print(f"  - {language}: missing ({detail})")


def print_repo_profile(repo_profile) -> None:
    """Display the repo-intake summary before scanning."""
    print("Repo intake:")
    print(f"  - scan profile: {repo_profile.scan_profile}")
    print(f"  - languages: {', '.join(repo_profile.detected_languages) or 'none'}")
    print(f"  - frameworks: {', '.join(repo_profile.framework_hints) or 'none'}")

    analysis_plan = repo_profile.metadata.get("analysis_plan", {})
    if analysis_plan:
        formatted = ", ".join(
            f"{language}:{depth}" for language, depth in sorted(analysis_plan.items())
        )
    else:
        formatted = "none"
    print(f"  - analysis plan: {formatted}")


def _unique_in_order(values) -> list[str]:
    """Return a stable list while removing duplicates and empty items."""
    seen = OrderedDict()
    for value in values:
        if value and value not in seen:
            seen[value] = None
    return list(seen.keys())


def resolve_scan_controls(
    target: Path,
    exclude_dirs: list[str] | None,
    exclude_globs: list[str] | None,
    exclude_profiles: list[str] | None,
    no_default_excludes: bool = False,
) -> tuple[list[str], list[str], list[str]]:
    """Merge default/manual exclude controls into stable lists."""
    manual_dirs = list(exclude_dirs or [])
    manual_globs = list(exclude_globs or [])
    requested_profiles = list(exclude_profiles or [])

    active_profiles: list[str] = []
    if target.is_dir() and not no_default_excludes:
        active_profiles.extend(DEFAULT_EXCLUDE_PROFILES)
    active_profiles.extend(requested_profiles)
    active_profiles = _unique_in_order(active_profiles)

    resolved_dirs: list[str] = []
    resolved_globs: list[str] = []
    for profile_name in active_profiles:
        profile = EXCLUDE_PROFILES.get(profile_name, {})
        resolved_dirs.extend(profile.get("dirs", []))
        resolved_globs.extend(profile.get("globs", []))

    resolved_dirs.extend(manual_dirs)
    resolved_globs.extend(manual_globs)

    return (
        active_profiles,
        _unique_in_order(resolved_dirs),
        _unique_in_order(resolved_globs),
    )


def print_scan_controls(
    target: Path,
    active_profiles,
    exclude_dirs,
    exclude_globs,
    progress_every: int,
) -> None:
    """Display optional directory-scan controls."""
    if not target.is_dir():
        return

    print("Scan controls:")
    print(f"  - exclude profiles: {', '.join(active_profiles) or 'none'}")
    print(f"  - exclude dirs: {', '.join(exclude_dirs) or 'none'}")
    print(f"  - exclude globs: {', '.join(exclude_globs) or 'none'}")
    print(f"  - progress every: {max(progress_every, 1)} files")


def print_scan_summary(scan_result, workflow_metadata: dict | None) -> None:
    """Display a concise end-of-run summary."""
    print("Scan summary:")
    print(f"  - files scanned: {scan_result.files_scanned}")
    print(f"  - total findings: {scan_result.total_vulnerabilities}")
    print(f"  - critical: {scan_result.critical_count}")
    print(f"  - high: {scan_result.high_count}")
    print(f"  - medium: {scan_result.medium_count}")
    print(f"  - low: {scan_result.low_count}")
    print(f"  - duration: {scan_result.duration:.2f}s")

    if workflow_metadata:
        triage_summary = workflow_metadata.get("triage_summary", {})
        route_summary = workflow_metadata.get("route_summary", {})
        print("Workflow summary:")
        print(
            "  - triage: "
            + ", ".join(
                f"{status}={triage_summary.get(status, 0)}"
                for status in ["confirmed", "likely", "needs-review", "suppressed"]
            )
        )
        if route_summary:
            print(
                "  - routes: "
                + ", ".join(
                    f"{route_id}={count}"
                    for route_id, count in sorted(route_summary.items())
                )
            )


async def verify_with_ai(ai_client, scan_result) -> None:
    """Run Gemini verification for all findings."""
    tasks = []
    for vulnerability in scan_result.vulnerabilities:
        tasks.append(
            ai_client.async_verify_vulnerability(
                vuln_type=vulnerability.vuln_type,
                source_code=vulnerability.dataflow.source.location.code_snippet,
                dataflow_path=vulnerability.dataflow.get_path_summary(),
                sink_code=vulnerability.dataflow.sink.location.code_snippet,
            )
        )

    results = await asyncio.gather(*tasks)
    for index, result in enumerate(results):
        scan_result.vulnerabilities[index].ai_verification = result


def export_reports(output_dir: Path, formats, scan_result, triage_records, workflow_metadata) -> list[Path]:
    """Export the requested report formats and return written paths."""
    from aegis_sast.integrations import SARIFFormatter
    from aegis_sast.reporting.json_exporter import JSONExporter
    from aegis_sast.reporting.markdown_exporter import MarkdownExporter

    written: list[Path] = []
    if "json" in formats:
        written.append(
            JSONExporter(output_dir).export(
                scan_result,
                triage_records=triage_records,
                workflow_metadata=workflow_metadata,
            )
        )
    if "markdown" in formats:
        written.append(
            MarkdownExporter(output_dir).export(
                scan_result,
                triage_records=triage_records,
                workflow_metadata=workflow_metadata,
            )
        )
    if "sarif" in formats:
        written.append(
            SARIFFormatter(output_dir).export(
                scan_result,
                triage_records=triage_records,
                workflow_metadata=workflow_metadata,
            )
        )
    return written


def print_progress_update(update: dict) -> None:
    """Render lightweight progress updates for large manual scans."""
    event = update.get("event")
    total_files = update.get("total_files", 0)
    files_processed = update.get("files_processed", 0)
    findings = update.get("findings", 0)
    errors = update.get("errors", 0)

    if event == "index-start":
        print(f"Progress: building Python index for {total_files} candidate files...")
        return

    if event == "index-complete":
        print(
            "Progress: Python index ready "
            f"({update.get('indexed_functions', 0)} functions indexed)"
        )
        return

    if event == "scan-start":
        print(f"Progress: scanning {total_files} candidate files...")
        return

    if event == "progress":
        current_file = update.get("current_file")
        suffix = f" | current={current_file}" if current_file else ""
        print(
            "Progress: "
            f"{files_processed}/{total_files} files"
            f" | findings={findings}"
            f" | errors={errors}{suffix}"
        )
        return

    if event == "complete":
        print(
            "Progress: complete "
            f"({files_processed}/{total_files} files"
            f", findings={findings}, errors={errors})"
        )


def run_manual_scan(
    *,
    target: Path,
    custom_rules_path: Path | None = None,
    output_dir: Path | None = None,
    formats: list[str] | None = None,
    max_depth: int = 5,
    with_ai: bool = False,
    exclude_dirs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    exclude_profiles: list[str] | None = None,
    no_default_excludes: bool = False,
    progress_every: int = 100,
    progress_callback=None,
    emit_console: bool = False,
) -> dict[str, Any]:
    """Run one manual scan and return reusable artifacts for other scripts."""
    target = target.resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")

    if custom_rules_path is not None:
        custom_rules_path = custom_rules_path.resolve()
        if not custom_rules_path.exists():
            raise FileNotFoundError(f"Rules file does not exist: {custom_rules_path}")

    try:
        from aegis_sast.analysis.rule_engine import RuleEngine
        from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector
        from aegis_sast.core.config import get_config, set_config
        from aegis_sast.core.models import ScanResult
        from aegis_sast.core.registry import get_registry
        from aegis_sast.knowledge import KnowledgeLoader
        from aegis_sast.orchestration import RepoIntake, ScanWorkflow
    except ModuleNotFoundError as exc:  # pragma: no cover - runtime environment dependent
        raise RuntimeError(f"missing runtime dependency: {exc}") from exc

    config = get_config()
    config.enable_ai_verification = with_ai
    config.max_analysis_depth = max_depth
    config.output_formats = formats or ["json", "markdown", "sarif"]
    config.output_dir = output_dir or default_output_dir(target)
    config.custom_rules_path = custom_rules_path
    set_config(config)

    registry = get_registry()
    repo_profile = RepoIntake(registry).analyze_target(target)
    active_profiles, resolved_exclude_dirs, resolved_exclude_globs = resolve_scan_controls(
        target,
        exclude_dirs or [],
        exclude_globs or [],
        exclude_profiles or [],
        no_default_excludes=no_default_excludes,
    )

    if emit_console:
        print_analyzer_status(registry)
        print_repo_profile(repo_profile)
        print_scan_controls(
            target,
            active_profiles,
            resolved_exclude_dirs,
            resolved_exclude_globs,
            progress_every,
        )

    detector = VulnerabilityDetector(RuleEngine(config.custom_rules_path), max_depth)
    selected_progress_callback = progress_callback
    if selected_progress_callback is None and emit_console:
        selected_progress_callback = print_progress_update

    if target.is_dir():
        scan_result = detector.analyze_directory(
            target,
            exclude_dir_names=resolved_exclude_dirs,
            exclude_globs=resolved_exclude_globs,
            progress_callback=selected_progress_callback,
            progress_every=progress_every,
        )
    else:
        vulnerabilities = detector.analyze_file(target)
        scan_result = ScanResult(
            target_path=str(target),
            start_time=datetime.now(),
            end_time=datetime.now(),
            vulnerabilities=vulnerabilities,
            files_scanned=1,
        )

    if with_ai and scan_result.vulnerabilities:
        try:
            from aegis_sast.llm import GeminiClient

            asyncio.run(verify_with_ai(GeminiClient(), scan_result))
        except Exception as exc:  # pragma: no cover - runtime environment dependent
            if emit_console:
                print(f"[warn] AI verification unavailable: {exc}")
                print("[warn] continuing with deterministic findings only")

    triage_records = []
    workflow_metadata = None
    if scan_result.vulnerabilities:
        workflow_state = ScanWorkflow(KnowledgeLoader()).run(
            scan_result,
            repo_profile=repo_profile,
        )
        triage_records = workflow_state.triage_records
        workflow_metadata = workflow_state.metadata

    written_reports = export_reports(
        config.output_dir,
        config.output_formats,
        scan_result,
        triage_records,
        workflow_metadata,
    )

    if emit_console:
        print_scan_summary(scan_result, workflow_metadata)
        print("Reports:")
        for path in written_reports:
            print(f"  - {path}")
        if scan_result.errors:
            print("Errors:")
            for error in scan_result.errors:
                print(f"  - {error}")

    return {
        "config": config,
        "registry": registry,
        "repo_profile": repo_profile,
        "active_profiles": active_profiles,
        "exclude_dirs": resolved_exclude_dirs,
        "exclude_globs": resolved_exclude_globs,
        "scan_result": scan_result,
        "triage_records": triage_records,
        "workflow_metadata": workflow_metadata,
        "written_reports": written_reports,
    }


def main() -> int:
    """Run a manual scan for any local target."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        run_manual_scan(
            target=args.target,
            custom_rules_path=args.rules,
            output_dir=args.output_dir,
            formats=args.format or ["json", "markdown", "sarif"],
            max_depth=args.max_depth,
            with_ai=args.with_ai,
            exclude_dirs=args.exclude_dir,
            exclude_globs=args.exclude_glob,
            exclude_profiles=args.exclude_profile,
            no_default_excludes=args.no_default_excludes,
            progress_every=args.progress_every,
            emit_console=True,
        )
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except RuntimeError as exc:
        print(f"[error] {exc}")
        print("Run `python scripts/doctor_env.py` and install requirements.txt first.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

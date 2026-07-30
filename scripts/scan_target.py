"""Scan any local file or repository target with a concise manual wrapper.

This script is meant for day-to-day manual testing when you want to point
Aegis-SAST at an arbitrary source tree without remembering the full CLI flags.

Examples:
  python scripts/scan_target.py examples/vulnerable_sqli.py
  python scripts/scan_target.py test_projects/cross_file_app --format json --format sarif
  python scripts/scan_target.py C:\\path\\to\\repo --with-ai --output-dir reports/manual/custom
  python scripts/scan_target.py D:\\repo --exclude-dir test --exclude-dir third_party --progress-every 50
  python scripts/scan_target.py D:\\repo --exclude-profile focus --progress-every 50
  python scripts/scan_target.py examples/vulnerable_rce.py --append-rules reports/rule_review/command_injection_seed/python_command_injection_semgrep_shape.legacy.yaml
  python scripts/scan_target.py examples/vulnerable_rce.py --view --keep-last 2
  python scripts/scan_target.py examples/vulnerable_rce.py --view --no-save
"""

from __future__ import annotations

import argparse
import asyncio
import re
import shutil
import sys
import tempfile
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
ARTIFACT_PROFILES = {
    "minimal": ["json"],
    "review": ["json", "markdown"],
    "full": ["json", "markdown", "sarif"],
}
TIMESTAMPED_RUN_RE = re.compile(r"^(?P<prefix>.+)_\d{8}_\d{6}$")


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for manual scans."""
    parser = argparse.ArgumentParser(
        description="Manual wrapper to scan any local file or repository target.",
    )
    parser.add_argument("target", type=Path, help="File or directory to scan")
    parser.add_argument(
        "--rules",
        type=Path,
        help="Optional custom YAML/JSON rules file that replaces the built-in rule set",
    )
    parser.add_argument(
        "--append-rules",
        action="append",
        default=[],
        type=Path,
        help=(
            "Optional YAML/JSON rules file to merge on top of the built-in rule set. "
            "Use this for reviewed/imported coverage bundles."
        ),
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
        help="Repeatable report format selector. Overrides --artifact-profile when set.",
    )
    parser.add_argument(
        "--artifact-profile",
        choices=sorted(ARTIFACT_PROFILES.keys()),
        default="minimal",
        help=(
            "Preset report bundle for manual scans: minimal=json, "
            "review=json+markdown, full=json+markdown+sarif."
        ),
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
    parser.add_argument(
        "--keep-last",
        type=int,
        default=0,
        help=(
            "When greater than zero, keep only the newest N report directories for the "
            "same target prefix under the current output parent."
        ),
    )
    parser.add_argument(
        "--view",
        action="store_true",
        help="Render the generated JSON report in the terminal after the scan finishes.",
    )
    parser.add_argument(
        "--view-limit",
        type=int,
        default=8,
        help="Maximum number of findings to show when --view is enabled.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not keep report artifacts on disk. Useful for terminal-only demo scans.",
    )
    return parser


def default_output_dir(target: Path) -> Path:
    """Build a stable default output directory for one manual scan."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return REPO_ROOT / "reports" / "manual_targets" / f"{manual_run_prefix(target)}_{timestamp}"


def manual_run_prefix(target: Path) -> str:
    """Return the stable manual-report prefix for one target path."""
    safe_name = target.resolve().name if target.exists() else target.name
    return safe_name.replace(" ", "_")


def resolve_output_formats(
    formats: list[str] | None,
    artifact_profile: str,
    *,
    ensure_json: bool = False,
) -> list[str]:
    """Resolve explicit formats or one artifact-profile preset into a stable list."""
    resolved = list(formats or [])
    if not resolved:
        resolved = list(ARTIFACT_PROFILES[artifact_profile])

    ordered: list[str] = []
    if ensure_json and "json" not in resolved:
        resolved = ["json", *resolved]

    for format_name in resolved:
        if format_name not in ordered:
            ordered.append(format_name)
    return ordered


def resolve_emitted_formats(
    formats: list[str] | None,
    artifact_profile: str,
    *,
    view_report: bool = False,
    persist_reports: bool = True,
) -> list[str]:
    """Resolve which report artifacts should actually be emitted for this run."""
    if not persist_reports:
        return ["json"] if view_report else []
    return resolve_output_formats(
        formats,
        artifact_profile,
        ensure_json=view_report,
    )


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


def print_rule_controls(
    custom_rules_path: Path | None,
    append_rules_paths: list[Path],
) -> None:
    """Display how the current scan will source its rule set."""
    print("Rule controls:")
    print(f"  - replace rules: {custom_rules_path or 'none'}")
    print(
        "  - append rules: "
        + (", ".join(str(path) for path in append_rules_paths) or "none")
    )


def print_artifact_controls(
    output_formats: list[str],
    keep_last: int,
    view_report: bool,
    persist_reports: bool,
) -> None:
    """Display how report artifacts will be emitted and retained."""
    print("Artifact controls:")
    print(f"  - output formats: {', '.join(output_formats) or 'none'}")
    print(f"  - persist reports: {'yes' if persist_reports else 'no (--no-save)'}")
    print(f"  - keep last runs: {keep_last if keep_last > 0 else 'all'}")
    print(f"  - terminal viewer: {'enabled' if view_report else 'disabled'}")


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


def select_report_path(paths: list[Path], suffix: str) -> Path:
    """Return the written artifact matching one suffix."""
    for path in paths:
        if path.suffix.lower() == suffix.lower():
            return path
    raise FileNotFoundError(f"Could not find a {suffix} report in the written artifacts.")


def cleanup_manual_run_directories(
    parent_dir: Path,
    *,
    target_prefix: str,
    keep_last: int,
) -> list[Path]:
    """Delete older timestamped manual-run directories for one target prefix."""
    stale_dirs = select_manual_run_directories_to_cleanup(
        parent_dir,
        target_prefix=target_prefix,
        keep_last=keep_last,
    )
    parent_dir = parent_dir.resolve()
    if stale_dirs and not str(parent_dir).startswith(str(REPO_ROOT.resolve())):
        raise ValueError(f"Refusing to clean reports outside the workspace: {parent_dir}")
    for stale_dir in stale_dirs:
        shutil.rmtree(stale_dir)
    return stale_dirs


def select_manual_run_directories_to_cleanup(
    parent_dir: Path,
    *,
    target_prefix: str,
    keep_last: int,
) -> list[Path]:
    """Return older timestamped manual-run directories for one target prefix."""
    if keep_last <= 0 or not parent_dir.exists():
        return []

    parent_dir = parent_dir.resolve()
    candidate_dirs: list[Path] = []
    for child in parent_dir.iterdir():
        if not child.is_dir():
            continue
        match = TIMESTAMPED_RUN_RE.match(child.name)
        if not match or match.group("prefix") != target_prefix:
            continue
        candidate_dirs.append(child)

    candidate_dirs.sort(
        key=lambda path: (path.stat().st_mtime, path.name),
        reverse=True,
    )
    return candidate_dirs[keep_last:]


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
    append_rules_paths: list[Path] | None = None,
    output_dir: Path | None = None,
    formats: list[str] | None = None,
    artifact_profile: str = "full",
    max_depth: int = 5,
    with_ai: bool = False,
    exclude_dirs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    exclude_profiles: list[str] | None = None,
    no_default_excludes: bool = False,
    progress_every: int = 100,
    keep_last: int = 0,
    view_report: bool = False,
    view_limit: int = 8,
    persist_reports: bool = True,
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
    resolved_append_rules: list[Path] = []
    for append_path in append_rules_paths or []:
        resolved_path = append_path.resolve()
        if not resolved_path.exists():
            raise FileNotFoundError(f"Rules file does not exist: {resolved_path}")
        resolved_append_rules.append(resolved_path)

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
    config.output_formats = resolve_emitted_formats(
        formats,
        artifact_profile,
        view_report=view_report,
        persist_reports=persist_reports,
    )
    default_dir = output_dir or default_output_dir(target)
    temp_report_dir: tempfile.TemporaryDirectory[str] | None = None
    if persist_reports:
        config.output_dir = default_dir
    else:
        temp_report_dir = tempfile.TemporaryDirectory(prefix="aegis-sast-console-")
        config.output_dir = Path(temp_report_dir.name)
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
        print_rule_controls(custom_rules_path, resolved_append_rules)
        print_artifact_controls(
            config.output_formats,
            keep_last,
            view_report,
            persist_reports,
        )

    detector = VulnerabilityDetector(
        RuleEngine(
            config.custom_rules_path,
            extra_rules_paths=resolved_append_rules,
        ),
        max_depth,
    )
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

    try:
        written_reports = export_reports(
            config.output_dir,
            config.output_formats,
            scan_result,
            triage_records,
            workflow_metadata,
        )

        cleaned_run_dirs: list[Path] = []
        if persist_reports:
            cleaned_run_dirs = cleanup_manual_run_directories(
                config.output_dir.parent,
                target_prefix=manual_run_prefix(target),
                keep_last=keep_last,
            )

        if emit_console:
            print_scan_summary(scan_result, workflow_metadata)
            if persist_reports:
                print("Reports:")
                for path in written_reports:
                    print(f"  - {path}")
            else:
                print("Reports:")
                print("  - not saved (--no-save)")
            if cleaned_run_dirs:
                print("Cleaned old runs:")
                for path in cleaned_run_dirs:
                    print(f"  - {path}")
            if scan_result.errors:
                print("Errors:")
                for error in scan_result.errors:
                    print(f"  - {error}")
            if view_report and written_reports:
                try:
                    from report_console import print_report_overview  # noqa: PLC0415

                    print()
                    print_report_overview(
                        select_report_path(written_reports, ".json"),
                        max_findings=view_limit,
                        preview_only=not persist_reports,
                    )
                except Exception as exc:  # pragma: no cover - terminal-view dependency dependent
                    print(f"[warn] Terminal report viewer unavailable: {exc}")

        return {
            "config": config,
            "registry": registry,
            "repo_profile": repo_profile,
            "active_profiles": active_profiles,
            "exclude_dirs": resolved_exclude_dirs,
            "exclude_globs": resolved_exclude_globs,
            "append_rules_paths": resolved_append_rules,
            "scan_result": scan_result,
            "triage_records": triage_records,
            "workflow_metadata": workflow_metadata,
            "written_reports": written_reports,
            "cleaned_run_dirs": cleaned_run_dirs,
            "persist_reports": persist_reports,
        }
    finally:
        if temp_report_dir is not None:
            temp_report_dir.cleanup()


def main() -> int:
    """Run a manual scan for any local target."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        run_manual_scan(
            target=args.target,
            custom_rules_path=args.rules,
            append_rules_paths=args.append_rules,
            output_dir=args.output_dir,
            formats=args.format,
            artifact_profile=args.artifact_profile,
            max_depth=args.max_depth,
            with_ai=args.with_ai,
            exclude_dirs=args.exclude_dir,
            exclude_globs=args.exclude_glob,
            exclude_profiles=args.exclude_profile,
            no_default_excludes=args.no_default_excludes,
            progress_every=args.progress_every,
            keep_last=args.keep_last,
            view_report=args.view,
            view_limit=args.view_limit,
            persist_reports=not args.no_save,
            emit_console=True,
        )
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except RuntimeError as exc:
        print(f"[error] {exc}")
        print("Environment check: python scripts/doctor_env.py")
        print("Install dependencies: pip install -r requirements.txt")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

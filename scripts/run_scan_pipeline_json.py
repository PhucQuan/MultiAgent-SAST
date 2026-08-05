"""Run ScanPipelineService from JSON input and emit one machine-readable result."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
REPORTS_ROOT = REPO_ROOT / "reports"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.orchestration import ScanPipelineRequest, ScanPipelineService


DEFAULT_EXCLUDE_DIRS = [
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
]
DEFAULT_EXCLUDE_GLOBS = [
    "*.min.js",
    "*.bundle.js",
    "*_pb2.py",
    "*.generated.*",
    "*.gen.*",
]


def build_parser() -> argparse.ArgumentParser:
    """Create the parser for the JSON bridge."""
    parser = argparse.ArgumentParser(
        description="Run the reusable Aegis scan pipeline and print JSON.",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read the JSON payload from stdin.",
    )
    parser.add_argument(
        "--payload",
        help="Optional inline JSON payload when stdin is not used.",
    )
    parser.add_argument(
        "--stream-progress",
        action="store_true",
        help="Emit NDJSON progress events before the final result payload.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Emit detector progress every N processed files.",
    )
    return parser


def _load_payload(args: argparse.Namespace) -> dict[str, Any]:
    """Load one JSON request payload from stdin or an inline flag."""
    if args.stdin:
        raw = sys.stdin.read()
    elif args.payload:
        raw = args.payload
    else:
        raise ValueError("A JSON payload is required via --stdin or --payload.")

    payload = json.loads(raw or "{}")
    if not isinstance(payload, dict):
        raise ValueError("Scan payload must be a JSON object.")
    return payload


def _resolve_path(raw_path: str | None) -> Path | None:
    """Resolve a local path relative to the repo root when needed."""
    if raw_path is None:
        return None

    candidate = Path(str(raw_path).strip()).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (REPO_ROOT / candidate).resolve()


def _safe_target_name(target_path: Path) -> str:
    """Return a filesystem-safe stem for report directories."""
    return "".join(
        character if character.isalnum() or character in {"-", "_"} else "_"
        for character in target_path.name
    ) or "scan_target"


def _default_output_dir(target_path: Path) -> Path:
    """Place dashboard-triggered scans under one dedicated reports subtree."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return REPORTS_ROOT / "dashboard_runs" / f"{_safe_target_name(target_path)}_{timestamp}"


def _normalize_output_formats(values: Any) -> list[str]:
    """Return a stable output-format list and always keep JSON for the dashboard."""
    if isinstance(values, list):
        requested = [str(value).strip().lower() for value in values if str(value).strip()]
    else:
        requested = ["json", "markdown"]

    if "json" not in requested:
        requested.insert(0, "json")

    deduped: list[str] = []
    for value in requested:
        if value not in deduped:
            deduped.append(value)
    return deduped


def build_request(payload: dict[str, Any]) -> ScanPipelineRequest:
    """Convert one JSON object into a typed scan pipeline request."""
    target_value = str(payload.get("targetPath", "")).strip()
    if not target_value:
        raise ValueError("targetPath is required.")

    target_path = _resolve_path(target_value)
    if target_path is None or not target_path.exists():
        raise FileNotFoundError(f"Target does not exist: {target_value}")

    rules_path = _resolve_path(payload.get("rulesPath"))
    append_rules = [
        resolved
        for resolved in (
            _resolve_path(path_value)
            for path_value in payload.get("appendRulesPaths", [])
            if isinstance(path_value, str) and path_value.strip()
        )
        if resolved is not None
    ]

    output_dir = _resolve_path(payload.get("outputDir")) or _default_output_dir(target_path)
    enable_ai = bool(payload.get("enableAi", False))
    max_depth = max(1, min(int(payload.get("maxDepth", 5) or 5), 20))

    exclude_dir_names = payload.get("excludeDirNames")
    if isinstance(exclude_dir_names, list):
        resolved_exclude_dirs = [str(value) for value in exclude_dir_names]
    elif target_path.is_dir():
        resolved_exclude_dirs = list(DEFAULT_EXCLUDE_DIRS)
    else:
        resolved_exclude_dirs = []

    exclude_globs = payload.get("excludeGlobs")
    if isinstance(exclude_globs, list):
        resolved_exclude_globs = [str(value) for value in exclude_globs]
    elif target_path.is_dir():
        resolved_exclude_globs = list(DEFAULT_EXCLUDE_GLOBS)
    else:
        resolved_exclude_globs = []

    return ScanPipelineRequest(
        target_path=target_path,
        rules_path=rules_path,
        append_rules_paths=append_rules,
        enable_ai_verification=enable_ai,
        max_analysis_depth=max_depth,
        exclude_dir_names=resolved_exclude_dirs,
        exclude_globs=resolved_exclude_globs,
        output_formats=_normalize_output_formats(payload.get("outputFormats")),
        output_dir=output_dir,
        export_reports=True,
    )


def _relative_report_path(report_path: Path) -> str | None:
    """Return the path relative to reports/ so the dashboard can reopen it."""
    try:
        return report_path.resolve().relative_to(REPORTS_ROOT.resolve()).as_posix()
    except ValueError:
        return None


def _serialize_repo_profile(repo_profile) -> dict[str, Any]:
    """Convert RepoProfile into a JSON-friendly payload."""
    return {
        "targetPath": repo_profile.target_path,
        "scanProfile": repo_profile.scan_profile,
        "detectedLanguages": repo_profile.detected_languages,
        "frameworkHints": repo_profile.framework_hints,
        "filesScanned": repo_profile.files_scanned,
        "metadata": repo_profile.metadata,
    }


def serialize_result(result) -> dict[str, Any]:
    """Convert ScanPipelineResult into one stable API payload."""
    reports: dict[str, dict[str, Any]] = {}
    selected_report_path = None

    for format_name, output_path in result.exported_reports.items():
        relative_path = _relative_report_path(output_path)
        reports[format_name] = {
            "path": str(output_path),
            "sourcePath": relative_path,
        }
        if format_name == "json":
            selected_report_path = relative_path

    return {
        "request": {
            "targetPath": str(result.request.target_path),
            "enableAi": result.request.enable_ai_verification,
            "maxDepth": result.request.max_analysis_depth,
            "excludeDirNames": result.request.exclude_dir_names,
            "excludeGlobs": result.request.exclude_globs,
            "outputDir": str(result.request.output_dir),
            "outputFormats": result.request.output_formats,
        },
        "repoProfile": _serialize_repo_profile(result.repo_profile),
        "summary": result.scan_result.get_summary(),
        "workflowSummary": result.workflow_metadata,
        "supportedLanguages": result.supported_languages,
        "importFailures": result.import_failures,
        "reports": reports,
        "selectedReportPath": selected_report_path,
        "ai": {
            "requested": result.ai_requested,
            "enabled": result.ai_enabled,
            "error": result.ai_error,
        },
        "exitCode": result.exit_code,
    }


def _emit_ndjson(payload: dict[str, Any]) -> None:
    """Write one JSON line so the dashboard bridge can stream updates."""
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for the dashboard-to-Python bridge."""
    args = build_parser().parse_args(argv)

    try:
        progress_every = max(int(args.progress_every or 100), 1)
        payload = _load_payload(args)
        if args.stream_progress:
            _emit_ndjson(
                {
                    "type": "progress",
                    "payload": {
                        "event": "stage",
                        "stage": "request",
                        "message": "Starting local scan pipeline.",
                    },
                }
            )
        request = build_request(payload)
        progress_callback = None
        if args.stream_progress:
            progress_callback = (
                lambda update: _emit_ndjson(
                    {
                        "type": "progress",
                        "payload": update,
                    }
                )
            )
        result = ScanPipelineService().run(
            request,
            progress_callback=progress_callback,
            progress_every=progress_every,
        )
        response_payload = {"ok": True, "scan": serialize_result(result)}
        if args.stream_progress:
            _emit_ndjson({"type": "result", **response_payload})
        else:
            print(json.dumps(response_payload, ensure_ascii=False))
        return 0
    except Exception as exc:
        response_payload = {"ok": False, "error": str(exc)}
        if args.stream_progress:
            _emit_ndjson({"type": "result", **response_payload})
        else:
            print(json.dumps(response_payload, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

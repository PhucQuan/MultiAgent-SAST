"""Run a minimal Semgrep baseline across the reviewed Python benchmark suite.

Examples:
  python scripts/run_semgrep_baseline.py
  python scripts/run_semgrep_baseline.py --case python-command-injection
  python scripts/run_semgrep_baseline.py --manifest datasets/benchmark/reviewed_bundle_v1/cases_python_reviewed_suite.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


DEFAULT_MANIFEST_CANDIDATES = [
    REPO_ROOT
    / "datasets"
    / "benchmark"
    / "reviewed_bundle_v1"
    / "cases_python_reviewed_suite.json",
    REPO_ROOT / "datasets" / "benchmark" / "reviewed_bundle_v1" / "cases.json",
]

DEFAULT_SEMGREP_CONFIGS = {
    "COMMAND_INJECTION": REPO_ROOT
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_command_injection_semgrep_shape.yaml",
    "PATH_TRAVERSAL": REPO_ROOT
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_path_traversal_semgrep_shape.yaml",
    "INSECURE_DESERIALIZATION": REPO_ROOT
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_insecure_deserialization_semgrep_shape.yaml",
    "SQL_INJECTION": REPO_ROOT
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_sql_injection_semgrep_shape.yaml",
    "SSRF": REPO_ROOT
    / "datasets"
    / "synthetic"
    / "rule_review_v1"
    / "seed_inputs"
    / "python_ssrf_semgrep_shape.yaml",
}


def default_manifest_path() -> Path:
    """Pick the most complete checked-in reviewed-bundle manifest available."""
    for candidate in DEFAULT_MANIFEST_CANDIDATES:
        if candidate.exists():
            return candidate
    return DEFAULT_MANIFEST_CANDIDATES[0]


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Run a minimal Semgrep baseline over the same reviewed-bundle "
            "benchmark cases used by the Python V1 suite."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=default_manifest_path(),
        help="Path to the reviewed-bundle benchmark manifest.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "Root directory for Semgrep baseline artifacts. Defaults to "
            "reports/benchmark/semgrep_baseline_v1/<timestamp>."
        ),
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Optional repeatable case_id filter.",
    )
    parser.add_argument(
        "--semgrep-bin",
        help=(
            "Optional explicit Semgrep executable or wrapper path. "
            "If omitted, the runner tries `semgrep` and then `python -m semgrep`."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Per-case subprocess timeout in seconds.",
    )
    return parser


def default_output_dir() -> Path:
    """Build a stable output directory for one baseline run."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return REPO_ROOT / "reports" / "benchmark" / "semgrep_baseline_v1" / timestamp


def load_manifest(path: Path) -> dict[str, Any]:
    """Load the reviewed-bundle benchmark manifest."""
    if not path.exists():
        raise FileNotFoundError(f"Benchmark manifest does not exist: {path}")

    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "aegis-reviewed-bundle-benchmark-v1":
        raise ValueError(
            "Expected schema_version 'aegis-reviewed-bundle-benchmark-v1' in the manifest."
        )
    if not isinstance(payload.get("cases"), list):
        raise ValueError("Benchmark manifest must contain a top-level 'cases' list.")
    return payload


def resolve_manifest_cases(
    manifest: dict[str, Any],
    *,
    selected_case_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Resolve target paths and Semgrep config paths for selected cases."""
    selected = {case_id.strip() for case_id in (selected_case_ids or []) if case_id.strip()}
    resolved_cases: list[dict[str, Any]] = []

    for item in manifest.get("cases", []):
        if not isinstance(item, dict):
            raise ValueError("Each benchmark case must be a mapping.")

        case_id = item.get("case_id")
        family = item.get("family")
        target = item.get("target")
        semgrep_config_value = item.get("semgrep_config")

        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("Each benchmark case must define a non-empty string case_id.")
        if selected and case_id not in selected:
            continue
        if not isinstance(family, str) or not family.strip():
            raise ValueError(f"Benchmark case {case_id!r} is missing a valid family.")
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"Benchmark case {case_id!r} is missing a valid target.")

        if semgrep_config_value is not None and (
            not isinstance(semgrep_config_value, str) or not semgrep_config_value.strip()
        ):
            raise ValueError(
                f"Benchmark case {case_id!r} has an invalid semgrep_config value."
            )

        default_config = DEFAULT_SEMGREP_CONFIGS.get(family)
        semgrep_config = (
            (REPO_ROOT / semgrep_config_value).resolve()
            if isinstance(semgrep_config_value, str) and semgrep_config_value.strip()
            else default_config
        )
        if semgrep_config is None:
            raise ValueError(
                f"Benchmark case {case_id!r} has no Semgrep config mapping for family {family!r}."
            )

        resolved_cases.append(
            {
                "case_id": case_id,
                "family": family,
                "target": (REPO_ROOT / target).resolve(),
                "semgrep_config": semgrep_config.resolve(),
                "goal": item.get("goal", ""),
            }
        )

    if selected and not resolved_cases:
        raise ValueError("No benchmark cases matched the requested --case filters.")

    return resolved_cases


def candidate_semgrep_commands(explicit_bin: str | None = None) -> list[list[str]]:
    """Return candidate command prefixes that may launch Semgrep."""
    commands: list[list[str]] = []
    if explicit_bin:
        commands.append([explicit_bin])
    else:
        discovered = shutil.which("semgrep")
        if discovered:
            commands.append([discovered])
        commands.append([sys.executable, "-m", "semgrep"])

    ordered: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for command in commands:
        key = tuple(command)
        if key not in seen:
            seen.add(key)
            ordered.append(command)
    return ordered


def discover_semgrep_command(explicit_bin: str | None = None) -> list[str]:
    """Pick the first Semgrep command prefix that responds to `--version`."""
    failures: list[str] = []

    for command in candidate_semgrep_commands(explicit_bin):
        try:
            result = subprocess.run(
                [*command, "--version"],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except FileNotFoundError:
            failures.append(f"{' '.join(command)}: not found")
            continue
        except subprocess.TimeoutExpired:
            failures.append(f"{' '.join(command)}: version check timed out")
            continue

        if result.returncode == 0:
            return command

        stderr = _decode_subprocess_output(result.stderr).strip()
        stdout = _decode_subprocess_output(result.stdout).strip()
        detail = stderr or stdout or f"exit {result.returncode}"
        failures.append(f"{' '.join(command)}: {detail}")

    raise RuntimeError(
        "Semgrep is not available in the current environment. "
        + " | ".join(failures)
    )


def summarize_semgrep_report(report: dict[str, Any], report_path: Path) -> dict[str, Any]:
    """Extract high-signal counters from one Semgrep JSON report."""
    results = report.get("results", [])
    errors = report.get("errors", [])
    by_check_id = Counter()
    by_severity = Counter()
    by_path = Counter()

    for finding in results:
        check_id = finding.get("check_id") or "UNKNOWN"
        severity = ((finding.get("extra") or {}).get("severity") or "UNKNOWN").upper()
        finding_path = finding.get("path") or "UNKNOWN"
        by_check_id[check_id] += 1
        by_severity[severity] += 1
        by_path[finding_path] += 1

    scanned_paths = _extract_scanned_paths(report)
    files_scanned = len(scanned_paths) if scanned_paths else len(by_path)

    return {
        "path": str(report_path),
        "result_count": len(results),
        "error_count": len(errors),
        "files_scanned": files_scanned,
        "by_check_id": dict(by_check_id),
        "by_severity": dict(by_severity),
        "by_path": dict(by_path),
    }


def _extract_scanned_paths(report: dict[str, Any]) -> list[str]:
    """Return scanned paths when Semgrep reports them explicitly."""
    paths = report.get("paths", {})
    if isinstance(paths, dict):
        scanned = paths.get("scanned")
        if isinstance(scanned, list):
            return [str(item) for item in scanned]
    return []


def _decode_subprocess_output(payload: bytes | str | None) -> str:
    """Decode subprocess output conservatively for Windows console safety."""
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    return payload.decode("utf-8", errors="replace")


def run_benchmark_case(
    *,
    case: dict[str, Any],
    output_root: Path,
    semgrep_command: list[str],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run Semgrep on one benchmark case and summarize the JSON output."""
    target = case["target"]
    semgrep_config = case["semgrep_config"]

    if not target.exists():
        raise FileNotFoundError(f"Benchmark target does not exist: {target}")
    if not semgrep_config.exists():
        raise FileNotFoundError(
            f"Semgrep config does not exist for case {case['case_id']}: {semgrep_config}"
        )

    case_output_dir = output_root / case["case_id"]
    case_output_dir.mkdir(parents=True, exist_ok=True)
    raw_report_path = case_output_dir / "semgrep_report.json"
    stdout_path = case_output_dir / "semgrep_stdout.txt"
    stderr_path = case_output_dir / "semgrep_stderr.txt"

    command = [
        *semgrep_command,
        "--config",
        str(semgrep_config),
        "--json",
        "--output",
        str(raw_report_path),
        str(target),
    ]

    print(f"[case] {case['case_id']}: semgrep baseline scan...")
    result = subprocess.run(
        command,
        capture_output=True,
        check=False,
        timeout=max(timeout_seconds, 1),
    )

    stdout_text = _decode_subprocess_output(result.stdout)
    stderr_text = _decode_subprocess_output(result.stderr)

    stdout_path.write_text(stdout_text, encoding="utf-8")
    stderr_path.write_text(stderr_text, encoding="utf-8")

    report = _load_semgrep_report(raw_report_path, result)
    summary = summarize_semgrep_report(report, raw_report_path)

    return {
        "case_id": case["case_id"],
        "family": case["family"],
        "goal": case.get("goal", ""),
        "target": str(target),
        "semgrep_config": str(semgrep_config),
        "command": command,
        "raw_report_path": str(raw_report_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "result_count": summary["result_count"],
        "error_count": summary["error_count"],
        "files_scanned": summary["files_scanned"],
        "by_check_id": summary["by_check_id"],
        "by_severity": summary["by_severity"],
        "by_path": summary["by_path"],
    }


def _load_semgrep_report(
    raw_report_path: Path,
    process_result: subprocess.CompletedProcess[bytes],
) -> dict[str, Any]:
    """Load the Semgrep JSON payload from disk or stdout."""
    if raw_report_path.exists():
        return json.loads(raw_report_path.read_text(encoding="utf-8"))

    stdout = _decode_subprocess_output(process_result.stdout).strip()
    if stdout.startswith("{"):
        payload = json.loads(stdout)
        raw_report_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return payload

    stderr = _decode_subprocess_output(process_result.stderr).strip()
    detail = stderr or stdout or f"Semgrep exited with code {process_result.returncode}"
    raise RuntimeError(f"Semgrep did not produce a JSON report. {detail}")


def aggregate_case_results(
    case_results: list[dict[str, Any]],
    *,
    manifest_path: Path,
    output_dir: Path,
    semgrep_command: list[str],
) -> dict[str, Any]:
    """Aggregate per-case Semgrep baseline results into one summary payload."""
    total_results = sum(item["result_count"] for item in case_results)
    total_errors = sum(item["error_count"] for item in case_results)
    total_files_scanned = sum(item["files_scanned"] for item in case_results)

    by_family_results = Counter()
    by_case_results = {}
    by_severity = Counter()

    for item in case_results:
        by_family_results[item["family"]] += item["result_count"]
        by_case_results[item["case_id"]] = item["result_count"]
        by_severity.update(item["by_severity"])

    return {
        "schema_version": "aegis-semgrep-baseline-result-v1",
        "manifest_path": str(manifest_path),
        "output_dir": str(output_dir),
        "generated_at": datetime.now().isoformat(),
        "semgrep_command": semgrep_command,
        "case_count": len(case_results),
        "cases": case_results,
        "aggregate": {
            "result_count": total_results,
            "error_count": total_errors,
            "files_scanned": total_files_scanned,
            "by_family_results": dict(by_family_results),
            "by_case_results": by_case_results,
            "by_severity": dict(by_severity),
        },
    }


def render_markdown(summary: dict[str, Any]) -> str:
    """Render a lightweight Markdown summary for one baseline run."""
    aggregate = summary["aggregate"]
    lines = [
        "# Semgrep Baseline V1",
        "",
        f"- Manifest: `{summary['manifest_path']}`",
        f"- Output dir: `{summary['output_dir']}`",
        f"- Generated at: `{summary['generated_at']}`",
        f"- Semgrep command: `{ ' '.join(summary['semgrep_command']) }`",
        "",
        "## Aggregate",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Results | {aggregate['result_count']} |",
        f"| Reported errors | {aggregate['error_count']} |",
        f"| Files scanned | {aggregate['files_scanned']} |",
        "",
        "## Cases",
        "",
        "| Case | Family | Results | Errors | Files |",
        "|---|---|---:|---:|---:|",
    ]

    for item in summary["cases"]:
        lines.append(
            f"| `{item['case_id']}` | `{item['family']}` | "
            f"{item['result_count']} | {item['error_count']} | {item['files_scanned']} |"
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
        ]
    )

    for item in summary["cases"]:
        lines.append(f"### `{item['case_id']}`")
        if item.get("goal"):
            lines.append(f"- Goal: {item['goal']}")
        lines.append(f"- Target: `{item['target']}`")
        lines.append(f"- Semgrep config: `{item['semgrep_config']}`")
        lines.append(f"- Raw report: `{item['raw_report_path']}`")
        top_checks = sorted(
            item["by_check_id"].items(),
            key=lambda entry: (-entry[1], entry[0]),
        )[:5]
        if top_checks:
            rendered_checks = ", ".join(f"`{check_id}` x{count}" for check_id, count in top_checks)
            lines.append(f"- Top checks: {rendered_checks}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_outputs(summary: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write JSON and Markdown outputs for one Semgrep baseline run."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "semgrep_baseline_summary.json"
    markdown_path = output_dir / "semgrep_baseline_summary.md"

    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    return json_path, markdown_path


def main(argv: list[str] | None = None) -> int:
    """Run the Semgrep baseline across the selected benchmark cases."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest.resolve())
        cases = resolve_manifest_cases(manifest, selected_case_ids=args.case)
        semgrep_command = discover_semgrep_command(args.semgrep_bin)
        output_dir = (args.output_dir or default_output_dir()).resolve()

        case_results = []
        for case in cases:
            case_results.append(
                run_benchmark_case(
                    case=case,
                    output_root=output_dir,
                    semgrep_command=semgrep_command,
                    timeout_seconds=args.timeout,
                )
            )

        summary = aggregate_case_results(
            case_results,
            manifest_path=args.manifest.resolve(),
            output_dir=output_dir,
            semgrep_command=semgrep_command,
        )
        json_path, markdown_path = write_outputs(summary, output_dir)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except ValueError as exc:
        parser.error(str(exc))
    except RuntimeError as exc:
        print(f"[error] {exc}")
        print(
            "Activate the target environment and make sure Semgrep is installed, "
            "then re-run this baseline."
        )
        return 1
    except subprocess.TimeoutExpired as exc:
        print(f"[error] Semgrep timed out after {exc.timeout} seconds.")
        return 1

    aggregate = summary["aggregate"]
    print("Semgrep Baseline V1:")
    print(f"  - cases: {summary['case_count']}")
    print(f"  - results: {aggregate['result_count']}")
    print(f"  - reported errors: {aggregate['error_count']}")
    print(f"  - files scanned: {aggregate['files_scanned']}")
    print(f"  - json: {json_path}")
    print(f"  - markdown: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

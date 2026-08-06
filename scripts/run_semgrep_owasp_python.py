"""Run curated Semgrep community rules on OWASP Benchmark datasets.

This runner keeps the comparison fair for thesis reporting:
- same OWASP dataset
- same curated thesis families
- same `score_owasp_benchmark.py` harness used for Aegis reports

Examples:
  python scripts/run_semgrep_owasp_python.py
  python scripts/run_semgrep_owasp_python.py --profile benchmark-java
  python scripts/run_semgrep_owasp_python.py --family PATH_TRAVERSAL --family SQL_INJECTION
  python scripts/run_semgrep_owasp_python.py --skip-score
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ModuleNotFoundError:  # pragma: no cover - runtime environment dependent
    Console = None
    Panel = None
    Table = None


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.integrations import import_semgrep_report
from aegis_sast.orchestration import ScanWorkflow
from aegis_sast.reporting.json_exporter import JSONExporter
from aegis_sast.reporting.markdown_exporter import MarkdownExporter


if Console is None:  # pragma: no cover - fallback only used in thin environments
    class _PlainConsole:
        def print(self, value: object = "") -> None:
            rendered = str(value)
            rendered = re.sub(r"\[/?[^\]]+\]", "", rendered)
            print(rendered)

    class _PlainPanel:
        def __init__(self, content: str):
            self.content = content

        def __str__(self) -> str:
            return self.content

        @classmethod
        def fit(cls, content: str, border_style: str | None = None):
            return cls(content)

    class _PlainTable:
        def __init__(self, title: str | None = None, **_: object):
            self.title = title
            self.columns: list[str] = []
            self.rows: list[tuple[str, ...]] = []

        def add_column(self, label: str, **_: object) -> None:
            self.columns.append(label)

        def add_row(self, *values: object) -> None:
            self.rows.append(tuple(str(value) for value in values))

        def __str__(self) -> str:
            lines: list[str] = []
            if self.title:
                lines.append(self.title)
            if self.columns:
                lines.append(" | ".join(self.columns))
                lines.append("-+-".join("-" * len(column) for column in self.columns))
            for row in self.rows:
                lines.append(" | ".join(row))
            return "\n".join(lines)

    console = _PlainConsole()
    Panel = _PlainPanel
    Table = _PlainTable
else:
    console = Console()


DEFAULT_FAMILIES = [
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "INSECURE_DESERIALIZATION",
    "SQL_INJECTION",
]
PYTHON_FAMILY_RULESETS = {
    "COMMAND_INJECTION": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "injection"
        / "subprocess-injection.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "injection"
        / "os-system-injection.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "command"
        / "subprocess-injection.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "command"
        / "command-injection-os-system.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "dangerous-subprocess-use.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "dangerous-system-call.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "dangerous-os-exec.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "dangerous-spawn-process.yaml",
    ],
    "PATH_TRAVERSAL": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "injection"
        / "path-traversal-open.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "secure-static-file-serve.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "path-traversal"
        / "path-traversal-open.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "path-traversal"
        / "path-traversal-join.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "path-traversal"
        / "path-traversal-file-name.yaml",
    ],
    "INSECURE_DESERIALIZATION": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "deserialization"
        / "pickle.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "aws-lambda"
        / "security"
        / "tainted-pickle-deserialization.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "audit"
        / "avoid-insecure-deserialization.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "insecure-deserialization.yaml",
    ],
    "SQL_INJECTION": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "injection"
        / "tainted-sql-string.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "aws-lambda"
        / "security"
        / "tainted-sql-string.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "tainted-sql-string.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "sql"
        / "sql-injection-using-db-cursor-execute.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "sql"
        / "sql-injection-using-raw.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "sql"
        / "sql-injection-rawsql.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "audit"
        / "formatted-sql-query.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "audit"
        / "sqli"
        / "psycopg-sqli.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "sqlalchemy"
        / "security"
        / "sqlalchemy-execute-raw-query.yaml",
    ],
    "CODE_INJECTION": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "aws-lambda"
        / "security"
        / "tainted-code-exec.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "injection"
        / "user-exec.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "injection"
        / "user-eval.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "code"
        / "user-exec.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "code"
        / "user-exec-format-string.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "code"
        / "user-eval.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "code"
        / "user-eval-format-string.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "audit"
        / "exec-detected.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "lang"
        / "security"
        / "audit"
        / "eval-detected.yaml",
    ],
    "OPEN_REDIRECT": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "flask"
        / "security"
        / "open-redirect.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "python"
        / "django"
        / "security"
        / "injection"
        / "open-redirect.yaml",
    ],
}
JAVA_FAMILY_RULESETS = {
    "COMMAND_INJECTION": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "tainted-cmd-from-http-request.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "command-injection-formatted-runtime-call.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "command-injection-process-builder.yaml",
    ],
    "PATH_TRAVERSAL": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "httpservlet-path-traversal.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "jax-rs"
        / "security"
        / "jax-rs-path-traversal.yaml",
    ],
    "INSECURE_DESERIALIZATION": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "object-deserialization.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "insecure-jms-deserialization.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "jackson-unsafe-deserialization.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "use-snakeyaml-constructor.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "xml-decoder.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "rmi"
        / "security"
        / "server-dangerous-object-deserialization.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "rmi"
        / "security"
        / "server-dangerous-class-deserialization.yaml",
    ],
    "SQL_INJECTION": [
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "formatted-sql-string.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "jdbc-sql-formatted-string.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "sqli"
        / "jdbc-sqli.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "sqli"
        / "hibernate-sqli.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "sqli"
        / "jpa-sqli.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "sqli"
        / "jdo-sqli.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "sqli"
        / "vertx-sqli.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "lang"
        / "security"
        / "audit"
        / "sqli"
        / "tainted-sql-from-http-request.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "spring"
        / "security"
        / "audit"
        / "spring-sqli.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "aws-lambda"
        / "security"
        / "tainted-sql-string.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "aws-lambda"
        / "security"
        / "tainted-sqli.yaml",
        REPO_ROOT
        / "refs"
        / "rule_sources"
        / "semgrep-rules"
        / "java"
        / "jboss"
        / "security"
        / "session_sqli.yaml",
    ],
}
PROFILE_CONFIGS = {
    "benchmark-python": {
        "label": "BenchmarkPython",
        "language": "python",
        "target": Path(r"D:\BenchmarkPython\testcode"),
        "expected_results": Path(r"D:\BenchmarkPython\expectedresults-0.1.csv"),
        "families": list(DEFAULT_FAMILIES),
        "rulesets": PYTHON_FAMILY_RULESETS,
        "output_dir_name": "semgrep_owasp_python",
    },
    "benchmark-java": {
        "label": "BenchmarkJava",
        "language": "java",
        "target": Path(r"D:\BenchmarkJava\src\main\java"),
        "expected_results": Path(r"D:\BenchmarkJava\expectedresults-1.2.csv"),
        "families": list(DEFAULT_FAMILIES),
        "rulesets": JAVA_FAMILY_RULESETS,
        "output_dir_name": "semgrep_owasp_java",
    },
}
SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}
CONFIDENCE_MAP = {
    "HIGH": 0.85,
    "MEDIUM": 0.65,
    "LOW": 0.45,
}
SUPPORTED_FAMILY_CHOICES = sorted(
    set(PYTHON_FAMILY_RULESETS) | set(JAVA_FAMILY_RULESETS)
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Run curated Semgrep community rules on OWASP Benchmark datasets and "
            "emit an Aegis-compatible JSON report for the shared scoring harness."
        ),
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_CONFIGS),
        default="benchmark-python",
        help="Benchmark profile that picks the dataset, language, and community ruleset mapping.",
    )
    parser.add_argument(
        "--target",
        type=Path,
        help="Optional benchmark source directory override for the selected profile.",
    )
    parser.add_argument(
        "--expected-results",
        type=Path,
        help="Optional expectedresults CSV override. Used unless --skip-score is set.",
    )
    parser.add_argument(
        "--family",
        action="append",
        choices=SUPPORTED_FAMILY_CHOICES,
        default=[],
        help="Optional repeatable thesis-family filter.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "Directory for benchmark artifacts. Defaults to "
            "reports/benchmark/semgrep_owasp_python/<timestamp>."
        ),
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
        default=1800,
        help="Per-family subprocess timeout in seconds.",
    )
    parser.add_argument(
        "--max-case-list",
        type=int,
        default=20,
        help="Maximum FP/FN case IDs kept per family when scoring.",
    )
    parser.add_argument(
        "--skip-score",
        action="store_true",
        help="Skip the OWASP scoring step even when --expected-results exists.",
    )
    parser.add_argument(
        "--apply-aegis-triage",
        action="store_true",
        help=(
            "Run the converted Semgrep report through the Aegis triage workflow "
            "and export a second hybrid report."
        ),
    )
    parser.add_argument(
        "--native-report",
        type=Path,
        help=(
            "Optional precomputed Aegis native JSON report to score with the same "
            "OWASP harness and include in the terminal matrix."
        ),
    )
    parser.add_argument(
        "--keep-family-artifacts",
        action="store_true",
        help=(
            "Keep per-family raw Semgrep JSON/stdout/stderr files. "
            "By default the runner only keeps the final converted report and score outputs."
        ),
    )
    return parser


def default_output_dir(profile_name: str) -> Path:
    """Build a stable output directory for one benchmark run."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir_name = PROFILE_CONFIGS[profile_name]["output_dir_name"]
    return REPO_ROOT / "reports" / "benchmark" / output_dir_name / timestamp


def transient_family_artifact_root(output_dir: Path) -> Path:
    """Return the hidden directory used for temporary family-level Semgrep artifacts."""
    return output_dir / ".family_artifacts"


def resolve_profile(profile_name: str) -> dict[str, Any]:
    """Resolve one configured benchmark profile."""
    try:
        return PROFILE_CONFIGS[profile_name]
    except KeyError as exc:
        raise ValueError(f"Unknown benchmark profile: {profile_name}") from exc


def resolve_families(
    requested_families: list[str] | None = None,
    *,
    default_families: list[str] | None = None,
) -> list[str]:
    """Resolve the family set for this run."""
    selected = [item.strip().upper() for item in (requested_families or []) if item.strip()]
    if not selected:
        return list(default_families or DEFAULT_FAMILIES)

    ordered: list[str] = []
    seen: set[str] = set()
    for family in selected:
        if family not in seen:
            seen.add(family)
            ordered.append(family)
    return ordered


def resolve_rule_configs(
    families: list[str],
    *,
    ruleset_map: dict[str, list[Path]],
) -> dict[str, list[Path]]:
    """Resolve community Semgrep rule paths for each selected family."""
    resolved: dict[str, list[Path]] = {}
    for family in families:
        config_paths = ruleset_map.get(family)
        if not config_paths:
            raise ValueError(f"No Semgrep config mapping exists for family {family!r}.")
        missing = [str(path) for path in config_paths if not path.exists()]
        if missing:
            missing_text = ", ".join(missing)
            raise FileNotFoundError(
                f"Missing Semgrep community rule files for {family}: {missing_text}"
            )
        resolved[family] = [path.resolve() for path in config_paths]
    return resolved


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


def _decode_subprocess_output(payload: bytes | str | None) -> str:
    """Decode subprocess output conservatively for Windows console safety."""
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    return payload.decode("utf-8", errors="replace")


def discover_semgrep_command(explicit_bin: str | None = None) -> tuple[list[str], str]:
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
            version = (_decode_subprocess_output(result.stdout).strip() or "unknown").splitlines()[0]
            return command, version

        stderr = _decode_subprocess_output(result.stderr).strip()
        stdout = _decode_subprocess_output(result.stdout).strip()
        detail = stderr or stdout or f"exit {result.returncode}"
        failures.append(f"{' '.join(command)}: {detail}")

    raise RuntimeError(
        "Semgrep is not available in the current environment. "
        + " | ".join(failures)
    )


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


def _extract_scanned_paths(report: dict[str, Any]) -> list[str]:
    """Return scanned paths when Semgrep reports them explicitly."""
    paths = report.get("paths", {})
    if isinstance(paths, dict):
        scanned = paths.get("scanned")
        if isinstance(scanned, list):
            return [str(item) for item in scanned]
    return []


def _location_dict(
    file_path: str,
    line: int,
    column: int,
    snippet: str,
) -> dict[str, Any]:
    """Build a JSON-friendly code location payload."""
    return {
        "file": file_path,
        "line": int(line or 1),
        "column": int(column or 1),
        "snippet": snippet or "",
    }


def _trace_endpoint_to_location(
    trace_payload: Any,
    *,
    fallback_path: str,
    fallback_line: int,
    fallback_column: int,
    fallback_snippet: str,
) -> dict[str, Any]:
    """Convert a Semgrep taint trace endpoint into one stable location object."""
    if (
        isinstance(trace_payload, list)
        and len(trace_payload) >= 2
        and isinstance(trace_payload[1], list)
        and trace_payload[1]
        and isinstance(trace_payload[1][0], dict)
    ):
        location = trace_payload[1][0]
        snippet = ""
        if len(trace_payload[1]) > 1 and isinstance(trace_payload[1][1], str):
            snippet = trace_payload[1][1]
        start = location.get("start", {})
        return _location_dict(
            str(location.get("path") or fallback_path),
            int(start.get("line") or fallback_line or 1),
            int(start.get("col") or fallback_column or 1),
            snippet or fallback_snippet,
        )

    return _location_dict(
        fallback_path,
        fallback_line,
        fallback_column,
        fallback_snippet,
    )


def _trace_intermediate_steps(trace_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert Semgrep intermediate taint variables into stable locations."""
    steps: list[dict[str, Any]] = []
    for item in trace_payload.get("intermediate_vars", []):
        if not isinstance(item, dict):
            continue
        location = item.get("location")
        if not isinstance(location, dict):
            continue
        start = location.get("start", {})
        steps.append(
            _location_dict(
                str(location.get("path") or ""),
                int(start.get("line") or 1),
                int(start.get("col") or 1),
                str(item.get("content") or ""),
            )
        )
    return steps


def _map_severity(semgrep_severity: str | None) -> str:
    """Map Semgrep severities into the Aegis report vocabulary."""
    normalized = (semgrep_severity or "").strip().upper()
    return SEVERITY_MAP.get(normalized, "UNKNOWN")


def _map_confidence(metadata: dict[str, Any]) -> float:
    """Map Semgrep metadata confidence into a stable float."""
    raw_confidence = str(metadata.get("confidence") or "").strip().upper()
    return CONFIDENCE_MAP.get(raw_confidence, 0.6)


def semgrep_result_to_finding(
    result: dict[str, Any],
    *,
    language: str,
    family: str,
    finding_id: str,
    detected_at: str,
) -> dict[str, Any]:
    """Convert one Semgrep result into a minimal Aegis-compatible finding."""
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    trace = extra.get("dataflow_trace") or {}
    path = str(result.get("path") or "")
    start = result.get("start") or {}
    fallback_line = int(start.get("line") or 1)
    fallback_column = int(start.get("col") or 1)
    fallback_snippet = str(extra.get("lines") or "")
    sink = _trace_endpoint_to_location(
        trace.get("taint_sink"),
        fallback_path=path,
        fallback_line=fallback_line,
        fallback_column=fallback_column,
        fallback_snippet=fallback_snippet,
    )
    source = _trace_endpoint_to_location(
        trace.get("taint_source"),
        fallback_path=path,
        fallback_line=fallback_line,
        fallback_column=fallback_column,
        fallback_snippet="",
    )
    severity = _map_severity(extra.get("severity"))
    rule_id = str(result.get("check_id") or family.lower())

    return {
        "id": finding_id,
        "tool": "semgrep-community",
        "language": language,
        "rule_id": rule_id,
        "type": family,
        "severity": severity,
        "triage_status": "likely",
        "confidence": _map_confidence(metadata),
        "file": path,
        "line": int(sink.get("line") or fallback_line or 1),
        "message": str(extra.get("message") or rule_id),
        "evidence": {
            "source": source,
            "sink": sink,
            "intermediate_steps": _trace_intermediate_steps(trace),
            "sanitizers": [],
        },
        "explanation": str(extra.get("message") or ""),
        "recommendation": str(metadata.get("fix") or ""),
        "metadata": {
            "check_id": rule_id,
            "semgrep_severity": str(extra.get("severity") or ""),
            "cwe": metadata.get("cwe", []),
            "owasp": metadata.get("owasp", []),
            "references": metadata.get("references", []),
            "engine_kind": extra.get("engine_kind"),
            "fingerprint": extra.get("fingerprint"),
        },
        "detected_at": detected_at,
    }


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
        "scanned_paths": scanned_paths,
        "errors": errors,
    }


def run_family_scan(
    *,
    language: str,
    family: str,
    configs: list[Path],
    target: Path,
    output_root: Path,
    semgrep_command: list[str],
    timeout_seconds: int,
    finding_offset: int,
    detected_at: str,
    keep_family_artifacts: bool = False,
) -> dict[str, Any]:
    """Run Semgrep on one family and convert the JSON results."""
    if not target.exists():
        raise FileNotFoundError(f"Benchmark target does not exist: {target}")

    family_slug = family.lower()
    artifact_root = output_root if keep_family_artifacts else transient_family_artifact_root(output_root)
    family_output_dir = artifact_root / family_slug
    family_output_dir.mkdir(parents=True, exist_ok=True)
    raw_report_path = family_output_dir / "semgrep_report.json"
    stdout_path = family_output_dir / "semgrep_stdout.txt"
    stderr_path = family_output_dir / "semgrep_stderr.txt"

    command = [*semgrep_command, "--metrics", "off", "--json", "--output", str(raw_report_path)]
    for config in configs:
        command.extend(["--config", str(config)])
    command.append(str(target))

    console.print(
        f"[cyan]Running[/cyan] {family} with {len(configs)} Semgrep rule file(s)..."
    )
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

    findings: list[dict[str, Any]] = []
    for index, finding in enumerate(report.get("results", []), start=1):
        findings.append(
            semgrep_result_to_finding(
                finding,
                language=language,
                family=family,
                finding_id=f"SEMGREP-{finding_offset + index:05d}",
                detected_at=detected_at,
            )
        )

    return {
        "family": family,
        "configs": [str(path) for path in configs],
        "command": command,
        "artifacts_kept": keep_family_artifacts,
        "raw_report_path": str(raw_report_path) if keep_family_artifacts else None,
        "stdout_path": str(stdout_path) if keep_family_artifacts else None,
        "stderr_path": str(stderr_path) if keep_family_artifacts else None,
        "result_count": summary["result_count"],
        "error_count": summary["error_count"],
        "files_scanned": summary["files_scanned"],
        "by_check_id": summary["by_check_id"],
        "by_severity": summary["by_severity"],
        "by_path": summary["by_path"],
        "scanned_paths": summary["scanned_paths"],
        "errors": summary["errors"],
        "findings": findings,
    }


def build_aegis_compatible_report(
    *,
    profile_name: str,
    language: str,
    target: Path,
    semgrep_command: list[str],
    semgrep_version: str,
    families: list[str],
    family_runs: list[dict[str, Any]],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Build one JSON report that the shared OWASP scorer can consume."""
    all_findings = [
        finding
        for family_run in family_runs
        for finding in family_run.get("findings", [])
    ]
    scanned_paths = {
        path
        for family_run in family_runs
        for path in family_run.get("scanned_paths", [])
        if path
    }
    by_severity = Counter(
        str(finding.get("severity") or "UNKNOWN").strip().lower()
        for finding in all_findings
    )
    top_level_errors = [
        {
            "family": family_run["family"],
            "details": family_run.get("errors", []),
        }
        for family_run in family_runs
        if family_run.get("errors")
    ]

    return {
        "schema_version": "aegis-compatible-semgrep-report-v1",
        "scan_metadata": {
            "tool": "semgrep-community",
            "version": semgrep_version,
            "timestamp": started_at.isoformat(),
            "target": str(target),
            "duration_seconds": (ended_at - started_at).total_seconds(),
            "files_scanned": len(scanned_paths),
        },
        "findings": all_findings,
        "summary": {
            "target": str(target),
            "duration_seconds": (ended_at - started_at).total_seconds(),
            "files_scanned": len(scanned_paths),
            "total_vulnerabilities": len(all_findings),
            "by_severity": {
                "critical": by_severity.get("critical", 0),
                "high": by_severity.get("high", 0),
                "medium": by_severity.get("medium", 0),
                "low": by_severity.get("low", 0),
            },
            "errors": top_level_errors,
        },
        "errors": top_level_errors,
        "semgrep_run_summary": {
            "profile": profile_name,
            "language": language,
            "families": families,
            "semgrep_command": semgrep_command,
            "family_runs": [
                {
                    key: value
                    for key, value in family_run.items()
                    if key != "findings"
                }
                for family_run in family_runs
            ],
        },
    }


def render_markdown(
    title: str,
    report: dict[str, Any],
    families: list[str],
    semgrep_command: list[str],
    family_runs: list[dict[str, Any]],
    score_summary: dict[str, Any] | None = None,
) -> str:
    """Render a compact Markdown summary for the benchmark run."""
    metadata = report["scan_metadata"]
    lines = [
        f"# {title}",
        "",
        f"- Target: `{metadata['target']}`",
        f"- Families: {', '.join(families)}",
        f"- Semgrep command: `{ ' '.join(semgrep_command) }`",
        f"- Files scanned: {metadata['files_scanned']}",
        f"- Findings converted: {len(report.get('findings', []))}",
        f"- Duration (s): {metadata['duration_seconds']:.2f}",
        "",
        "| Family | Findings | Errors | Files | Rules |",
        "|---|---:|---:|---:|---:|",
    ]

    for family_run in family_runs:
        lines.append(
            f"| `{family_run['family']}` | {family_run['result_count']} | "
            f"{family_run['error_count']} | {family_run['files_scanned']} | "
            f"{len(family_run['configs'])} |"
        )

    if score_summary:
        aggregate = score_summary["modes"]["all"]["aggregate"]
        lines.extend(
            [
                "",
                "## OWASP Score",
                "",
                "| Metric | Value |",
                "|---|---:|",
                f"| TP | {aggregate['tp']} |",
                f"| FP | {aggregate['fp']} |",
                f"| FN | {aggregate['fn']} |",
                f"| Precision | {aggregate['precision']:.4f} |",
                f"| Recall | {aggregate['recall']:.4f} |",
                f"| F1 | {aggregate['f1']:.4f} |",
            ]
        )

    lines.extend(["", "## Family Artifacts", ""])
    kept_any_artifacts = any(family_run.get("artifacts_kept") for family_run in family_runs)
    if not kept_any_artifacts:
        lines.append("- Per-family raw Semgrep artifacts were not kept in this run.")
    else:
        for family_run in family_runs:
            if not family_run.get("artifacts_kept"):
                lines.append(f"- `{family_run['family']}` raw artifacts were skipped.")
                continue
            lines.append(f"- `{family_run['family']}` report: `{family_run['raw_report_path']}`")
            lines.append(f"- `{family_run['family']}` stdout: `{family_run['stdout_path']}`")
            lines.append(f"- `{family_run['family']}` stderr: `{family_run['stderr_path']}`")

    return "\n".join(lines).rstrip() + "\n"


def write_outputs(
    *,
    output_dir: Path,
    title: str,
    report: dict[str, Any],
    families: list[str],
    semgrep_command: list[str],
    family_runs: list[dict[str, Any]],
    score_summary: dict[str, Any] | None = None,
) -> tuple[Path, Path]:
    """Write JSON and Markdown outputs for one benchmark run."""
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "semgrep_aegis_report.json"
    markdown_path = output_dir / "semgrep_run_summary.md"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_markdown(title, report, families, semgrep_command, family_runs, score_summary),
        encoding="utf-8",
    )
    return report_path, markdown_path


def _load_owasp_score_module():
    """Load the shared OWASP score module from disk."""
    score_path = SCRIPT_DIR / "score_owasp_benchmark.py"
    spec = importlib.util.spec_from_file_location(
        "score_owasp_benchmark",
        score_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def score_report_if_requested(
    *,
    report: dict[str, Any],
    expected_results: Path,
    families: list[str],
    output_dir: Path,
    max_case_list: int,
) -> tuple[dict[str, Any], Path, Path]:
    """Score the converted report with the shared OWASP scorer."""
    score_module = _load_owasp_score_module()
    summary = score_module.score_report(
        report,
        score_module.load_expected_cases(expected_results.resolve()),
        families=families,
        max_case_list=max_case_list,
    )
    json_path, markdown_path = score_module.write_outputs(summary, output_dir)
    return summary, json_path, markdown_path


def apply_aegis_triage_to_report(
    *,
    report: dict[str, Any],
    output_dir: Path,
) -> tuple[dict[str, Any], Path, Path, dict[str, Any]]:
    """Run the imported Semgrep report through the Aegis triage workflow."""
    scan_result, repo_profile = import_semgrep_report(report)
    workflow_state = ScanWorkflow().run(scan_result, repo_profile=repo_profile)
    workflow_metadata = dict(workflow_state.metadata)
    workflow_metadata["detector_source"] = report.get("scan_metadata", {}).get(
        "tool",
        "semgrep-community",
    )
    workflow_metadata["detector_lane"] = "semgrep+aegis-triage"
    workflow_metadata["upstream_profile"] = report.get("semgrep_run_summary", {}).get(
        "profile"
    )

    json_path = JSONExporter(output_dir).export(
        scan_result,
        filename="semgrep_aegis_triaged_report.json",
        triage_records=workflow_state.triage_records,
        workflow_metadata=workflow_metadata,
    )
    markdown_path = MarkdownExporter(output_dir).export(
        scan_result,
        filename="semgrep_aegis_triaged_report.md",
        triage_records=workflow_state.triage_records,
        workflow_metadata=workflow_metadata,
    )
    triaged_report = json.loads(json_path.read_text(encoding="utf-8"))
    triaged_report.setdefault("scan_metadata", {})["tool"] = "semgrep-community+aegis-triage"
    json_path.write_text(
        json.dumps(triaged_report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return triaged_report, json_path, markdown_path, workflow_metadata


def score_existing_report(
    *,
    report_path: Path,
    expected_results: Path,
    families: list[str],
    output_dir: Path,
    max_case_list: int,
) -> tuple[dict[str, Any], Path, Path]:
    """Score one already-generated JSON report with the shared harness."""
    score_module = _load_owasp_score_module()
    report = score_module.load_report(report_path.resolve())
    summary = score_module.score_report(
        report,
        score_module.load_expected_cases(expected_results.resolve()),
        families=families,
        max_case_list=max_case_list,
    )
    json_path, markdown_path = score_module.write_outputs(summary, output_dir)
    return summary, json_path, markdown_path


def print_score_matrix(
    lanes: list[tuple[str, dict[str, Any]]],
) -> None:
    """Render a compact detector/triage comparison matrix."""
    if len(lanes) < 2:
        return

    table = Table(
        title="Benchmark Matrix",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Lane", style="cyan")
    table.add_column("All F1", justify="right")
    table.add_column("Visible F1", justify="right")
    table.add_column("High-Conf F1", justify="right")
    table.add_column("Visible TP", justify="right")
    table.add_column("Visible FP", justify="right")
    table.add_column("Visible FN", justify="right")

    for label, summary in lanes:
        all_metrics = summary["modes"]["all"]["aggregate"]
        visible_metrics = summary["modes"]["visible"]["aggregate"]
        high_conf_metrics = summary["modes"]["high-confidence"]["aggregate"]
        table.add_row(
            label,
            f"{all_metrics['f1']:.4f}",
            f"{visible_metrics['f1']:.4f}",
            f"{high_conf_metrics['f1']:.4f}",
            str(visible_metrics["tp"]),
            str(visible_metrics["fp"]),
            str(visible_metrics["fn"]),
        )

    console.print(table)


def print_run_overview(
    *,
    title: str,
    profile_name: str,
    language: str,
    families: list[str],
    report: dict[str, Any],
    report_path: Path,
    markdown_path: Path,
    score_summary: dict[str, Any] | None,
    score_json_path: Path | None,
    score_markdown_path: Path | None,
    triaged_report_path: Path | None,
    triaged_markdown_path: Path | None,
    triaged_score_summary: dict[str, Any] | None,
    triaged_score_json_path: Path | None,
    triaged_score_markdown_path: Path | None,
    native_report_path: Path | None,
    native_score_summary: dict[str, Any] | None,
    native_score_json_path: Path | None,
    native_score_markdown_path: Path | None,
    keep_family_artifacts: bool,
) -> None:
    """Render a compact terminal overview for one Semgrep benchmark run."""
    metadata = report["scan_metadata"]
    console.print(
        Panel.fit(
            (
                f"[bold cyan]{title}[/bold cyan]\n"
                f"[dim]{report_path}[/dim]"
            ),
            border_style="cyan",
        )
    )

    overview = Table(show_header=False, box=None)
    overview.add_column("Field", style="green")
    overview.add_column("Value")
    overview.add_row("Profile", profile_name)
    overview.add_row("Language", language)
    overview.add_row("Families", ", ".join(families))
    overview.add_row("Semgrep version", str(metadata["version"]))
    overview.add_row("Files scanned", str(metadata["files_scanned"]))
    overview.add_row("Findings converted", str(len(report.get("findings", []))))
    overview.add_row("Family artifacts", "kept" if keep_family_artifacts else "compact only")
    console.print(overview)

    family_table = Table(
        title="Family Coverage",
        show_header=True,
        header_style="bold yellow",
    )
    family_table.add_column("Family", style="yellow")
    family_table.add_column("Findings", justify="right")
    family_table.add_column("Errors", justify="right")
    family_table.add_column("Files", justify="right")
    family_table.add_column("Rules", justify="right")
    for family_run in report["semgrep_run_summary"]["family_runs"]:
        family_table.add_row(
            family_run["family"],
            str(family_run["result_count"]),
            str(family_run["error_count"]),
            str(family_run["files_scanned"]),
            str(len(family_run["configs"])),
        )
    console.print(family_table)

    if score_summary:
        aggregate = score_summary["modes"]["all"]["aggregate"]
        score_table = Table(
            title="OWASP Score (All Findings)",
            show_header=True,
            header_style="bold magenta",
        )
        score_table.add_column("TP", justify="right", style="magenta")
        score_table.add_column("FP", justify="right")
        score_table.add_column("FN", justify="right")
        score_table.add_column("Precision", justify="right")
        score_table.add_column("Recall", justify="right")
        score_table.add_column("F1", justify="right")
        score_table.add_row(
            str(aggregate["tp"]),
            str(aggregate["fp"]),
            str(aggregate["fn"]),
            f"{aggregate['precision']:.4f}",
            f"{aggregate['recall']:.4f}",
            f"{aggregate['f1']:.4f}",
        )
        console.print(score_table)

    score_lanes: list[tuple[str, dict[str, Any]]] = []
    if score_summary:
        score_lanes.append(("Semgrep raw", score_summary))
    if triaged_score_summary:
        score_lanes.append(("Semgrep + triage", triaged_score_summary))
    if native_score_summary:
        score_lanes.append(("Aegis native", native_score_summary))
    print_score_matrix(score_lanes)

    artifact_table = Table(show_header=False, box=None)
    artifact_table.add_column("Artifact", style="green")
    artifact_table.add_column("Path")
    artifact_table.add_row("Converted report", str(report_path))
    artifact_table.add_row("Run summary", str(markdown_path))
    if score_json_path is not None:
        artifact_table.add_row("Score JSON", str(score_json_path))
    if score_markdown_path is not None:
        artifact_table.add_row("Score Markdown", str(score_markdown_path))
    if triaged_report_path is not None:
        artifact_table.add_row("Triaged report", str(triaged_report_path))
    if triaged_markdown_path is not None:
        artifact_table.add_row("Triaged markdown", str(triaged_markdown_path))
    if triaged_score_json_path is not None:
        artifact_table.add_row("Triaged score JSON", str(triaged_score_json_path))
    if triaged_score_markdown_path is not None:
        artifact_table.add_row("Triaged score Markdown", str(triaged_score_markdown_path))
    if native_report_path is not None:
        artifact_table.add_row("Native report", str(native_report_path))
    if native_score_json_path is not None:
        artifact_table.add_row("Native score JSON", str(native_score_json_path))
    if native_score_markdown_path is not None:
        artifact_table.add_row("Native score Markdown", str(native_score_markdown_path))
    console.print(artifact_table)


def main(argv: list[str] | None = None) -> int:
    """Run the curated Semgrep OWASP BenchmarkPython comparison."""
    parser = build_parser()
    args = parser.parse_args(argv)
    transient_artifacts_dir: Path | None = None
    triaged_report = None
    triaged_report_path = None
    triaged_markdown_path = None
    triaged_score_summary = None
    triaged_score_json_path = None
    triaged_score_markdown_path = None
    native_report_path = None
    native_score_summary = None
    native_score_json_path = None
    native_score_markdown_path = None

    try:
        profile = resolve_profile(args.profile)
        title = f"Semgrep {profile['label']} ({profile['language']})"
        target = (args.target or profile["target"]).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Benchmark target does not exist: {target}")

        families = resolve_families(args.family, default_families=profile["families"])
        family_configs = resolve_rule_configs(families, ruleset_map=profile["rulesets"])
        semgrep_command, semgrep_version = discover_semgrep_command(args.semgrep_bin)
        output_dir = (args.output_dir or default_output_dir(args.profile)).resolve()
        transient_artifacts_dir = transient_family_artifact_root(output_dir)
        started_at = datetime.now()
        detected_at = started_at.isoformat()

        family_runs: list[dict[str, Any]] = []
        finding_offset = 0
        for family in families:
            family_run = run_family_scan(
                language=profile["language"],
                family=family,
                configs=family_configs[family],
                target=target,
                output_root=output_dir,
                semgrep_command=semgrep_command,
                timeout_seconds=args.timeout,
                finding_offset=finding_offset,
                detected_at=detected_at,
                keep_family_artifacts=args.keep_family_artifacts,
            )
            family_runs.append(family_run)
            finding_offset += family_run["result_count"]

        ended_at = datetime.now()
        report = build_aegis_compatible_report(
            profile_name=args.profile,
            language=profile["language"],
            target=target,
            semgrep_command=semgrep_command,
            semgrep_version=semgrep_version,
            families=families,
            family_runs=family_runs,
            started_at=started_at,
            ended_at=ended_at,
        )

        if not args.skip_score and args.expected_results:
            expected_results = args.expected_results.resolve()
            if not expected_results.exists():
                raise FileNotFoundError(
                    f"Expected-results CSV does not exist: {expected_results}"
                )
        elif not args.skip_score:
            expected_results = profile["expected_results"].resolve()
            if not expected_results.exists():
                raise FileNotFoundError(
                    f"Expected-results CSV does not exist: {expected_results}"
                )
        else:
            expected_results = None

        score_summary = None
        score_json_path = None
        score_markdown_path = None
        if expected_results is not None:
            score_summary, score_json_path, score_markdown_path = score_report_if_requested(
                report=report,
                expected_results=expected_results,
                families=families,
                output_dir=output_dir / "score_raw",
                max_case_list=args.max_case_list,
            )

        report_path, markdown_path = write_outputs(
            output_dir=output_dir,
            title=title,
            report=report,
            families=families,
            semgrep_command=semgrep_command,
            family_runs=family_runs,
            score_summary=score_summary,
        )

        if args.apply_aegis_triage:
            (
                triaged_report,
                triaged_report_path,
                triaged_markdown_path,
                _triaged_workflow_metadata,
            ) = apply_aegis_triage_to_report(
                report=report,
                output_dir=output_dir,
            )
            if expected_results is not None:
                (
                    triaged_score_summary,
                    triaged_score_json_path,
                    triaged_score_markdown_path,
                ) = score_report_if_requested(
                    report=triaged_report,
                    expected_results=expected_results,
                    families=families,
                    output_dir=output_dir / "score_triaged",
                    max_case_list=args.max_case_list,
                )

        if args.native_report is not None:
            native_report_path = args.native_report.resolve()
            if not native_report_path.exists():
                raise FileNotFoundError(
                    f"Native Aegis report does not exist: {native_report_path}"
                )
            if expected_results is not None:
                (
                    native_score_summary,
                    native_score_json_path,
                    native_score_markdown_path,
                ) = score_existing_report(
                    report_path=native_report_path,
                    expected_results=expected_results,
                    families=families,
                    output_dir=output_dir / "score_native",
                    max_case_list=args.max_case_list,
                )
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except ValueError as exc:
        parser.error(str(exc))
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1
    except subprocess.TimeoutExpired as exc:
        console.print(f"[red]Error:[/red] Semgrep timed out after {exc.timeout} seconds.")
        return 1
    finally:
        if (
            transient_artifacts_dir is not None
            and transient_artifacts_dir.exists()
            and not args.keep_family_artifacts
        ):
            shutil.rmtree(transient_artifacts_dir, ignore_errors=True)

    print_run_overview(
        title=title,
        profile_name=args.profile,
        language=profile["language"],
        families=families,
        report=report,
        report_path=report_path,
        markdown_path=markdown_path,
        score_summary=score_summary,
        score_json_path=score_json_path,
        score_markdown_path=score_markdown_path,
        triaged_report_path=triaged_report_path,
        triaged_markdown_path=triaged_markdown_path,
        triaged_score_summary=triaged_score_summary,
        triaged_score_json_path=triaged_score_json_path,
        triaged_score_markdown_path=triaged_score_markdown_path,
        native_report_path=native_report_path,
        native_score_summary=native_score_summary,
        native_score_json_path=native_score_json_path,
        native_score_markdown_path=native_score_markdown_path,
        keep_family_artifacts=args.keep_family_artifacts,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

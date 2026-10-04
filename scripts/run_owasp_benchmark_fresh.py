"""
End-to-end runner that executes fresh Semgrep OSS scan on OWASP Benchmark Python
and immediately scores it against expectedresults-0.1.csv ground-truth.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CWE_FAMILY_MAP = {
    "78": "COMMAND_INJECTION",
    "89": "SQL_INJECTION",
    "22": "PATH_TRAVERSAL",
    "502": "INSECURE_DESERIALIZATION",
    "601": "OPEN_REDIRECT",
    "95": "CODE_INJECTION",
    "94": "CODE_INJECTION",
    "79": "XSS",
    "611": "XXE",
    "643": "XPATH_INJECTION",
}


def run_benchmark(
    target_dir: Path,
    expected_results_csv: Path,
    rules_dir: Path,
    output_base_dir: Path,
    family_filter: list[str] | None = None,
) -> int:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_base_dir / f"owasp_run_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    raw_semgrep_json = run_dir / "semgrep_raw.json"
    aegis_report_json = run_dir / "aegis_sast_report.json"

    print("=" * 65)
    print("  Aegis-SAST: Fresh OWASP Benchmark Scanner & Scorer")
    print(f"  Target         : {target_dir}")
    print(f"  Rules          : {rules_dir}")
    print(f"  Expected CSV   : {expected_results_csv}")
    print(f"  Output Dir     : {run_dir}")
    print("=" * 65)

    # 1. Run Semgrep OSS Scan
    print("\n[1/3] Running Semgrep OSS scan across 1,230 test cases...")
    start_scan = time.time()
    cmd = [
        "semgrep",
        "scan",
        "--config",
        str(rules_dir),
        "--json",
        "--output",
        str(raw_semgrep_json),
        str(target_dir),
    ]

    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    scan_duration = round(time.time() - start_scan, 2)
    print(f"      Semgrep scan finished in {scan_duration}s.")

    if not raw_semgrep_json.exists():
        print(f"[-] Error: Semgrep output file not created. Stderr: {res.stderr}", file=sys.stderr)
        return 1

    # 2. Bridge Semgrep matches with Tree-sitter DFG Taint Analysis & Sanitizers
    print("\n[2/3] Bridging Semgrep findings with Tree-sitter DFG & Sanitizer analysis...")
    from aegis_sast.integrations.semgrep_runner import SemgrepMatch
    from aegis_sast.integrations.taint_bridge import TaintBridge
    from aegis_sast.core.models import Severity

    with open(raw_semgrep_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    matches = []
    for r in results:
        extra = r.get("extra", {})
        sev_str = extra.get("severity", "UNKNOWN").upper()
        sev = Severity.HIGH if sev_str == "ERROR" else (Severity.MEDIUM if sev_str == "WARNING" else Severity.LOW)
        matches.append(
            SemgrepMatch(
                check_id=r.get("check_id", ""),
                file_path=r.get("path", ""),
                line=r.get("start", {}).get("line", 1),
                col=r.get("start", {}).get("col", 1),
                end_line=r.get("end", {}).get("line", 1),
                end_col=r.get("end", {}).get("col", 1),
                message=extra.get("message", ""),
                severity=sev,
                metadata=extra.get("metadata", {}),
                metavars=extra.get("metavars", {}),
                code_snippet=extra.get("lines", ""),
            )
        )

    bridge = TaintBridge()
    bridged_findings = bridge.bridge_matches(matches, project_root=target_dir)

    findings = []
    for b in bridged_findings:
        findings.append({
            "tool": "aegis-semgrep-bridge",
            "type": b.vulnerability_type,
            "rule_id": b.rule_id,
            "file": b.file_path,
            "path": b.file_path,
            "line": b.line_number,
            "message": b.message,
            "severity": b.severity.value,
            "triage_status": b.triage_status.value,
            "confidence": b.confidence,
        })

    report_payload = {
        "scan_metadata": {
            "tool": "aegis-sast",
            "version": "1.0.0",
            "engine": "semgrep-oss-full",
            "timestamp": datetime.now().isoformat(),
            "target": str(target_dir),
            "duration_seconds": scan_duration,
        },
        "findings": findings,
    }

    with open(aegis_report_json, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    print(f"      Created fresh report with {len(findings)} security findings -> {aegis_report_json}")

    # 3. Score against Ground Truth
    print("\n[3/3] Scoring report against Ground Truth CSV...")
    score_script = REPO_ROOT / "scripts" / "score_owasp_benchmark.py"
    score_cmd = [
        sys.executable,
        str(score_script),
        "--report",
        str(aegis_report_json),
        "--expected-results",
        str(expected_results_csv),
        "--output-dir",
        str(run_dir / "score"),
    ]

    if family_filter:
        for f in family_filter:
            score_cmd += ["--family", f]

    subprocess.run(score_cmd, check=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        type=Path,
        default=Path(r"D:\BenchmarkPython\testcode"),
        help="Path to OWASP BenchmarkPython testcode directory",
    )
    parser.add_argument(
        "--expected-results",
        type=Path,
        default=Path(r"D:\BenchmarkPython\expectedresults-0.1.csv"),
        help="Path to expectedresults-0.1.csv",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=REPO_ROOT / "rules" / "semgrep-oss-full",
        help="Path to semgrep rules directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "reports" / "benchmark" / "owasp",
        help="Directory to save fresh benchmark artifacts",
    )
    parser.add_argument(
        "--family",
        action="append",
        dest="families",
        help="Filter specific CWE family (e.g. COMMAND_INJECTION, SQL_INJECTION)",
    )
    args = parser.parse_args()

    return run_benchmark(
        target_dir=args.target,
        expected_results_csv=args.expected_results,
        rules_dir=args.rules,
        output_base_dir=args.output_dir,
        family_filter=args.families,
    )


if __name__ == "__main__":
    raise SystemExit(main())

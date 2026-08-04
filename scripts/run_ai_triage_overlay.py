"""Run AI triage as an overlay on top of an existing Aegis JSON report.

Examples:
  python scripts/run_ai_triage_overlay.py reports/manual_targets/demo/aegis_sast_report.json
  python scripts/run_ai_triage_overlay.py reports/manual_targets/demo --output reports/ai/demo_overlay.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.core.models import TriageStatus
from aegis_sast.triage import AITriageRunner


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Review an existing Aegis JSON report with the AI triage overlay "
            "without re-running the detector."
        ),
    )
    parser.add_argument(
        "report",
        help="Path to one JSON report file or a run directory containing it.",
    )
    parser.add_argument(
        "--output",
        help="Optional JSON path for saving the overlay result. Defaults to preview only.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=8,
        help="Maximum reviewed findings to preview in the terminal summary.",
    )
    return parser


def resolve_report_path(report_arg: str) -> Path:
    """Resolve a report selector into one concrete JSON report path."""
    candidate = Path(report_arg)
    if not candidate.is_absolute():
        candidate = (REPO_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    if candidate.is_file():
        return candidate
    if candidate.is_dir():
        report_candidates = sorted(candidate.glob("aegis_sast_report_*.json"))
        if report_candidates:
            return report_candidates[-1]
        json_candidates = sorted(candidate.glob("*.json"))
        if len(json_candidates) == 1:
            return json_candidates[0]
        raise FileNotFoundError(
            f"Could not find a unique JSON report inside run directory: {candidate}"
        )
    raise FileNotFoundError(f"Report path does not exist: {candidate}")


def load_report(report_path: Path) -> dict[str, Any]:
    """Load one JSON report from disk."""
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if "findings" not in report:
        raise ValueError(f"Unsupported report shape: {report_path}")
    return report


def _coerce_status(value: Any) -> TriageStatus:
    """Map report triage strings back into the normalized enum."""
    normalized = str(value or "").strip().lower()
    for status in TriageStatus:
        if normalized == status.value:
            return status
    return TriageStatus.NEEDS_REVIEW


def _coerce_confidence(value: Any) -> float:
    """Clamp a report confidence value into a stable 0.0-1.0 range."""
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = 0.5
    return max(0.0, min(parsed, 1.0))


def _build_legacy_triage_input(finding: dict[str, Any]) -> dict[str, Any]:
    """Create a minimal triage_input payload for older report shapes."""
    evidence = finding.get("evidence", {})
    return {
        "schema_version": "aegis-triage-input-legacy-report-v0",
        "finding": {
            "id": finding.get("id"),
            "tool": finding.get("tool", "aegis-sast"),
            "language": finding.get("language"),
            "rule_id": finding.get("rule_id", finding.get("type")),
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "triage_status": finding.get("triage_status", TriageStatus.NEEDS_REVIEW.value),
            "confidence": _coerce_confidence(finding.get("confidence", 0.5)),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "message": finding.get("message"),
        },
        "evidence": {
            "source": evidence.get("source", {}),
            "sink": evidence.get("sink", {}),
            "intermediate_steps": evidence.get("intermediate_steps", []),
            "sanitizers": evidence.get("sanitizers", []),
            "path_summary": evidence.get("summary", {}).get("path_summary", []),
            "summary": {
                "path_length": evidence.get("summary", {}).get("path_length", 0),
                "intermediate_step_count": evidence.get("summary", {}).get(
                    "intermediate_step_count", 0
                ),
                "sanitizer_count": evidence.get("summary", {}).get("sanitizer_count", 0),
                "has_sanitizers": evidence.get("summary", {}).get("has_sanitizers", False),
            },
            "graph_slice": evidence.get("summary", {}).get("graph_slice", {}),
            "detection": evidence.get("metadata", {}).get("detection", {}),
            "local_helper_summaries": evidence.get("metadata", {}).get(
                "local_callee_summaries", []
            ),
        },
        "guidance": {
            "explanation": finding.get("explanation"),
            "recommendation": finding.get("recommendation"),
        },
        "metadata": {
            "triage": finding.get("metadata", {}).get("triage", {}),
            "detection": finding.get("metadata", {}).get("detection", {}),
        },
    }


def apply_ai_overlay(
    report: dict[str, Any],
    runner: AITriageRunner,
    *,
    source_report: str,
) -> dict[str, Any]:
    """Apply AI review to all findings in one loaded JSON report."""
    findings = report.get("findings", [])
    base_counts: Counter[str] = Counter()
    ai_counts: Counter[str] = Counter()
    results = []
    fallback_count = 0
    legacy_input_count = 0

    for index, finding in enumerate(findings, start=1):
        triage_input = finding.get("triage_input")
        triage_input_present = isinstance(triage_input, dict) and bool(triage_input)
        if not triage_input_present:
            triage_input = _build_legacy_triage_input(finding)
            legacy_input_count += 1

        base_status = _coerce_status(finding.get("triage_status"))
        base_confidence = _coerce_confidence(finding.get("confidence", 0.5))
        decision = runner.review_triage_input(
            triage_input,
            fallback_status=base_status,
            fallback_confidence=base_confidence,
            fallback_explanation=finding.get("explanation") or finding.get("message"),
            fallback_recommendation=finding.get("recommendation"),
        )
        decision_dict = decision.to_dict()
        status_changed = decision.status != base_status
        confidence_delta = round(decision.confidence - base_confidence, 4)
        confidence_changed = abs(confidence_delta) > 1e-9

        base_counts[base_status.value] += 1
        ai_counts[decision.status.value] += 1
        if decision.metadata.get("fallback_used"):
            fallback_count += 1

        results.append(
            {
                "index": index,
                "id": finding.get("id"),
                "type": finding.get("type"),
                "severity": finding.get("severity"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "message": finding.get("message"),
                "base_triage_status": base_status.value,
                "base_confidence": base_confidence,
                "triage_input_schema": triage_input.get("schema_version"),
                "triage_input_present": triage_input_present,
                "status_changed": status_changed,
                "confidence_changed": confidence_changed,
                "confidence_delta": confidence_delta,
                "ai_triage_decision": decision_dict,
            }
        )

    return {
        "schema_version": "aegis-ai-triage-overlay-v1",
        "generated_at": datetime.now().isoformat(),
        "source_report": source_report,
        "scan_metadata": report.get("scan_metadata", {}),
        "summary": {
            "findings_reviewed": len(results),
            "changed_status_count": sum(
                1 for item in results if item["status_changed"]
            ),
            "changed_confidence_count": sum(
                1 for item in results if item["confidence_changed"]
            ),
            "fallback_count": fallback_count,
            "legacy_input_count": legacy_input_count,
            "base_status_counts": dict(base_counts),
            "ai_status_counts": dict(ai_counts),
        },
        "results": results,
    }


def _format_counts(counts: dict[str, int]) -> str:
    """Render compact triage count blocks."""
    ordered_statuses = [
        TriageStatus.CONFIRMED.value,
        TriageStatus.LIKELY.value,
        TriageStatus.NEEDS_REVIEW.value,
        TriageStatus.SUPPRESSED.value,
    ]
    parts = [f"{status}={counts.get(status, 0)}" for status in ordered_statuses]
    return ", ".join(parts)


def render_overlay_summary(
    overlay: dict[str, Any],
    *,
    max_findings: int = 8,
) -> str:
    """Render a compact terminal summary for one overlay result."""
    summary = overlay.get("summary", {})
    lines = [
        "AI Triage Overlay:",
        f"  - source report: {overlay.get('source_report', '')}",
        f"  - findings reviewed: {summary.get('findings_reviewed', 0)}",
        f"  - changed statuses: {summary.get('changed_status_count', 0)}",
        f"  - changed confidences: {summary.get('changed_confidence_count', 0)}",
        f"  - fallback decisions: {summary.get('fallback_count', 0)}",
        f"  - legacy inputs rebuilt: {summary.get('legacy_input_count', 0)}",
        f"  - base triage: {_format_counts(summary.get('base_status_counts', {}))}",
        f"  - ai triage: {_format_counts(summary.get('ai_status_counts', {}))}",
    ]

    results = overlay.get("results", [])
    if results and max_findings > 0:
        lines.append("Reviewed findings:")
        for item in results[:max_findings]:
            file_name = Path(str(item.get("file") or "")).name or "unknown"
            decision = item.get("ai_triage_decision", {})
            lines.append(
                "  - "
                f"#{item.get('index')} {item.get('type')} "
                f"{file_name}:{item.get('line')} | "
                f"{item.get('base_triage_status')} -> {decision.get('status')} | "
                f"conf {item.get('base_confidence', 0.0):.2f} -> "
                f"{float(decision.get('confidence', 0.0)):.2f}"
                + (
                    " | fallback"
                    if decision.get("metadata", {}).get("fallback_used")
                    else ""
                )
            )
    return "\n".join(lines)


def save_overlay(overlay: dict[str, Any], output_path: Path) -> Path:
    """Write the overlay result to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(overlay, indent=2, ensure_ascii=False), encoding="utf-8")
    return output_path


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    args = build_parser().parse_args(argv)
    report_path = resolve_report_path(args.report)
    report = load_report(report_path)
    overlay = apply_ai_overlay(
        report,
        AITriageRunner(),
        source_report=str(report_path),
    )
    print(render_overlay_summary(overlay, max_findings=args.max_findings))

    if args.output:
        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = (REPO_ROOT / output_path).resolve()
        save_overlay(overlay, output_path)
        print(f"Overlay JSON: {output_path}")
    else:
        print("Overlay JSON: not saved (use --output to persist)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

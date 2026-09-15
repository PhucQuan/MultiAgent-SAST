"""Chạy lớp multi-agent (`ai/`) trên một báo cáo Aegis đã quét sẵn.

Ghi `triage_state` của multi-agent đè lên `triage_status` trong một bản sao của
report, để chấm lại bằng đúng `scripts/score_owasp_benchmark.py` mà core dùng.
Nhờ vậy so sánh core-triage với multi-agent-triage là so cùng một thước đo.

Ví dụ:
  python scripts/run_ai_multiagent_benchmark.py \
    --report <aegis_sast_report.json> --limit 10 --workers 4 \
    --output-dir /path/to/out
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Lock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from ai.graph.build import run_triage  # noqa: E402
from ai.config import get_settings  # noqa: E402
from ai.llm.nvidia_client import llm_client, time_budget  # noqa: E402
from ai.schemas.finding import (  # noqa: E402
    DataFlowStep,
    EvidenceBundle,
    Language,
    Location,
    NormalizedFinding,
)

CWE_BY_TYPE = {
    "SQL_INJECTION": "CWE-89",
    "COMMAND_INJECTION": "CWE-78",
    "PATH_TRAVERSAL": "CWE-22",
    "INSECURE_DESERIALIZATION": "CWE-502",
    "SSRF": "CWE-918",
    "CODE_INJECTION": "CWE-94",
    "OPEN_REDIRECT": "CWE-601",
    "XSS": "CWE-79",
    "XPATH_INJECTION": "CWE-643",
    "LDAP_INJECTION": "CWE-90",
    "TRUST_BOUNDARY": "CWE-501",
    "WEAK_CRYPTO": "CWE-327",
    "HARDCODED_SECRET": "CWE-798",
}

SEVERITY_BY_NAME = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "low",
}


def _location(raw: dict) -> Location:
    return Location(
        file=raw.get("file") or raw.get("file_path") or "unknown",
        line=int(raw.get("line") or raw.get("line_number") or 0),
        column=raw.get("column"),
        code_slice=(raw.get("snippet") or raw.get("code_snippet") or "").strip(),
    )


def _evidence_quality(finding: dict) -> float:
    """Ưu tiên evidence_score do auditor node tất định chấm; nếu thiếu thì lấy confidence."""
    review = (finding.get("agent_reviews") or {}).get("auditor_review") or {}
    score = review.get("evidence_score")
    if isinstance(score, (int, float)):
        return max(0.0, min(1.0, float(score)))
    return max(0.0, min(1.0, float(finding.get("confidence") or 0.0)))


def to_ai_finding(finding: dict) -> NormalizedFinding:
    """Chuyển finding trong report của Core sang schema của lớp multi-agent."""
    evidence = finding.get("evidence") or {}
    source = _location(evidence.get("source") or {})
    sink = _location(evidence.get("sink") or {})

    path: list[DataFlowStep] = [
        DataFlowStep(file=source.file, line=source.line, kind="source", code=source.code_slice)
    ]
    for step in evidence.get("intermediate_steps") or []:
        loc = _location(step)
        path.append(
            DataFlowStep(file=loc.file, line=loc.line, kind="propagate", code=loc.code_slice)
        )
    sanitizers: list[str] = []
    for san in evidence.get("sanitizers") or []:
        loc = _location((san or {}).get("location") or san or {})
        label = (san or {}).get("function_name") or (san or {}).get("sanitizer_type") or "sanitizer"
        sanitizers.append(str(label))
        path.append(DataFlowStep(file=loc.file, line=loc.line, kind="sanitizer", code=loc.code_slice))
    path.append(
        DataFlowStep(file=sink.file, line=sink.line, kind="sink", code=sink.code_slice)
    )

    vuln_type = finding.get("type") or finding.get("rule_id") or "UNKNOWN"
    return NormalizedFinding(
        finding_id=finding.get("id") or "unknown",
        vuln_type=vuln_type,
        cwe=CWE_BY_TYPE.get(vuln_type, "CWE-000"),
        language=Language(finding.get("language") or "python"),
        severity=SEVERITY_BY_NAME.get((finding.get("severity") or "MEDIUM").upper(), "medium"),
        confidence=max(0.0, min(1.0, float(finding.get("confidence") or 0.0))),
        evidence=EvidenceBundle(
            source=source,
            sink=sink,
            data_flow_path=path,
            sanitizers_seen=sanitizers,
            evidence_quality=_evidence_quality(finding),
        ),
        metadata={"core_triage_status": finding.get("triage_status")},
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Chạy lớp multi-agent trên report Aegis.")
    p.add_argument("--report", type=Path, required=True, help="Aegis JSON report đã quét sẵn")
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--limit", type=int, default=None, help="Chỉ chạy N finding đầu")
    p.add_argument(
        "--sample-per-family",
        type=int,
        default=None,
        help="Lấy N finding đầu mỗi type, để mẫu phủ đều các family",
    )
    p.add_argument("--family", action="append", default=None, help="Lọc theo type, lặp lại được")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument(
        "--resume",
        type=Path,
        default=None,
        help="File .jsonl của lần chạy trước; bỏ qua các finding đã có kết quả.",
    )
    p.add_argument("--no-cache", action="store_true", help="Bỏ qua cache LLM trên đĩa")
    p.add_argument(
        "--source-root",
        type=Path,
        default=None,
        help="Thư mục mã nguồn để gắn backend tool-use thật. Không truyền thì "
        "code_tools giữ mock và Auditor không đọc được code.",
    )
    return p


def triage_findings(
    findings: list[dict],
    *,
    workers: int = 4,
    checkpoint: Path | None = None,
    results: dict[str, dict] | None = None,
) -> tuple[dict[str, dict], float]:
    """Chạy danh sách finding qua LangGraph multi-agent.

    Dùng chung cho runner benchmark và cho `scan_with_ai.py`, để hai đường chạy
    không trôi khác nhau về hành vi. Trả về (bảng kết quả, wall clock).
    """
    results = results if results is not None else {}
    lock = Lock()
    done = {"n": 0}
    total = len(findings)
    started = time.time()

    # Để `scripts/watch_ai_progress.py` biết tổng số finding mà không cần --total.
    if checkpoint is not None:
        (checkpoint.parent / "run_meta.json").write_text(
            json.dumps(
                {"total": total, "workers": workers, "started_at": datetime.now().isoformat()},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def work(raw: dict) -> None:
        fid = raw.get("id")
        t0 = time.time()
        try:
            # Trần thời gian cho mỗi finding: một model kẹt không được phép kéo
            # cả lần chạy đi hàng giờ.
            with time_budget(get_settings().finding_budget_sec):
                state = run_triage(to_ai_finding(raw))
            row = {
                "finding_id": fid,
                "type": raw.get("type"),
                "file": raw.get("file"),
                "line": raw.get("line"),
                "core_triage_status": raw.get("triage_status"),
                "ai_triage_state": state.triage_state.value if state.triage_state else None,
                "llm_failed": state.llm_failed,
                "debate_round": state.debate_round,
                "skeptic_mode": state.skeptic_mode,
                "tool_calls": len(state.tool_calls_made),
                "knowledge_cards": len(state.knowledge_cards),
                "auditor": (
                    state.auditor_verdict.model_dump() if state.auditor_verdict else None
                ),
                "skeptic": (
                    state.skeptic_verdict.model_dump() if state.skeptic_verdict else None
                ),
                "judge": state.judge_decision.model_dump() if state.judge_decision else None,
                "elapsed_sec": round(time.time() - t0, 1),
            }
        except Exception as e:  # fail-open ở mức harness
            row = {
                "finding_id": fid,
                "type": raw.get("type"),
                "file": raw.get("file"),
                "line": raw.get("line"),
                "core_triage_status": raw.get("triage_status"),
                "ai_triage_state": "needs-review",
                "llm_failed": True,
                "harness_error": f"{type(e).__name__}: {e}",
                "elapsed_sec": round(time.time() - t0, 1),
            }
        with lock:
            results[fid] = row
            if checkpoint is not None:
                with checkpoint.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            done["n"] += 1
            print(
                f"  [{done['n']:>3}/{total}] {fid} {str(raw.get('type')):<26} "
                f"core={str(raw.get('triage_status')):<12} "
                f"ai={row['ai_triage_state']:<12} {row['elapsed_sec']:>6}s",
                flush=True,
            )

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(work, findings))
    return results, time.time() - started


def build_overlay(report: dict, results: dict[str, dict]) -> dict:
    """Bản sao report với `triage_status` thay bằng quyết định của multi-agent.

    Nhờ vậy chấm lại được bằng đúng `scripts/score_owasp_benchmark.py`.
    """
    overlay = json.loads(json.dumps(report))
    kept = []
    for raw in overlay.get("findings") or []:
        row = results.get(raw.get("id"))
        if row is None:
            continue
        raw["triage_status"] = row["ai_triage_state"] or "needs-review"
        kept.append(raw)
    overlay["findings"] = kept
    return overlay


def use_cold_cache() -> str:
    """Trỏ cache LLM sang thư mục tạm rỗng để đo trên cache lạnh."""
    import tempfile

    import diskcache

    tmp_cache = tempfile.mkdtemp(prefix="aegis-llm-cache-")
    llm_client._cache = diskcache.Cache(tmp_cache)
    return tmp_cache


def main() -> None:
    args = build_parser().parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    findings = report.get("findings") or []
    if args.family:
        wanted = {f.upper() for f in args.family}
        findings = [f for f in findings if (f.get("type") or "").upper() in wanted]
    if args.sample_per_family:
        from collections import defaultdict

        seen: dict[str, int] = defaultdict(int)
        sampled = []
        for f in findings:
            t = f.get("type") or "UNKNOWN"
            if seen[t] < args.sample_per_family:
                seen[t] += 1
                sampled.append(f)
        findings = sampled
    if args.limit:
        findings = findings[: args.limit]

    if args.source_root:
        from python_code_tools_backend import bind_python_backend

        backend = bind_python_backend(args.source_root)
        print(
            f"[i] tool backend: {args.source_root} "
            f"({backend.function_count} hàm đã index)"
        )
    else:
        print("[i] tool backend: MOCK (Auditor không đọc được mã nguồn)")

    print(f"[i] report      : {args.report}")
    print(f"[i] finding chạy: {len(findings)}")
    print(f"[i] workers     : {args.workers}")

    results: dict[str, dict] = {}
    if args.resume and args.resume.exists():
        for line in args.resume.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                results[row["finding_id"]] = row
        before = len(findings)
        findings = [f for f in findings if f["id"] not in results]
        print(f"[i] resume      : bỏ qua {before - len(findings)} finding đã có")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.no_cache:
        print(f"[i] cache lạnh  : {use_cold_cache()}")

    # Checkpoint từng dòng: một lần chạy dài bị đứt sẽ không mất sạch kết quả.
    results, wall = triage_findings(
        findings,
        workers=args.workers,
        checkpoint=args.output_dir / "checkpoint.jsonl",
        results=results,
    )

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    usage = llm_client.get_usage_summary()
    decisions_path = args.output_dir / f"ai_multiagent_decisions_{stamp}.json"
    decisions_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "source_report": str(args.report),
                "finding_count": len(results),
                "wall_clock_sec": round(wall, 1),
                "llm_usage": usage,
                "results": list(results.values()),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    overlay_path = args.output_dir / f"aegis_report_ai_overlay_{stamp}.json"
    overlay_path.write_text(
        json.dumps(build_overlay(report, results), ensure_ascii=False), encoding="utf-8"
    )

    from collections import Counter

    print(f"\n[ok] quyết định : {decisions_path}")
    print(f"[ok] overlay    : {overlay_path}")
    print(f"[ok] wall clock : {wall:.1f}s cho {len(results)} finding")
    print(f"[ok] LLM usage  : {usage}")
    print(f"[ok] phân bố ai : {dict(Counter(r['ai_triage_state'] for r in results.values()))}")
    print(f"[ok] llm_failed : {sum(1 for r in results.values() if r.get('llm_failed'))}")


if __name__ == "__main__":
    main()

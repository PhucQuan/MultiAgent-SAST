"""Quét một target rồi cho lớp multi-agent triage lại — trong MỘT lệnh.

Đây là đường chạy dành cho người dùng, khác với `run_ai_multiagent_benchmark.py`
(chỉ nhận report có sẵn, dùng để đo benchmark).

Luồng:
  1. Quét tất định bằng Core SAST  -> report JSON + triage tất định
  2. Gắn tool backend đọc mã nguồn thật của chính target
  3. Đưa từng finding qua LangGraph: Planner -> Hypothesis -> Knowledge
     -> Auditor (tool-use) -> Skeptic -> Judge
  4. Ghi report overlay (triage_status = quyết định của multi-agent) + bảng so sánh

Ví dụ:
  python scripts/scan_with_ai.py examples/vulnerable_sqli.py
  python scripts/scan_with_ai.py /duong/dan/du-an --workers 4 --limit 20
  python scripts/scan_with_ai.py /duong/dan/du-an --no-ai-triage   # chỉ quét, không gọi LLM

Cần `NVIDIA_API_KEY` trong `.env`. Xem `ai/README.md`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
for _p in (REPO_ROOT, SCRIPT_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from run_ai_multiagent_benchmark import (  # noqa: E402
    build_overlay,
    triage_findings,
    use_cold_cache,
)
from scan_target import run_manual_scan  # noqa: E402

STATE_ORDER = ["confirmed", "likely", "needs-review", "suppressed"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Quét target rồi triage bằng lớp multi-agent (NVIDIA NIM).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", type=Path, help="File hoặc thư mục cần quét")
    p.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Thư mục ghi artifact. Mặc định reports/ai_scans/<target>-<timestamp>",
    )
    p.add_argument("--workers", type=int, default=4, help="Số finding chạy song song")
    p.add_argument("--limit", type=int, default=None, help="Chỉ triage N finding đầu")
    p.add_argument(
        "--family", action="append", default=None, help="Lọc theo loại lỗ hổng, lặp lại được"
    )
    p.add_argument("--max-depth", type=int, default=5, help="Độ sâu taint của detector")
    p.add_argument(
        "--no-ai-triage",
        action="store_true",
        help="Chỉ chạy quét tất định, bỏ qua lớp multi-agent (không tốn credit LLM)",
    )
    p.add_argument(
        "--no-cache", action="store_true", help="Bỏ qua cache LLM trên đĩa (đo cache lạnh)"
    )
    p.add_argument(
        "--exclude-dir", action="append", default=None, help="Bỏ qua thư mục, lặp lại được"
    )
    return p


def find_report_json(output_dir: Path) -> Path | None:
    candidates = sorted(
        output_dir.glob("aegis_sast_report_*.json"), key=lambda p: p.stat().st_mtime
    )
    return candidates[-1] if candidates else None


def main() -> int:
    args = build_parser().parse_args()
    target = args.target.resolve()
    if not target.exists():
        print(f"[x] Không tìm thấy target: {target}", file=sys.stderr)
        return 1

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.output_dir or (
        REPO_ROOT / "reports" / "ai_scans" / f"{target.name}-{stamp}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Bước 1: quét tất định -------------------------------------------
    print(f"[1/3] Quét tất định: {target}")
    run_manual_scan(
        target=target,
        output_dir=out_dir,
        formats=["json", "markdown"],
        max_depth=args.max_depth,
        with_ai=False,  # đây là cờ của lớp Gemini cũ, KHÔNG liên quan tới ai/
        exclude_dirs=args.exclude_dir,
        emit_console=False,
    )
    report_path = find_report_json(out_dir)
    if report_path is None:
        print("[x] Không tìm thấy report JSON sau khi quét", file=sys.stderr)
        return 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings = report.get("findings") or []
    print(f"      -> {len(findings)} finding | {report_path.name}")

    if not findings:
        print("[ok] Không có finding nào, dừng.")
        return 0

    if args.family:
        wanted = {f.upper() for f in args.family}
        findings = [f for f in findings if (f.get("type") or "").upper() in wanted]
    if args.limit:
        findings = findings[: args.limit]

    if args.no_ai_triage:
        print("[2/3] Bỏ qua lớp multi-agent (--no-ai-triage)")
        print(f"[ok] Report: {report_path}")
        return 0

    # --- Bước 2: gắn tool backend đọc mã nguồn thật -----------------------
    print(f"[2/3] Gắn tool backend vào {target}")
    from python_code_tools_backend import bind_python_backend

    root = target if target.is_dir() else target.parent
    backend = bind_python_backend(root)
    print(f"      -> {backend.function_count} hàm Python đã index")
    if backend.function_count == 0:
        print(
            "      [!] Không index được hàm nào. Backend tool hiện chỉ đọc Python; "
            "với JS/Java/PHP, agent chỉ suy luận trên evidence của detector."
        )

    if args.no_cache:
        print(f"      -> cache lạnh: {use_cold_cache()}")

    # --- Bước 3: triage bằng multi-agent ----------------------------------
    print(f"[3/3] Triage {len(findings)} finding bằng multi-agent (workers={args.workers})")
    results, wall = triage_findings(
        findings, workers=args.workers, checkpoint=out_dir / "checkpoint.jsonl"
    )

    from ai.llm.nvidia_client import llm_client

    usage = llm_client.get_usage_summary()
    decisions_path = out_dir / "ai_triage_decisions.json"
    decisions_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "target": str(target),
                "source_report": str(report_path),
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
    overlay_path = out_dir / "aegis_report_ai_overlay.json"
    overlay_path.write_text(
        json.dumps(build_overlay(report, results), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # --- Tóm tắt ----------------------------------------------------------
    counts = Counter(r["ai_triage_state"] for r in results.values())
    changed = [
        r for r in results.values() if r["ai_triage_state"] != r["core_triage_status"]
    ]
    failed = [r for r in results.values() if r.get("llm_failed")]

    print("\n" + "=" * 72)
    print(f"KẾT QUẢ  {len(results)} finding  |  {wall:.1f}s  |  "
          f"{usage.get('total_calls', 0)} LLM call")
    print("=" * 72)
    for state in STATE_ORDER:
        if counts.get(state):
            print(f"  {state:<14} {counts[state]:>4}")
    if failed:
        print(f"\n  [!] {len(failed)} finding rơi vào fail-open (LLM hỏng) -> needs-review")
    if usage.get("truncated_calls"):
        print(f"  [!] {usage['truncated_calls']} call bị cắt output (chạm max_tokens)")

    if changed:
        print(f"\nMulti-agent đổi kết luận so với triage tất định ({len(changed)}):")
        for r in sorted(changed, key=lambda x: str(x["finding_id"])):
            loc = f"{Path(str(r.get('file') or '')).name}:{r.get('line')}"
            print(f"  {str(r['finding_id']):<10} {str(r['type']):<26} {loc:<28} "
                  f"{r['core_triage_status']} -> {r['ai_triage_state']}")

    print(f"\nArtifact:")
    print(f"  report gốc : {report_path}")
    print(f"  overlay AI : {overlay_path}")
    print(f"  chi tiết   : {decisions_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

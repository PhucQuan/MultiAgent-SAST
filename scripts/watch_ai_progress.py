"""Thanh tiến độ trực tiếp cho một lần chạy triage multi-agent.

Đọc `checkpoint.jsonl` mà runner ghi sau mỗi finding, nên xem được cả những
lần chạy nền do người khác khởi động, và cả sau khi lần chạy đã kết thúc.

Ví dụ:
  python scripts/watch_ai_progress.py                     # tự tìm lần chạy mới nhất
  python scripts/watch_ai_progress.py <thư-mục-kết-quả>
  python scripts/watch_ai_progress.py <thư-mục> --total 144
  python scripts/watch_ai_progress.py --once              # in một lần rồi thoát
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from datetime import timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SEARCH_ROOTS = [
    REPO_ROOT / "reports" / "ai_scans",
    Path("/Users/ductue/NCKH/AegisBenchmarkArtifacts"),
]

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
    from rich.table import Table
except ModuleNotFoundError:  # pragma: no cover
    Console = None


def newest_run() -> Path | None:
    """Thư mục có checkpoint.jsonl được ghi gần đây nhất."""
    candidates: list[Path] = []
    for root in SEARCH_ROOTS:
        if root.exists():
            candidates.extend(root.glob("*/checkpoint.jsonl"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime).parent


def read_rows(checkpoint: Path) -> list[dict]:
    if not checkpoint.exists():
        return []
    rows = []
    for line in checkpoint.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # dòng đang được ghi dở
    return rows


def resolve_total(run_dir: Path, override: int | None) -> int | None:
    if override:
        return override
    meta = run_dir / "run_meta.json"
    if meta.exists():
        try:
            return int(json.loads(meta.read_text(encoding="utf-8"))["total"])
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
    return None


def render(run_dir: Path, rows: list[dict], total: int | None, started: float):
    done = len(rows)
    counts = Counter(r.get("ai_triage_state") for r in rows)
    failed = sum(1 for r in rows if r.get("llm_failed"))
    # Tốc độ tính theo thời gian thực đã trôi, không phải tổng elapsed_sec của
    # từng finding, vì các finding chạy song song.
    wall = max(time.time() - started, 1e-6)
    rate = done / wall if done else 0.0

    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style="dim")
    table.add_column()
    table.add_row("Thư mục", str(run_dir))
    if total:
        pct = done / total * 100
        bar_len = 40
        filled = int(bar_len * done / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        table.add_row("Tiến độ", f"[green]{bar}[/green] {done}/{total}  ({pct:.0f}%)")
        if rate > 0 and done < total:
            eta = timedelta(seconds=int((total - done) / rate))
            table.add_row("Còn lại", f"~{eta}")
    else:
        table.add_row("Tiến độ", f"{done} finding xong (chưa biết tổng)")
    table.add_row("Đã chạy", str(timedelta(seconds=int(wall))))
    if rows:
        avg = sum(r.get("elapsed_sec", 0) for r in rows) / len(rows)
        table.add_row("TB/finding", f"{avg:.1f}s")
    dist = "  ".join(
        f"[bold]{k}[/bold]={v}" for k, v in sorted(counts.items(), key=lambda x: str(x[0]))
    )
    table.add_row("Kết quả", dist or "—")
    if failed:
        table.add_row("[yellow]Fail-open[/yellow]", f"[yellow]{failed}[/yellow]")
    if rows:
        last = rows[-1]
        table.add_row(
            "Mới nhất",
            f"{last.get('finding_id')} {last.get('type')} → {last.get('ai_triage_state')}",
        )
    status = "ĐANG CHẠY" if not total or done < total else "XONG"
    return Panel(table, title=f"Aegis multi-agent triage — {status}", border_style="cyan")


def plain(run_dir: Path, rows: list[dict], total: int | None) -> str:
    done = len(rows)
    counts = Counter(r.get("ai_triage_state") for r in rows)
    head = f"{done}/{total}" if total else str(done)
    return f"{run_dir.name}: {head} finding | {dict(counts)}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", type=Path, nargs="?", default=None)
    ap.add_argument("--total", type=int, default=None, help="Tổng số finding của lần chạy")
    ap.add_argument("--once", action="store_true", help="In một lần rồi thoát")
    ap.add_argument("--interval", type=float, default=2.0, help="Giây giữa hai lần làm mới")
    args = ap.parse_args()

    run_dir = args.run_dir or newest_run()
    if run_dir is None:
        print("[x] Không tìm thấy lần chạy nào có checkpoint.jsonl.")
        return 1
    checkpoint = run_dir / "checkpoint.jsonl"
    total = resolve_total(run_dir, args.total)
    started = checkpoint.stat().st_mtime if checkpoint.exists() else time.time()
    # Ước lượng thời điểm bắt đầu từ dòng đầu tiên nếu có
    rows = read_rows(checkpoint)
    if rows:
        started = min(started, time.time() - sum(r.get("elapsed_sec", 0) for r in rows))

    if Console is None or args.once:
        print(plain(run_dir, read_rows(checkpoint), total))
        return 0

    console = Console()
    with Live(console=console, refresh_per_second=4) as live:
        while True:
            rows = read_rows(checkpoint)
            live.update(render(run_dir, rows, total, started))
            if total and len(rows) >= total:
                break
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

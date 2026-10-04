"""Đối chiếu quyết định của lớp multi-agent với ground truth OWASP Benchmark.

Chấm ở mức finding (không phải mức case × family như score_owasp_benchmark.py),
vì mẫu nhỏ không phủ hết 1230 case nên recall toàn cục sẽ vô nghĩa.

Một finding được coi là "giữ lại" nếu triage_state khác `suppressed`.

Ví dụ:
  python scripts/compare_ai_triage_ground_truth.py \
    --decisions <ai_multiagent_decisions_*.json> \
    --report <aegis_sast_report.json> \
    --expected-results /path/to/expectedresults-0.1.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def load_expected(path: Path) -> dict[str, tuple[str, bool, str]]:
    out: dict[str, tuple[str, bool, str]] = {}
    with path.open(encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            out[row[0].strip()] = (
                row[1].strip(),
                row[2].strip().lower() == "true",
                row[3].strip(),
            )
    return out


def case_of(finding: dict) -> str:
    return re.sub(r"\.py$", "", (finding.get("file") or "").split("/")[-1])


def confusion(rows: list[dict], key: str) -> dict[str, int]:
    """TP/FP/TN/FN ở mức finding cho một cột trạng thái triage."""
    tp = fp = tn = fn = 0
    for r in rows:
        if r["ground_truth"] is None:
            continue
        kept = (r[key] or "") != "suppressed"
        if r["ground_truth"] and kept:
            tp += 1
        elif r["ground_truth"] and not kept:
            fn += 1
        elif not r["ground_truth"] and kept:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--decisions", type=Path, required=True)
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--expected-results", type=Path, required=True)
    ap.add_argument("--output", type=Path, default=None)
    args = ap.parse_args()

    expected = load_expected(args.expected_results)
    report = json.loads(args.report.read_text(encoding="utf-8"))
    by_id = {f["id"]: f for f in report.get("findings") or []}
    decisions = json.loads(args.decisions.read_text(encoding="utf-8"))

    rows: list[dict] = []
    for r in decisions["results"]:
        finding = by_id.get(r["finding_id"])
        if finding is None:
            continue
        case = case_of(finding)
        cat, real, cwe = expected.get(case, ("?", None, "?"))
        rows.append({
            "finding_id": r["finding_id"],
            "case": case,
            "type": r["type"],
            "gt_category": cat,
            "gt_cwe": cwe,
            "ground_truth": real,
            "core": r["core_triage_status"],
            "ai": r["ai_triage_state"],
            "llm_failed": r.get("llm_failed"),
            "skeptic_ran": r.get("skeptic") is not None,
            "debate_round": r.get("debate_round"),
            "tool_calls": r.get("tool_calls"),
        })

    hdr = (f"{'finding':<10} {'case':<20} {'type':<26} {'thật?':<6} "
           f"{'core':<13} {'ai':<13} {'skeptic':<8} {'debate':<7} {'tool'}")
    print(hdr); print("-" * len(hdr))
    for r in rows:
        print(f"{r['finding_id']:<10} {r['case']:<20} {r['type']:<26} "
              f"{str(r['ground_truth']):<6} {str(r['core']):<13} {str(r['ai']):<13} "
              f"{str(r['skeptic_ran']):<8} {str(r['debate_round']):<7} {r['tool_calls']}")

    core_m = confusion(rows, "core")
    ai_m = confusion(rows, "ai")
    print(f"\n{'Lớp triage':<26} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Precision':>10} {'Recall':>8} {'F1':>8}")
    for name, m in (("Core (tất định)", core_m), ("Multi-agent (LLM)", ai_m)):
        print(f"{name:<26} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} {m['fn']:>4} "
              f"{m['precision']:>10} {m['recall']:>8} {m['f1']:>8}")

    if args.output:
        args.output.write_text(
            json.dumps({"rows": rows, "core": core_m, "multi_agent": ai_m},
                       ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[ok] {args.output}")


if __name__ == "__main__":
    main()

"""Chấm report Aegis trên benchmark RealVuln (mã Python người viết, có nhãn tay).

Khác với OWASP Benchmark — nơi mỗi file là đúng một test case và nhãn gắn theo
tên file — RealVuln gán nhãn theo `file + [start_line, end_line]`. Vì vậy cần
một quy tắc khớp tường minh, và quy tắc đó quyết định con số cuối cùng nhiều
hơn bất kỳ tham số nào khác. Ba lựa chọn ở đây, cùng lý do:

* **Khớp theo vùng dòng có nới lỏng.** Một finding được tính là khớp một nhãn
  khi cùng file và dòng của nó nằm trong `[start_line - tol, end_line + tol]`.
  Cần dung sai vì SAST báo tại *sink* trong khi người gán nhãn thường khoanh cả
  khối hàm; mặc định `--tolerance 5`.

* **Khớp theo họ lỗ hổng, không theo mã CWE chính xác.** Ground truth có
  `acceptable_cwes`, và các họ như SQL injection trải trên CWE-89/564/943.
  So khớp cứng theo `primary_cwe` sẽ đánh trượt những phát hiện đúng bản chất.

* **Một nhãn chỉ được ghi nhận một lần.** Nhiều finding cùng trỏ vào một nhãn
  chỉ tính một true positive; các finding thừa tính là trùng lặp chứ không phải
  false positive, vì phạt hai lần cho cùng một chỗ sẽ bóp méo precision.

Finding không khớp nhãn nào được tính false positive **chỉ khi** nó nằm trong
một file mà ground truth có xét tới. File không ai gán nhãn thì không thể kết
luận đúng hay sai, nên bị loại khỏi phép tính thay vì mặc định coi là sai —
đây là điểm khác cốt lõi so với OWASP Benchmark, nơi mọi file đều có nhãn.

Ví dụ:
  python scripts/score_realvuln.py \
    --scans <thư-mục-chứa-các-report> \
    --ground-truth <realvuln>/ground-truth \
    --output-dir reports/benchmark/realvuln
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Ánh xạ CWE -> họ lỗ hổng của Aegis. Chỉ liệt kê các họ công cụ thực sự hỗ trợ;
# nhãn mang CWE ngoài bảng này nằm ngoài phạm vi đánh giá.
CWE_TO_FAMILY: dict[str, str] = {
    "CWE-89": "SQL_INJECTION",
    "CWE-564": "SQL_INJECTION",
    "CWE-943": "SQL_INJECTION",
    "CWE-78": "COMMAND_INJECTION",
    "CWE-77": "COMMAND_INJECTION",
    "CWE-22": "PATH_TRAVERSAL",
    "CWE-23": "PATH_TRAVERSAL",
    "CWE-35": "PATH_TRAVERSAL",
    "CWE-94": "CODE_INJECTION",
    "CWE-95": "CODE_INJECTION",
    "CWE-601": "OPEN_REDIRECT",
    "CWE-502": "INSECURE_DESERIALIZATION",
}

DEFAULT_FAMILIES = sorted(set(CWE_TO_FAMILY.values()))

# Trạng thái triage bị coi là "đã giấu khỏi báo cáo".
SUPPRESSED = {"suppressed"}
HIGH_CONFIDENCE = {"confirmed", "likely"}


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    duplicates: int = 0
    matched_labels: set = field(default_factory=set)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "duplicates": self.duplicates,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def family_of_label(label: dict) -> str | None:
    """Họ lỗ hổng của một nhãn, xét cả acceptable_cwes."""
    for cwe in [label.get("primary_cwe")] + list(label.get("acceptable_cwes") or []):
        if cwe in CWE_TO_FAMILY:
            return CWE_TO_FAMILY[cwe]
    return None


def normalize_path(path: str, repo_root: Path | None) -> str:
    """Đưa đường dẫn về dạng tương đối so với gốc repo để so khớp được."""
    p = Path(path)
    if repo_root is not None:
        try:
            return str(p.resolve().relative_to(repo_root.resolve()))
        except (ValueError, OSError):
            pass
    return str(p)


def load_scan(report_path: Path) -> tuple[list[dict], Path | None]:
    data = json.loads(report_path.read_text())
    target = data.get("scan_metadata", {}).get("target")
    return data.get("findings", []), (Path(target) if target else None)


def score_repo(
    findings: list[dict],
    repo_root: Path | None,
    labels: list[dict],
    families: set[str],
    tolerance: int,
    mode: str,
) -> tuple[Counts, list[dict]]:
    """Chấm một repo. Trả về (counts, danh sách finding kèm phán quyết)."""
    in_scope = [
        (i, lab)
        for i, lab in enumerate(labels)
        if family_of_label(lab) in families
    ]
    # Chỉ những file mà người gán nhãn đã xét mới được dùng để đếm false
    # positive; file không ai xem thì không có căn cứ nói đúng hay sai.
    reviewed_files = {lab["file"] for lab in labels}

    counts = Counts()
    details: list[dict] = []

    for f in findings:
        status = str(f.get("triage_status", "")).lower()
        if mode == "visible" and status in SUPPRESSED:
            continue
        if mode == "high_confidence" and status not in HIGH_CONFIDENCE:
            continue

        fam = str(f.get("type", ""))
        if fam not in families:
            continue

        rel = normalize_path(f.get("file", ""), repo_root)
        line = int(f.get("line") or 0)

        if rel not in reviewed_files:
            details.append({"file": rel, "line": line, "family": fam,
                            "verdict": "outside_reviewed_files"})
            continue

        hit = None
        for idx, lab in in_scope:
            if lab["file"] != rel:
                continue
            if family_of_label(lab) != fam:
                continue
            loc = lab.get("location") or {}
            lo = int(loc.get("start_line", 0)) - tolerance
            hi = int(loc.get("end_line", loc.get("start_line", 0))) + tolerance
            if lo <= line <= hi:
                hit = (idx, lab)
                break

        if hit is None:
            counts.fp += 1
            details.append({"file": rel, "line": line, "family": fam,
                            "verdict": "false_positive"})
            continue

        idx, lab = hit
        if not lab["is_vulnerable"]:
            # Trúng một FP trap: mẫu trông đáng ngờ nhưng đã được xác nhận an toàn.
            counts.fp += 1
            details.append({"file": rel, "line": line, "family": fam,
                            "verdict": "hit_fp_trap", "label_id": lab["id"]})
            continue

        if idx in counts.matched_labels:
            counts.duplicates += 1
            details.append({"file": rel, "line": line, "family": fam,
                            "verdict": "duplicate", "label_id": lab["id"]})
            continue

        counts.matched_labels.add(idx)
        counts.tp += 1
        details.append({"file": rel, "line": line, "family": fam,
                        "verdict": "true_positive", "label_id": lab["id"]})

    for idx, lab in in_scope:
        if lab["is_vulnerable"] and idx not in counts.matched_labels:
            counts.fn += 1
        elif not lab["is_vulnerable"] and idx not in counts.matched_labels:
            # FP trap mà công cụ không báo = tránh được cái bẫy.
            counts.tn += 1

    return counts, details


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scans", type=Path, required=True,
                    help="Thư mục chứa <slug>/aegis_sast_report_*.json")
    ap.add_argument("--ground-truth", type=Path, required=True,
                    help="Thư mục ground-truth của RealVuln")
    ap.add_argument("--family", action="append", default=None,
                    help="Giới hạn họ lỗ hổng, lặp lại được")
    ap.add_argument("--tolerance", type=int, default=5,
                    help="Dung sai số dòng khi khớp nhãn (mặc định 5)")
    ap.add_argument("--authorship", default="human_authored",
                    help="Lọc theo authorship; 'all' để lấy hết")
    ap.add_argument("--output-dir", type=Path, default=None)
    args = ap.parse_args()

    families = set(args.family or DEFAULT_FAMILIES)
    totals = {m: Counts() for m in ("all", "visible", "high_confidence")}
    per_family = {m: defaultdict(Counts) for m in totals}
    per_repo: dict[str, dict] = {}
    all_details: dict[str, list] = {}
    repos_used = 0

    for gt_file in sorted(args.ground_truth.glob("*/ground-truth.json")):
        gt = json.loads(gt_file.read_text())
        if str(gt.get("language", "")).lower() != "python":
            continue
        if args.authorship != "all" and gt.get("authorship") != args.authorship:
            continue
        slug = gt_file.parent.name
        reports = sorted((args.scans / slug).glob("aegis_sast_report_*.json"))
        if not reports:
            continue
        findings, repo_root = load_scan(reports[-1])
        repos_used += 1

        per_repo[slug] = {}
        for mode in totals:
            counts, details = score_repo(
                findings, repo_root, gt["findings"], families, args.tolerance, mode
            )
            totals[mode].tp += counts.tp
            totals[mode].fp += counts.fp
            totals[mode].fn += counts.fn
            totals[mode].tn += counts.tn
            totals[mode].duplicates += counts.duplicates
            per_repo[slug][mode] = counts.as_dict()
            if mode == "visible":
                all_details[slug] = details

            for fam in families:
                fc = per_family[mode][fam]
                fam_labels = [
                    lab for lab in gt["findings"] if family_of_label(lab) == fam
                ]
                sub, _ = score_repo(
                    findings, repo_root, gt["findings"], {fam}, args.tolerance, mode
                )
                fc.tp += sub.tp
                fc.fp += sub.fp
                fc.fn += sub.fn
                fc.tn += sub.tn
                _ = fam_labels

    print(f"Repo chấm được : {repos_used}")
    print(f"Phạm vi họ     : {', '.join(sorted(families))}")
    print(f"Dung sai dòng  : ±{args.tolerance}")
    print()
    print(f"{'Mode':18}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'dup':>5}"
          f"{'Precision':>11}{'Recall':>9}{'F1':>9}")
    print("-" * 72)
    for mode, c in totals.items():
        print(f"{mode:18}{c.tp:5}{c.fp:5}{c.fn:5}{c.tn:5}{c.duplicates:5}"
              f"{c.precision:11.4f}{c.recall:9.4f}{c.f1:9.4f}")
    print()
    print(f"{'Họ (mode=visible)':30}{'TP':>5}{'FP':>5}{'FN':>5}"
          f"{'Precision':>11}{'Recall':>9}{'F1':>9}")
    print("-" * 72)
    for fam in sorted(families):
        c = per_family["visible"][fam]
        print(f"{fam:30}{c.tp:5}{c.fp:5}{c.fn:5}"
              f"{c.precision:11.4f}{c.recall:9.4f}{c.f1:9.4f}")

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "benchmark": "RealVuln",
            "repos_scored": repos_used,
            "families": sorted(families),
            "tolerance": args.tolerance,
            "authorship": args.authorship,
            "modes": {m: c.as_dict() for m, c in totals.items()},
            "per_family": {
                m: {f: c.as_dict() for f, c in fams.items()}
                for m, fams in per_family.items()
            },
            "per_repo": per_repo,
        }
        (args.output_dir / "realvuln_score_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False)
        )
        (args.output_dir / "finding_details.json").write_text(
            json.dumps(all_details, indent=2, ensure_ascii=False)
        )
        print(f"\nĐã ghi {args.output_dir}/realvuln_score_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

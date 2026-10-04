"""Chấm Aegis trên PySASTBench SyntheticDataset (cặp vulnerable/fixed).

Dataset đi kèm bài "An Empirical Study on Static Application Security Testing
(SAST) Tools for Python" (https://github.com/Victor725/PySASTBench). Mỗi test
case là một cặp file cùng tên: `<cwe>_DS-<n>_vul.py` chứa lỗ hổng, và
`<cwe>_DS-<n>_fix.py` là chính đoạn mã đó sau khi đã vá.

Cấu trúc cặp này cho một phép đo sạch hơn hẳn benchmark một chiều: bản vá
thường chỉ khác bản lỗi ở đúng cơ chế phòng thủ, mọi thứ còn lại giữ nguyên.
Vì vậy một công cụ báo lỗi trên cả hai bản không phân biệt được gì — nó chỉ
đang khớp mẫu sink. Số false positive ở đây do đó có ý nghĩa hơn nhiều so với
false positive đo trên mã ngẫu nhiên.

Quy tắc chấm, ở mức TEST CASE chứ không phải mức finding:

* file `_vul.py` có ít nhất một finding đúng họ lỗ hổng -> true positive;
  không có -> false negative;
* file `_fix.py` có finding đúng họ -> false positive; không có -> true negative.

Hai chế độ khớp, chọn bằng `--match`:

* `official` (mặc định) — theo đúng `scripts/evaluate/Synthetic/parsers.py` của
  nhóm tác giả: finding phải vừa đúng họ lỗ hổng, vừa nằm trong đúng hàm ghi ở
  cột `Vul Position` của `SyntheticDataset.csv`. Tên hàm lấy bằng cách dò cây
  AST tìm scope bao dòng đó, nối bằng dấu chấm cho hàm lồng trong lớp. Dùng chế
  độ này khi cần so sánh với bảng trong bài báo.
* `family` — chỉ cần đúng họ, không xét hàm. Rộng rãi hơn, nên cho chặn trên
  của recall; hữu ích để tách riêng câu hỏi "có phát hiện được gì không" khỏi
  câu hỏi "có chỉ đúng chỗ không".

Ví dụ:
  python scripts/score_pysastbench.py \
    --dataset <pysastbench>/SyntheticDataset \
    --output-dir reports/benchmark/pysastbench
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# CWE trong dataset -> họ lỗ hổng của Aegis.
CWE_TO_FAMILY = {
    "22": "PATH_TRAVERSAL",
    "77": "COMMAND_INJECTION",
    "79": "XSS",
    "89": "SQL_INJECTION",
    "94": "CODE_INJECTION",
    "502": "INSECURE_DESERIALIZATION",
}

# Sáu họ nằm trong phạm vi đánh giá đã chốt của Aegis. XSS có trong enum của
# công cụ nhưng không thuộc phạm vi này, nên được báo cáo tách riêng.
IN_SCOPE = {
    "PATH_TRAVERSAL",
    "COMMAND_INJECTION",
    "SQL_INJECTION",
    "CODE_INJECTION",
    "INSECURE_DESERIALIZATION",
    "OPEN_REDIRECT",
}

SUPPRESSED = {"suppressed"}
HIGH_CONFIDENCE = {"confirmed", "likely"}


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

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
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }



def get_enclosing_scope(path: Path, line_num: int) -> str:
    """Tên hàm/lớp bao quanh một dòng, dạng 'Lop.ham'.

    Cài lại theo `getFunc` trong parsers.py của nhóm tác giả, để tên sinh ra ở
    đây khớp đúng định dạng của cột `Vul Position`.
    """
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, OSError):
        return ""

    scope: list[str] = []
    current: ast.AST | None = tree

    def find_body(node: ast.AST):
        body = getattr(node, "body", None)
        if body is None:
            return None
        if isinstance(node, ast.Try):
            body = body + node.handlers + node.orelse + node.finalbody
        for n in body:
            lineno = getattr(n, "lineno", None)
            end = getattr(n, "end_lineno", None)
            if lineno is None or end is None:
                continue
            if lineno <= line_num <= end:
                if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    scope.append(n.name)
                return n
        return None

    while current is not None:
        current = find_body(current)
    return ".".join(scope)


def load_positions(dataset: Path) -> dict[str, str]:
    """Đọc cột `Vul Position` từ SyntheticDataset.csv cạnh thư mục dataset."""
    csv_path = dataset.parent / "SyntheticDataset.csv"
    if not csv_path.exists():
        return {}
    out: dict[str, str] = {}
    with csv_path.open(encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            case = (row.get("TestCase") or "").strip()
            if case:
                out[case] = (row.get("Vul Position") or "").strip()
    return out


def scan_file(path: Path, registry, rule_engine_cls, detector_cls) -> list:
    """Quét một file, trả về danh sách Vulnerability."""
    detector = detector_cls(rule_engine_cls(), max_depth=5)
    return detector.analyze_file(path) or []


def collect_pairs(dataset: Path) -> dict[str, list[tuple[str, Path, Path]]]:
    """Gom các cặp vul/fix theo thư mục CWE."""
    pairs: dict[str, list[tuple[str, Path, Path]]] = defaultdict(list)
    for cwe_dir in sorted(dataset.iterdir()):
        if not cwe_dir.is_dir():
            continue
        cwe = cwe_dir.name
        for vul in sorted(cwe_dir.glob("*_vul.py")):
            fix = vul.with_name(vul.name.replace("_vul.py", "_fix.py"))
            case_id = vul.name.replace("_vul.py", "")
            pairs[cwe].append((case_id, vul, fix if fix.exists() else None))
    return pairs


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--dataset", type=Path, required=True,
                    help="Thư mục SyntheticDataset của PySASTBench")
    ap.add_argument("--output-dir", type=Path, default=None)
    ap.add_argument("--include-out-of-scope", action="store_true",
                    help="Tính cả các họ ngoài phạm vi (ví dụ XSS) vào tổng")
    ap.add_argument("--match", choices=("official", "family"), default="official",
                    help="official: khớp cả họ và tên hàm như script của tác giả; "
                         "family: chỉ khớp họ (rộng hơn)")
    args = ap.parse_args()

    from aegis_sast.analysis.rule_engine import RuleEngine
    from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector

    positions = load_positions(args.dataset)
    if args.match == "official" and not positions:
        print("Không đọc được SyntheticDataset.csv — cần nó cho chế độ official",
              file=sys.stderr)
        return 1

    pairs = collect_pairs(args.dataset)
    if not pairs:
        print("Không tìm thấy cặp vul/fix nào", file=sys.stderr)
        return 1

    modes = ("all", "visible", "high_confidence")
    totals = {m: Counts() for m in modes}
    per_family = {m: defaultdict(Counts) for m in modes}
    cases: list[dict] = []

    started = time.perf_counter()
    scanned = 0

    for cwe, entries in sorted(pairs.items(), key=lambda kv: int(kv[0])):
        family = CWE_TO_FAMILY.get(cwe)
        if family is None:
            continue
        for case_id, vul_path, fix_path in entries:
            record = {"case_id": case_id, "cwe": cwe, "family": family}

            for label, path in (("vul", vul_path), ("fix", fix_path)):
                if path is None:
                    continue
                vulns = scan_file(path, None, RuleEngine, VulnerabilityDetector)
                scanned += 1
                hits = {m: False for m in modes}
                expected_scope = positions.get(case_id, "")
                for v in vulns:
                    vtype = getattr(v.vuln_type, "value", str(v.vuln_type))
                    if vtype != family:
                        continue
                    if args.match == "official" and expected_scope:
                        # Finding phải nằm đúng trong hàm mà ground truth chỉ ra.
                        scope = get_enclosing_scope(path, int(v.line_number or 0))
                        if scope != expected_scope:
                            continue
                    raw_status = v.infer_triage_status()
                    status = str(getattr(raw_status, "value", raw_status or "")).lower()
                    hits["all"] = True
                    if status not in SUPPRESSED:
                        hits["visible"] = True
                    if status in HIGH_CONFIDENCE:
                        hits["high_confidence"] = True
                record[f"{label}_detected"] = dict(hits)
                record[f"{label}_finding_count"] = len(vulns)

            in_scope = family in IN_SCOPE
            for m in modes:
                bucket = totals[m] if (in_scope or args.include_out_of_scope) else None
                fam_bucket = per_family[m][family]
                if record.get("vul_detected", {}).get(m):
                    fam_bucket.tp += 1
                    if bucket: bucket.tp += 1
                else:
                    fam_bucket.fn += 1
                    if bucket: bucket.fn += 1
                if fix_path is not None:
                    if record.get("fix_detected", {}).get(m):
                        fam_bucket.fp += 1
                        if bucket: bucket.fp += 1
                    else:
                        fam_bucket.tn += 1
                        if bucket: bucket.tn += 1
            cases.append(record)

    elapsed = time.perf_counter() - started

    print(f"Dataset      : {args.dataset}")
    print(f"Test case    : {len(cases)} cặp vul/fix  ({scanned} file đã quét)")
    print(f"Thời gian    : {elapsed:.1f}s")
    print(f"Phạm vi tổng : {'mọi họ' if args.include_out_of_scope else 'chỉ họ Aegis hỗ trợ'}")
    print(f"Quy tắc khớp : {args.match}"
          f"{' (khớp cả họ và tên hàm, như script của tác giả)' if args.match == 'official' else ' (chỉ khớp họ)'}")
    print()
    print(f"{'Mode':18}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'Precision':>11}{'Recall':>9}{'F1':>9}")
    print("-" * 67)
    for m in modes:
        c = totals[m]
        print(f"{m:18}{c.tp:5}{c.fp:5}{c.fn:5}{c.tn:5}"
              f"{c.precision:11.4f}{c.recall:9.4f}{c.f1:9.4f}")
    print()
    print(f"{'Họ (mode=visible)':28}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}"
          f"{'Precision':>11}{'Recall':>9}{'F1':>9}")
    print("-" * 77)
    for fam in sorted(per_family["visible"]):
        c = per_family["visible"][fam]
        tag = "" if fam in IN_SCOPE else "  (ngoài phạm vi)"
        print(f"{fam:28}{c.tp:5}{c.fp:5}{c.fn:5}{c.tn:5}"
              f"{c.precision:11.4f}{c.recall:9.4f}{c.f1:9.4f}{tag}")

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "benchmark": "PySASTBench SyntheticDataset",
            "dataset": str(args.dataset),
            "case_count": len(cases),
            "files_scanned": scanned,
            "elapsed_sec": round(elapsed, 2),
            "in_scope_families": sorted(IN_SCOPE),
            "match_mode": args.match,
            "modes": {m: totals[m].as_dict() for m in modes},
            "per_family": {
                m: {f: c.as_dict() for f, c in per_family[m].items()} for m in modes
            },
            "cases": cases,
        }
        (args.output_dir / "pysastbench_score_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False)
        )
        print(f"\nĐã ghi {args.output_dir}/pysastbench_score_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

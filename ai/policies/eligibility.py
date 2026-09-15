"""Eligibility gate — chặn finding trước khi tốn một token nào.

Đây là cơ chế tiết kiệm quota quan trọng nhất của tầng AI: NVIDIA Build free
tier vừa chậm vừa giới hạn request, nên gửi mọi finding sang LLM là không khả
thi. Gate này hoàn toàn tất định (không gọi LLM) và trả về lý do từ chối cụ
thể để báo cáo còn truy vết được vì sao một finding không được AI xem xét.

Xếp hạng bằng `priority_score`, một công thức rule-based có trọng số cố định.
Chưa cần ML: với ngân sách top-N nhỏ, thứ tự ưu tiên rule-based đã là baseline
mạnh, và quan trọng hơn là nó tái lập được — điều kiện bắt buộc cho benchmark.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..config import Settings, get_settings
from ..schemas.finding import NormalizedFinding

# Thứ hạng severity dùng chung cho mọi so sánh ngưỡng.
SEVERITY_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

# CWE mà một lần bỏ sót đắt hơn nhiều lần soi thừa; luôn được cộng điểm
# exploitability và không bao giờ bị hạ ưu tiên vì evidence yếu.
HIGH_IMPACT_CWES = {
    "CWE-89",   # SQL injection
    "CWE-78",   # OS command injection
    "CWE-94",   # code injection
    "CWE-502",  # insecure deserialization
    "CWE-918",  # SSRF
}


@dataclass
class EligibilityDecision:
    """Kết quả gate cho MỘT finding."""

    finding_id: str
    eligible: bool
    reason: str
    priority: float = 0.0
    # Ghi lại mọi luật đã áp dụng để report truy ngược được quyết định.
    policy_events: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "eligible": self.eligible,
            "reason": self.reason,
            "priority": round(self.priority, 4),
            "policy_events": list(self.policy_events),
        }


def _normalized_severity(finding: NormalizedFinding) -> float:
    """Severity về thang [0, 1]."""
    return SEVERITY_RANK.get(finding.severity, 0) / 3.0


def _exploitability_signal(finding: NormalizedFinding) -> float:
    """Ước lượng khả năng khai thác từ chính evidence tất định.

    Đường dẫn dataflow đi tới sink mà không gặp sanitizer nào là tín hiệu
    mạnh nhất; CWE có tác động cao được cộng thêm.
    """
    signal = 0.0
    if finding.evidence.data_flow_path:
        kinds = {step.kind for step in finding.evidence.data_flow_path}
        if "source" in kinds and "sink" in kinds:
            signal += 0.5
        if "sanitizer" not in kinds and not finding.evidence.sanitizers_seen:
            signal += 0.3
    if finding.cwe in HIGH_IMPACT_CWES:
        signal += 0.2
    return min(signal, 1.0)


def _ambiguity(finding: NormalizedFinding) -> float:
    """Độ mơ hồ: cao nhất khi static engine lưỡng lự quanh mức 0.5.

    Finding mà core đã rất chắc (confidence ~0 hoặc ~1) thì LLM ít có khả năng
    thêm được gì; đúng phần ở giữa mới đáng tốn token.
    """
    return 1.0 - abs(finding.confidence - 0.5) * 2.0


def _code_exposure(finding: NormalizedFinding) -> float:
    """Mức phơi nhiễm: đường dẫn càng dài/càng qua nhiều file càng đáng soi."""
    path = finding.evidence.data_flow_path
    if not path:
        return 0.0
    files = {step.file for step in path}
    cross_file = min((len(files) - 1) / 3.0, 1.0)
    length = min(len(path) / 8.0, 1.0)
    return 0.5 * cross_file + 0.5 * length


def priority_score(finding: NormalizedFinding) -> float:
    """Điểm ưu tiên trong [0, 1] theo công thức rule-based của kế hoạch.

    Trọng số cố định và không phụ thuộc thứ tự quét, nên hai lần chạy trên
    cùng một report cho cùng một thứ tự — điều kiện cần để benchmark tái lập.
    """
    return (
        0.35 * _normalized_severity(finding)
        + 0.25 * finding.confidence
        + 0.20 * _exploitability_signal(finding)
        + 0.10 * _ambiguity(finding)
        + 0.10 * _code_exposure(finding)
    )


def check_eligibility(
    finding: NormalizedFinding,
    settings: Settings | None = None,
    *,
    per_file_counter: Counter | None = None,
    scan_budget_used: int = 0,
    static_verdict_is_fp: bool = False,
) -> EligibilityDecision:
    """Quyết định một finding có được gửi sang LLM hay không.

    Các tham số đếm (`per_file_counter`, `scan_budget_used`) do phía gọi quản
    lý để gate này không giữ trạng thái toàn cục — nhờ vậy test chạy độc lập
    được và benchmark song song không giẫm lên nhau.
    """
    s = settings or get_settings()
    events: list[str] = []
    score = priority_score(finding)

    def deny(reason: str) -> EligibilityDecision:
        events.append(reason)
        return EligibilityDecision(
            finding_id=finding.finding_id,
            eligible=False,
            reason=reason,
            priority=score,
            policy_events=events,
        )

    if not s.llm_enabled:
        return deny(f"ai_mode_{s.ai_mode}")

    if static_verdict_is_fp:
        # Heuristic tất định đã chứng minh an toàn — gọi LLM là lãng phí thuần.
        return deny("static_heuristic_proved_safe")

    if SEVERITY_RANK.get(finding.severity, 0) < SEVERITY_RANK[s.min_severity_for_llm]:
        return deny(f"severity_below_{s.min_severity_for_llm}")

    if finding.evidence.evidence_quality < s.min_evidence_quality_for_llm:
        # Evidence quá mỏng: tool static còn rẻ và chắc hơn LLM đoán.
        return deny("insufficient_evidence_for_llm")

    ev = finding.evidence
    if not ev.data_flow_path and not (ev.source and ev.sink):
        return deny("no_source_sink_or_path")

    if scan_budget_used >= s.max_llm_findings_per_scan:
        return deny("scan_llm_budget_exhausted")

    if per_file_counter is not None:
        used = per_file_counter[finding.evidence.sink.file]
        if used >= s.max_llm_findings_per_file:
            return deny("file_llm_budget_exhausted")

    events.append("eligible")
    return EligibilityDecision(
        finding_id=finding.finding_id,
        eligible=True,
        reason="eligible",
        priority=score,
        policy_events=events,
    )


def select_for_llm(
    findings: list[NormalizedFinding],
    settings: Settings | None = None,
    *,
    static_fp_ids: set[str] | None = None,
) -> tuple[list[NormalizedFinding], list[EligibilityDecision]]:
    """Chọn tập finding được gửi sang LLM, theo thứ tự ưu tiên giảm dần.

    Trả về `(được_chọn, mọi_quyết_định)`. Danh sách quyết định gồm cả finding
    bị loại kèm lý do, để report giải thích được vì sao AI bỏ qua chúng.
    """
    s = settings or get_settings()
    fp_ids = static_fp_ids or set()

    # Sắp xếp trước rồi mới tiêu ngân sách: nếu không, finding quét được sớm
    # sẽ chiếm hết quota bất kể mức độ quan trọng.
    ordered = sorted(
        findings,
        key=lambda f: (-priority_score(f), f.finding_id),
    )

    per_file: Counter = Counter()
    selected: list[NormalizedFinding] = []
    decisions: list[EligibilityDecision] = []

    for finding in ordered:
        decision = check_eligibility(
            finding,
            s,
            per_file_counter=per_file,
            scan_budget_used=len(selected),
            static_verdict_is_fp=finding.finding_id in fp_ids,
        )
        decisions.append(decision)
        if decision.eligible:
            selected.append(finding)
            per_file[finding.evidence.sink.file] += 1

    return selected, decisions

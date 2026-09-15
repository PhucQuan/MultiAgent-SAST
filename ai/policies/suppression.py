"""Policy hậu kiểm — quyết định verdict của LLM có được đổi output hay không.

Tầng AI tồn tại để giảm false positive, nhưng sai lầm của nó không đối xứng:
một cảnh báo thừa tốn vài phút của người review, còn một lỗ hổng bị giấu đi có
thể lên production. Mọi luật ở đây vì vậy đều lệch về phía giữ cảnh báo.

Bốn luật, áp dụng theo thứ tự, bằng Python chứ không bằng lời dặn trong prompt
— một mô hình có thể bỏ qua lời dặn, không thể bỏ qua câu lệnh `if`:

1. LLM hỏng  -> `needs-review` (fail-open).
2. High/Critical chưa được validator xác nhận an toàn -> không bao giờ suppress.
3. Verdict không trích được evidence có thật -> hạ xuống `needs-review`.
4. Kết luận "false positive" mà validator không chứng minh -> hạ xuống.

Mọi lần hạ cấp đều ghi lại tên luật vào `policy_events`, để báo cáo giải thích
được vì sao một finding không bị suppress dù mô hình đề nghị thế.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Settings, get_settings
from ..schemas.state import GraphState
from ..schemas.verdict import TriageState

# Severity mà một lần bỏ sót là không chấp nhận được.
PROTECTED_SEVERITIES = frozenset({"high", "critical"})

# Trạng thái triage mở rộng, tách "không đủ bằng chứng" khỏi "đã xem và cho qua".
SUPPRESSING_STATES = frozenset({TriageState.SUPPRESSED})


@dataclass
class PolicyOutcome:
    """Kết quả áp policy lên một verdict."""

    triage_state: TriageState
    changed: bool
    events: list[str] = field(default_factory=list)
    # Chỉ True khi suppression có bằng chứng tất định chống lưng.
    safe_suppression: bool = False

    def to_dict(self) -> dict:
        return {
            "triage_state": self.triage_state.value,
            "changed": self.changed,
            "events": list(self.events),
            "safe_suppression": self.safe_suppression,
        }


def _citations_are_grounded(state: GraphState) -> bool:
    """Citation của agent có trỏ tới bằng chứng có thật không.

    Chấp nhận citation khớp với ledger HOẶC khớp với dataflow path mà Core
    SAST đã sinh ra — cả hai đều là dữ liệu chương trình, không phải lời model.
    Một citation trỏ tới file:line không tồn tại là dấu hiệu mô hình đang bịa.
    """
    cited: set[str] = set()
    for verdict in (state.auditor_verdict, state.skeptic_verdict):
        if verdict:
            cited.update(c.strip() for c in verdict.grounded_citations if c.strip())
    if not cited:
        return False

    known = set(state.evidence.citations())
    ev = state.finding.evidence
    known.add(f"{ev.source.file}:{ev.source.line}")
    known.add(f"{ev.sink.file}:{ev.sink.line}")
    for step in ev.data_flow_path:
        known.add(f"{step.file}:{step.line}")

    # Khớp lỏng theo đuôi đường dẫn: agent thường trích đường dẫn tương đối
    # trong khi evidence giữ đường dẫn tuyệt đối, và ngược lại.
    def matches(citation: str) -> bool:
        if citation in known:
            return True
        return any(k.endswith(citation) or citation.endswith(k) for k in known)

    return any(matches(c) for c in cited)


def apply_suppression_policy(
    state: GraphState,
    proposed: TriageState,
    settings: Settings | None = None,
) -> PolicyOutcome:
    """Áp policy lên trạng thái mà Judge đề xuất, trả trạng thái được phép ghi."""
    s = settings or get_settings()
    events: list[str] = []
    severity = state.finding.severity.lower()
    validator = state.validator_assessment

    def downgrade(reason: str) -> PolicyOutcome:
        events.append(reason)
        return PolicyOutcome(
            triage_state=TriageState.NEEDS_REVIEW,
            changed=proposed != TriageState.NEEDS_REVIEW,
            events=events,
            safe_suppression=False,
        )

    # --- Luật 1: LLM hỏng thì không kết luận gì ------------------------
    if state.llm_failed:
        if proposed in SUPPRESSING_STATES:
            return downgrade("fail_open_enforced")
        events.append("llm_failed_noted")

    # --- Luật 2: High/Critical được bảo vệ -----------------------------
    if proposed in SUPPRESSING_STATES and severity in PROTECTED_SEVERITIES:
        if not s.high_critical_auto_suppress:
            validator_cleared = bool(validator and validator.proved_safe_pattern)
            if not validator_cleared:
                return downgrade("high_critical_no_auto_suppress")
            events.append("high_critical_suppress_allowed_by_validator")

    # --- Luật 3: verdict phải có evidence có thật ----------------------
    if s.require_evidence_citations and proposed in SUPPRESSING_STATES:
        if not _citations_are_grounded(state):
            return downgrade("suppression_without_grounded_evidence")

    # --- Luật 4: FP phải được validator chứng minh ---------------------
    if s.require_static_validation_for_false_positive and proposed in SUPPRESSING_STATES:
        if validator is None:
            return downgrade("suppression_without_validator")
        if validator.insufficient_evidence:
            return downgrade("insufficient_evidence")
        if not validator.proved_safe_pattern:
            # Đây là nhánh hay gặp nhất: mô hình "thấy có vẻ an toàn" nhưng
            # không tool nào chứng minh được. Không đủ để giấu cảnh báo.
            return downgrade("no_static_proof_of_safety")

    # --- Bất đồng chưa giải quyết giữa hai agent -----------------------
    if (
        state.auditor_verdict
        and state.skeptic_verdict
        and state.auditor_verdict.exploitable != state.skeptic_verdict.exploitable
        and proposed in SUPPRESSING_STATES
    ):
        return downgrade("unresolved_disagreement")

    if proposed in SUPPRESSING_STATES:
        events.append("suppression_allowed_with_evidence")
        return PolicyOutcome(
            triage_state=proposed,
            changed=False,
            events=events,
            safe_suppression=True,
        )

    return PolicyOutcome(
        triage_state=proposed,
        changed=False,
        events=events,
        safe_suppression=False,
    )


def build_suppression_record(state: GraphState, settings: Settings | None = None) -> dict:
    """Bản ghi suppression đầy đủ provenance, hết hạn khi code đổi.

    `expires_on_code_change` không phải tuỳ chọn: một sink được chứng minh an
    toàn nhờ hằng số ràng buộc sẽ hết an toàn ngay khi ai đó sửa dòng gán đó.
    """
    s = settings or get_settings()
    validator = state.validator_assessment
    return {
        "finding_fingerprint": state.finding.finding_id,
        "status": "SUPPRESSED_WITH_EVIDENCE",
        "reason": "; ".join(validator.notes) if validator and validator.notes else
        "validator xác nhận mẫu an toàn",
        "evidence_ids": list(validator.evidence_ids) if validator else [],
        "created_for_commit": state.commit_sha,
        "expires_on_code_change": True,
        "policy_version": s.policy_version,
        "constant_bound": bool(validator and validator.constant_bound),
        "sanitizer_confirmed": bool(validator and validator.sanitizer_confirmed),
    }

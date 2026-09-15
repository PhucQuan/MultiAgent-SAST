"""AITriageService — API công khai duy nhất để Core gọi tầng AI.

Trước khi có lớp này, `orchestration` biết về client Gemini còn script
benchmark biết về graph NVIDIA. Mỗi thay đổi ở tầng AI lan ra cả hai nơi, và
không chỗ nào áp được policy một cách nhất quán.

Giờ mọi đường đều đi qua `triage()`. Ba việc luôn xảy ra ở đây, không bỏ qua
được bằng cách gọi vòng khác:

* eligibility gate chạy trước, nên finding không đủ điều kiện không tốn token;
* policy suppression chạy sau, nên verdict của mô hình không tự đổi được output;
* verdict luôn mang theo provenance và chi phí, nên báo cáo truy ngược được.

Ở mode `shadow` và `review-only`, service vẫn chạy và vẫn trả verdict, nhưng
`applies_to_output=False`. Phía gọi phải tôn trọng cờ này — đó là cách thu
thập dữ liệu về chất lượng tầng AI mà không để nó ảnh hưởng kết quả thật.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

from aegis_sast.ai.contracts import (
    EvidenceReference,
    ModelUsage,
    RecommendedAction,
    TriageRequest,
    TriageStatus,
    TriageVerdict,
)


def _lazy_ai_imports():
    """Nạp lớp multi-agent muộn.

    `ai/` kéo theo LangGraph và pydantic-settings, và `Settings` yêu cầu
    NVIDIA_API_KEY. Import ở đầu module sẽ làm `aegis_sast` không import được
    trên máy chỉ chạy static SAST — tức là biến một tính năng tuỳ chọn thành
    phụ thuộc bắt buộc.
    """
    from ai.config import get_settings
    from ai.graph.build import run_triage
    from ai.policies.eligibility import check_eligibility
    from ai.schemas.finding import NormalizedFinding
    from ai.schemas.verdict import TriageState

    return get_settings, run_triage, check_eligibility, NormalizedFinding, TriageState


# Ánh xạ trạng thái nội bộ của graph sang contract công khai.
_STATE_TO_STATUS = {
    "confirmed": TriageStatus.TRUE_POSITIVE,
    "likely": TriageStatus.TRUE_POSITIVE,
    "suppressed": TriageStatus.FALSE_POSITIVE,
    "needs-review": TriageStatus.NEEDS_HUMAN_REVIEW,
}

_STATUS_TO_ACTION = {
    TriageStatus.TRUE_POSITIVE: RecommendedAction.REPORT,
    TriageStatus.FALSE_POSITIVE: RecommendedAction.SUPPRESS_WITH_EXPIRY,
    TriageStatus.UNCERTAIN: RecommendedAction.HUMAN_REVIEW,
    TriageStatus.NEEDS_HUMAN_REVIEW: RecommendedAction.HUMAN_REVIEW,
    TriageStatus.INSUFFICIENT_EVIDENCE: RecommendedAction.REQUEST_STATIC_ANALYSIS,
}


class AITriageService:
    """Façade cho toàn bộ tầng AI."""

    def __init__(
        self,
        graph: Any = None,
        trajectory_path: Optional[Path] = None,
        run_id: str = "",
    ):
        self._graph = graph
        self.trajectory_path = Path(trajectory_path) if trajectory_path else None
        self.run_id = run_id
        # Đếm ngân sách ở phạm vi cả lần quét, không phải từng finding.
        self._scan_llm_used = 0
        self._per_file_used: dict[str, int] = {}

    # ------------------------------------------------------------------
    def triage(self, request: TriageRequest) -> TriageVerdict:
        """Triage một finding. Luôn trả verdict, không bao giờ raise ra ngoài."""
        (
            get_settings,
            run_triage,
            check_eligibility,
            NormalizedFinding,
            _TriageState,
        ) = _lazy_ai_imports()

        settings = get_settings()
        started = time.perf_counter()

        try:
            finding = NormalizedFinding.model_validate(request.normalized_finding)
        except Exception as exc:
            # Finding không hợp contract là lỗi tích hợp, nhưng nó không được
            # phép làm hỏng cả lần quét — trả verdict "chưa đủ dữ liệu".
            return self._insufficient(
                request, settings, f"finding không hợp schema: {exc}"
            )

        from collections import Counter

        decision = check_eligibility(
            finding,
            settings,
            per_file_counter=Counter(self._per_file_used),
            scan_budget_used=self._scan_llm_used,
        )
        if not decision.eligible:
            return self._skipped(request, settings, decision)

        self._scan_llm_used += 1
        sink_file = finding.evidence.sink.file
        self._per_file_used[sink_file] = self._per_file_used.get(sink_file, 0) + 1

        try:
            state = run_triage(
                finding,
                graph=self._graph,
                run_id=self.run_id,
                commit_sha=request.commit_sha,
                repo_id=request.repository_id,
                repo_profile=request.repo_profile,
            )
        except Exception as exc:
            return self._insufficient(request, settings, f"graph lỗi: {exc}")

        verdict = self._to_verdict(request, state, settings)
        verdict.usage.latency_ms = int((time.perf_counter() - started) * 1000)
        self._record_trajectory(state)
        return verdict

    # ------------------------------------------------------------------
    def _to_verdict(self, request, state, settings) -> TriageVerdict:
        """Dịch GraphState sang contract công khai."""
        triage_state = state.triage_state.value if state.triage_state else "needs-review"
        status = _STATE_TO_STATUS.get(triage_state, TriageStatus.NEEDS_HUMAN_REVIEW)

        validator = state.validator_assessment
        if validator is not None and validator.insufficient_evidence:
            status = TriageStatus.INSUFFICIENT_EVIDENCE

        evidence = [
            EvidenceReference(**ref.model_dump(exclude={"payload"}))
            for ref in state.evidence.artifacts.values()
        ]

        # Kết luận FP mà không có bằng chứng nào là mâu thuẫn nội tại: hạ về
        # "chưa đủ dữ liệu" thay vì báo cáo một false positive không kiểm chứng.
        if status is TriageStatus.FALSE_POSITIVE and not evidence:
            status = TriageStatus.INSUFFICIENT_EVIDENCE

        decision = state.judge_decision
        usage = ModelUsage(
            provider="nvidia_nim",
            tool_calls=state.tool_calls_used,
            input_tokens=state.tokens_used,
        )

        return TriageVerdict(
            finding_id=request.finding_id,
            status=status,
            confidence=decision.confidence if decision else 0.0,
            cwe_ids=[state.finding.cwe],
            rationale=decision.reasoning if decision else "",
            evidence_ids=state.evidence.ids(),
            evidence=evidence,
            unresolved_questions=[e.get("error", "") for e in state.errors if e],
            recommended_action=_STATUS_TO_ACTION[status],
            safe_suppression=(
                status is TriageStatus.FALSE_POSITIVE
                and bool(validator and validator.proved_safe_pattern)
            ),
            provider="nvidia_nim",
            prompt_version=settings.prompt_version,
            graph_version=settings.graph_version,
            knowledge_version=settings.knowledge_version,
            policy_version=settings.policy_version,
            policy_events=list(state.policy_events),
            usage=usage,
            applies_to_output=settings.verdict_applies_to_output,
            ai_mode=settings.ai_mode,
        )

    def _skipped(self, request, settings, decision) -> TriageVerdict:
        """Finding bị gate loại — ghi rõ lý do, không giả vờ đã xem xét."""
        return TriageVerdict(
            finding_id=request.finding_id,
            status=TriageStatus.NEEDS_HUMAN_REVIEW,
            confidence=0.0,
            rationale=f"AI bỏ qua finding này: {decision.reason}",
            recommended_action=RecommendedAction.HUMAN_REVIEW,
            policy_events=[f"eligibility:{decision.reason}"],
            prompt_version=settings.prompt_version,
            policy_version=settings.policy_version,
            # Quyết định bỏ qua KHÔNG được đổi output: finding giữ nguyên
            # trạng thái mà Core SAST đã gán cho nó.
            applies_to_output=False,
            ai_mode=settings.ai_mode,
        )

    def _insufficient(self, request, settings, reason: str) -> TriageVerdict:
        return TriageVerdict(
            finding_id=request.finding_id,
            status=TriageStatus.INSUFFICIENT_EVIDENCE,
            confidence=0.0,
            rationale=reason,
            recommended_action=RecommendedAction.REQUEST_STATIC_ANALYSIS,
            policy_events=["service_error"],
            prompt_version=settings.prompt_version,
            policy_version=settings.policy_version,
            applies_to_output=False,
            ai_mode=settings.ai_mode,
        )

    def _record_trajectory(self, state) -> None:
        """Ghi quỹ đạo nếu được cấu hình; lỗi ghi log không làm hỏng triage."""
        if self.trajectory_path is None:
            return
        try:
            from ai.observability.trajectory import build_trajectory, write_trajectory

            write_trajectory(build_trajectory(state), self.trajectory_path)
        except Exception:
            pass

    # ------------------------------------------------------------------
    @property
    def scan_budget_used(self) -> int:
        return self._scan_llm_used

    def reset_budget(self) -> None:
        """Bắt đầu một lần quét mới."""
        self._scan_llm_used = 0
        self._per_file_used = {}

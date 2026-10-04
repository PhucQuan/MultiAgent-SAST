"""Contract giữa Core SAST và tầng AI.

Đây là ranh giới duy nhất mà hai bên được phép biết về nhau. Trước khi có nó,
`orchestration` gọi thẳng client Gemini còn benchmark gọi thẳng graph NVIDIA —
đổi provider phải sửa nhiều chỗ, và không ai trả lời được câu hỏi "verdict này
do model nào, prompt phiên bản nào sinh ra".

Mọi verdict đi qua đây đều mang theo `evidence_ids`. Một kết luận không trích
được bằng chứng nào là kết luận không kiểm chứng được, và contract từ chối
xếp nó ngang hàng với kết luận có bằng chứng: `TriageStatus` có riêng hai
trạng thái `INSUFFICIENT_EVIDENCE` và `NEEDS_HUMAN_REVIEW` cho những ca đó,
thay vì ép về true/false positive.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class TriageStatus(str, Enum):
    """Kết quả triage. Bốn trạng thái đầu là kết luận, hai cuối là 'chưa biết'."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class RecommendedAction(str, Enum):
    REPORT = "report"
    SUPPRESS_WITH_EXPIRY = "suppress_with_expiry"
    REQUEST_STATIC_ANALYSIS = "request_static_analysis"
    REQUEST_TEST_VALIDATION = "request_test_validation"
    HUMAN_REVIEW = "human_review"


class EvidenceReference(BaseModel):
    """Một mẩu bằng chứng, luôn kèm nguồn gốc và hash nội dung."""

    artifact_id: str
    artifact_type: str
    producer: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    content_hash: str
    relevance: float = Field(default=1.0, ge=0.0, le=1.0)


class TriageRequest(BaseModel):
    """Yêu cầu triage một finding, kèm ngân sách cho phép tiêu."""

    finding_id: str
    repository_id: str = ""
    commit_sha: str = ""
    normalized_finding: dict
    evidence_bundle: dict = Field(default_factory=dict)
    repo_profile: dict = Field(default_factory=dict)
    policy_id: str = "default"
    # Ngân sách đi cùng request chứ không đọc từ config toàn cục: phía gọi
    # biết còn bao nhiêu quota cho cả lần quét, node bên trong thì không.
    time_budget_ms: int = 60_000
    token_budget: int = 3_500
    tool_call_budget: int = 4


class ModelUsage(BaseModel):
    """Chi phí thực tế của một lượt triage, để đối chiếu với ngân sách."""

    provider: str = ""
    models_used: list[str] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    api_calls: int = 0
    tool_calls: int = 0
    cache_hits: int = 0
    latency_ms: int = 0
    fallback_used: bool = False


class TriageVerdict(BaseModel):
    """Kết luận triage cho một finding."""

    finding_id: str
    status: TriageStatus
    confidence: float = Field(ge=0.0, le=1.0)
    severity_override: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    recommended_action: RecommendedAction = RecommendedAction.HUMAN_REVIEW
    # Chỉ True khi policy tất định đã cho phép — không phải khi model nói thế.
    safe_suppression: bool = False

    # --- provenance: bắt buộc để báo cáo truy ngược được ---------------
    provider: str = ""
    prompt_version: str = ""
    graph_version: str = ""
    knowledge_version: str = ""
    policy_version: str = ""
    policy_events: list[str] = Field(default_factory=list)
    usage: ModelUsage = Field(default_factory=ModelUsage)
    # `False` khi chạy ở mode shadow/review-only: verdict được ghi lại nhưng
    # không được phép đổi output chính.
    applies_to_output: bool = False
    ai_mode: Literal[
        "disabled", "heuristic", "shadow", "review-only", "active"
    ] = "shadow"

    def is_conclusive(self) -> bool:
        """Có phải kết luận thật, hay chỉ là 'chưa đủ dữ liệu'."""
        return self.status in (TriageStatus.TRUE_POSITIVE, TriageStatus.FALSE_POSITIVE)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

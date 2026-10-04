"""GraphState — state dùng chung cho toàn bộ LangGraph workflow.

State không chỉ chở hội thoại giữa các agent: nó là sổ cái bằng chứng của một
finding. Mỗi tool call, mỗi knowledge card, mỗi kết luận của validator đều để
lại artifact có `content_hash` và `producer` trong `evidence`, nên verdict
cuối cùng truy ngược được tới file/dòng/commit thay vì tới một đoạn văn do mô
hình viết ra.

Các trường ngân sách (`tokens_used`, `tool_calls_used`, `elapsed_ms`) nằm ngay
trong state chứ không ở biến toàn cục, để hai finding chạy song song không
tiêu lẫn ngân sách của nhau.
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from .evidence import EvidenceLedger
from .finding import NormalizedFinding
from .hypothesis import StructuredHypothesis
from .verdict import AgentVerdict, JudgeDecision, TriageState


class ValidatorAssessment(BaseModel):
    """Kết luận của validator tất định. Không có trường nào do LLM điền."""

    dataflow_confirmed: bool = False
    sink_reachable: bool = False
    sanitizer_confirmed: bool = False
    constant_bound: bool = False
    guarded_by_control_flow: bool = False
    guarded_by_early_return: bool = False
    # Điều kiện DUY NHẤT cho phép suppress tự động.
    proved_safe_pattern: bool = False
    insufficient_evidence: bool = False
    evidence_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    tools_unavailable: list[str] = Field(default_factory=list)


class PlannedAction(BaseModel):
    """Một bước điều tra mà planner yêu cầu."""

    action: str
    arguments: dict = Field(default_factory=dict)
    rationale: str = ""
    # Vì sao bước này được chọn: rule tất định hay do LLM đề xuất.
    source: str = "heuristic_policy"


class GraphState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # ---- Danh tính và provenance -------------------------------------
    run_id: str = ""
    commit_sha: str = ""
    repo_id: str = ""

    finding: NormalizedFinding
    repo_profile: dict = Field(default_factory=dict)

    # ---- Sổ cái bằng chứng -------------------------------------------
    evidence: EvidenceLedger = Field(default_factory=EvidenceLedger)
    knowledge_cards: list[dict] = Field(default_factory=list)

    # ---- Kế hoạch điều tra --------------------------------------------
    plan: list[PlannedAction] = Field(default_factory=list)
    completed_actions: list[dict] = Field(default_factory=list)
    blocked_actions: list[dict] = Field(default_factory=list)

    # ---- Đánh giá của từng agent ---------------------------------------
    hypothesis: Optional[StructuredHypothesis] = None
    auditor_verdict: Optional[AgentVerdict] = None
    skeptic_verdict: Optional[AgentVerdict] = None
    skeptic_mode: str = "neutral"
    validator_assessment: Optional[ValidatorAssessment] = None
    judge_decision: Optional[JudgeDecision] = None
    triage_state: Optional[TriageState] = None

    # ---- Ngân sách cho finding này -------------------------------------
    debate_round: int = 0
    tool_calls_used: int = 0
    tokens_used: int = 0
    elapsed_ms: int = 0

    # ---- Trạng thái lỗi và vết policy ----------------------------------
    llm_failed: bool = False
    tool_calls_made: list[dict] = Field(default_factory=list)
    policy_events: list[str] = Field(default_factory=list)
    errors: list[dict] = Field(default_factory=list)
    model_metadata: dict = Field(default_factory=dict)

    # ------------------------------------------------------------------
    def record_policy(self, event: str) -> None:
        """Ghi một luật đã áp dụng, giữ thứ tự và không trùng lặp liên tiếp."""
        if not self.policy_events or self.policy_events[-1] != event:
            self.policy_events.append(event)

    def budget_exhausted(self, tool_call_budget: int, token_budget: int) -> bool:
        """Đã chạm trần tool call hoặc token cho finding này chưa."""
        return (
            self.tool_calls_used >= tool_call_budget
            or self.tokens_used >= token_budget
        )

    def has_new_evidence_since(self, count: int) -> bool:
        """Từ mốc `count` artifact tới giờ có thu được bằng chứng mới không.

        Dùng để cắt vòng lặp: nếu một vòng điều tra không sinh artifact nào
        mới thì tranh luận thêm chỉ lặp lại cùng thiên kiến và đốt quota.
        """
        return len(self.evidence) > count

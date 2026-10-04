"""Policy tất định chạy TRƯỚC và SAU LLM.

Hai nhóm policy tách bạch:

* `eligibility` — quyết định finding nào xứng đáng tốn quota LLM. Chạy trước,
  không gọi LLM, nên không tốn gì.
* `suppression` — kiểm tra verdict của LLM trước khi cho phép nó đổi output.
  Chạy sau, là lưới an toàn chống suppress nhầm lỗ hổng thật.
"""

from .suppression import (
    PROTECTED_SEVERITIES,
    PolicyOutcome,
    apply_suppression_policy,
    build_suppression_record,
)
from .eligibility import (
    EligibilityDecision,
    SEVERITY_RANK,
    check_eligibility,
    priority_score,
    select_for_llm,
)

__all__ = [
    "PROTECTED_SEVERITIES",
    "PolicyOutcome",
    "apply_suppression_policy",
    "build_suppression_record",
    "EligibilityDecision",
    "SEVERITY_RANK",
    "check_eligibility",
    "priority_score",
    "select_for_llm",
]

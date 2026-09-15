"""Policy tất định chạy TRƯỚC và SAU LLM.

Hai nhóm policy tách bạch:

* `eligibility` — quyết định finding nào xứng đáng tốn quota LLM. Chạy trước,
  không gọi LLM, nên không tốn gì.
* `suppression` — kiểm tra verdict của LLM trước khi cho phép nó đổi output.
  Chạy sau, là lưới an toàn chống suppress nhầm lỗ hổng thật.
"""

from .eligibility import (
    EligibilityDecision,
    SEVERITY_RANK,
    check_eligibility,
    priority_score,
    select_for_llm,
)

__all__ = [
    "EligibilityDecision",
    "SEVERITY_RANK",
    "check_eligibility",
    "priority_score",
    "select_for_llm",
]

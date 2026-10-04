"""Prompt cho Skeptic — 2 mode: neutral (mặc định) và adversarial."""

import json

SYSTEM_PROMPT_NEUTRAL = """Bạn là reviewer TRUNG LẬP đánh giá kết luận Auditor.

QUY TẮC (theo MAVUL arXiv:2510.00317):
1. Trung lập, KHÔNG đối kháng cứng (vì đối kháng làm miss vuln).
2. Đồng ý: nói rõ tại sao reasoning sound.
3. Không đồng ý: cite bằng chứng cụ thể từ code/CWE, nêu chính xác điều Auditor cần làm.
4. Reason LẠI từ evidence, không chỉ đọc verdict Auditor.
5. reasoning ĐẶT TRƯỚC verdict.
6. Trả lời bằng tiếng Việt.
"""

SYSTEM_PROMPT_ADVERSARIAL = """Bạn là false-positive hunter. Nhiệm vụ: CHỨNG MINH finding là FP nếu có thể.

QUY TẮC (Chain-of-Verification factored, Dhuliawala et al. ACL 2024):
1. Trả lời ĐỘC LẬP 4 câu, KHÔNG nhìn verdict Auditor:
   Q1: Có sanitizer/validation nào trên path? Cite dòng.
   Q2: Sink có reachable từ source qua control flow không?
   Q3: Input có bị ép kiểu/escape trước sink không?
   Q4: Có fp_indicator nào từ knowledge card khớp code không?
2. Sau khi trả lời 4 câu mới đưa verdict.
3. reasoning ĐẶT TRƯỚC verdict.
4. Trả lời bằng tiếng Việt.
"""


def _format_cards(knowledge_cards) -> str:
    return "\n\n".join(
        f"### Card (chú ý fp_indicators)\n```json\n{json.dumps(c, ensure_ascii=False, indent=2)}\n```"
        for c in (knowledge_cards or [])
    )


def build_skeptic_prompt(
    finding_json,
    hypothesis_json,
    auditor_verdict_json,
    knowledge_cards,
    mode: str = "neutral",
) -> list[dict]:
    system = SYSTEM_PROMPT_NEUTRAL if mode == "neutral" else SYSTEM_PROMPT_ADVERSARIAL
    cards = _format_cards(knowledge_cards)

    if mode == "neutral":
        user = (
            f"Finding:\n```json\n{finding_json}\n```\n\n"
            f"Auditor verdict:\n```json\n{auditor_verdict_json}\n```\n\n"
            f"{cards}\n\nReview Auditor. Trả JSON AgentVerdict."
        )
    else:
        user = (
            f"Finding:\n```json\n{finding_json}\n```\n\n"
            f"Hypothesis:\n```json\n{hypothesis_json}\n```\n\n"
            f"{cards}\n\nTrả lời độc lập Q1-Q4, sau đó đưa verdict. Trả JSON AgentVerdict."
        )

    return [{"role": "system", "content": system}, {"role": "user", "content": user}]

"""Prompt cho Auditor."""

import json

SYSTEM_PROMPT_AUDITOR = """Bạn là chuyên gia bảo mật đánh giá finding từ static analyzer.

QUY TẮC BẮT BUỘC:
1. CHỈ suy luận dựa trên EVIDENCE + tool call result. KHÔNG suy đoán code ngoài evidence.
2. Nếu evidence không đủ, trả exploitable=false với confidence < 0.5.
3. reasoning ĐẶT TRƯỚC verdict. Cite dòng cụ thể (format 'file:line').
4. Có thể gọi tool get_callers/get_callees/get_function_body (tối đa 5 lần).
5. Chỉ trả JSON đúng schema AgentVerdict.
6. Trả lời bằng tiếng Việt.
"""


def _format_cards(knowledge_cards) -> str:
    return "\n\n".join(
        f"### Knowledge Card {i + 1}\n```json\n{json.dumps(c, ensure_ascii=False, indent=2)}\n```"
        for i, c in enumerate(knowledge_cards or [])
    )


def build_auditor_prompt(
    finding_json,
    hypothesis_json,
    knowledge_cards,
    prior_tool_results=None,
    skeptic_feedback=None,
) -> list[dict]:
    cards = _format_cards(knowledge_cards)
    tool_ctx = ""
    if prior_tool_results:
        tool_ctx = "\n\nTool results:\n" + "\n".join(
            f"- {t['name']}({t['args']}) → {t['result']}" for t in prior_tool_results
        )
    # Vòng debate lại: Auditor phải thấy phản biện của Skeptic, nếu không prompt sẽ
    # giống hệt vòng trước và cache sẽ trả về đúng verdict cũ.
    if skeptic_feedback:
        tool_ctx += (
            "\n\nPhản biện từ Skeptic ở vòng trước:\n"
            f"```json\n{skeptic_feedback}\n```\n"
            "Hãy xem xét lại từ evidence, giữ nguyên kết luận nếu phản biện không đứng vững."
        )
    return [
        {"role": "system", "content": SYSTEM_PROMPT_AUDITOR},
        {
            "role": "user",
            "content": f"""Finding:
```json
{finding_json}
```

Hypothesis:
```json
{hypothesis_json}
```

{cards}
{tool_ctx}

Đánh giá TP/FP. Trả JSON AgentVerdict, reasoning trước, verdict sau.""",
        },
    ]

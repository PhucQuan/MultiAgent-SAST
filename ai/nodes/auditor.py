"""Auditor — đánh giá TP/FP, có tool-use loop tối đa 5 lần."""

import json

from ..config import settings
from ..llm.nvidia_client import llm_client
from ..prompts.auditor import build_auditor_prompt
from ..schemas.state import GraphState
from ..schemas.verdict import AgentVerdict
from ..tools.registry import MAX_TOOL_CALLS, TOOL_DEFINITIONS, dispatch_tool_call


def auditor_node(state: GraphState) -> GraphState:
    new_state = state.model_copy(deep=True)
    if new_state.triage_state or not new_state.hypothesis:
        if not new_state.hypothesis:
            new_state.llm_failed = True
        return new_state

    finding_json = state.finding.model_dump_json(indent=2)
    hypothesis_json = state.hypothesis.model_dump_json(indent=2)
    # Từ vòng debate thứ hai trở đi, đưa phản biện Skeptic vào prompt.
    skeptic_feedback = (
        state.skeptic_verdict.model_dump_json(indent=2)
        if state.debate_round > 0 and state.skeptic_verdict
        else None
    )
    tool_results: list[dict] = []
    messages = build_auditor_prompt(
        finding_json,
        hypothesis_json,
        state.knowledge_cards,
        skeptic_feedback=skeptic_feedback,
    )

    # Tool-use loop (dùng NVIDIA NIM native tools param)
    # Trần tool call tính theo FINDING, không theo từng vòng debate. Guide ghi
    # "tối đa 5 tool call/finding", nhưng auditor_reround gọi lại node nên trần
    # cũ bị nhân với số vòng: đo 2026-09-06 có finding dùng tới 20 tool call.
    remaining = max(0, MAX_TOOL_CALLS - len(new_state.tool_calls_made))
    for _ in range(remaining):
        try:
            resp = llm_client.call_raw(
                model=settings.model_auditor,
                messages=messages,
                temperature=settings.temp_auditor,
                tools=TOOL_DEFINITIONS,
            )
        except Exception:
            # Hỏng ở vòng tool-use KHÔNG được giết cả finding. Bỏ phần tool và
            # đi thẳng tới bước chốt verdict, nơi có đủ retry + fallback chain.
            # Đo 2026-09-10: 100% ca fail-open đều phát sinh ở đúng chỗ này.
            break

        msg = resp.choices[0].message
        if not getattr(msg, "tool_calls", None):
            break  # LLM không gọi tool nữa

        messages.append(
            {
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [tc.model_dump() for tc in msg.tool_calls],
            }
        )
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            result = dispatch_tool_call(tc.function.name, args)
            tool_results.append(
                {"name": tc.function.name, "args": args, "result": result}
            )
            messages.append(
                {"role": "tool", "tool_call_id": tc.id, "content": result}
            )

    # Force final structured output
    messages.append(
        {
            "role": "system",
            "content": "Bây giờ TRẢ JSON AgentVerdict cuối cùng, không tool call nữa.",
        }
    )
    verdict = llm_client.call_structured(
        model=settings.model_auditor,
        messages=messages,
        schema=AgentVerdict,
        temperature=settings.temp_auditor,
    )

    if verdict is None:
        new_state.llm_failed = True
    else:
        new_state.auditor_verdict = verdict
        new_state.tool_calls_made.extend(tool_results)
    return new_state

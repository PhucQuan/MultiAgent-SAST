"""Prompt cho Judge — chấm 3 tiêu chí kiểu GPTLens và áp policy."""

# CWE nhạy cảm (crypto / policy / trust-boundary): tối đa NEEDS_REVIEW,
# không bao giờ SUPPRESSED — theo "Sifting the Noise" (arXiv:2601.22952).
SENSITIVE_CWES = {
    "CWE-327",
    "CWE-328",
    "CWE-501",
    "CWE-798",
    "CWE-311",
    "CWE-522",
    "CWE-863",
    "CWE-862",
}

SYSTEM_PROMPT_JUDGE = """Bạn là Judge quyết định triage_state cuối.

QUY TẮC:
1. Chấm 3 tiêu chí (kiểu GPTLens): correctness, severity, exploitability (mỗi tiêu chí [0,1]).
1b. ÁNH XẠ ĐIỂM SANG triage_state (bắt buộc theo thứ tự, lấy nhánh khớp đầu tiên):
   - suppressed : correctness < 0.4, HOẶC tìm thấy fp_indicator khớp trực tiếp với code
                  và exploitability < 0.3 (ví dụ: đã có guard/sanitizer chặn sink).
   - needs-review: bằng chứng thiếu hoặc mâu thuẫn, HOẶC Auditor và Skeptic bất đồng,
                  HOẶC 0.4 <= correctness < 0.7.
   - confirmed  : correctness >= 0.9 VÀ exploitability >= 0.9 VÀ (không có Skeptic
                  phản đối, hoặc Skeptic cũng kết luận exploitable=true).
   - likely     : các trường hợp còn lại.
   KHÔNG được mặc định chọn 'likely' cho mọi finding. Nếu điểm đạt mức 'confirmed'
   thì phải trả 'confirmed'; nếu bằng chứng cho thấy đã bị chặn thì phải trả 'suppressed'.
2. ANTI-OVER-SUPPRESSION: CWE thuộc {CWE-327, CWE-328, CWE-501, CWE-798, CWE-311, CWE-522, CWE-863, CWE-862}
   → KHÔNG BAO GIỜ trả suppressed, tối đa needs-review.
   Ghi 'anti_over_suppression' vào policy_applied.
3. FAIL-OPEN: llm_failed=true → triage_state phải là likely hoặc needs-review.
   Ghi 'fail_open' vào policy_applied.
4. KHÔNG được lấy trường `confidence` của finding (do detector tất định chấm)
   làm correctness_score. Ba điểm số phải do BẠN tự đánh giá từ evidence và từ
   lập luận của Auditor/Skeptic. Nếu chỉ chép lại confidence của detector thì
   toàn bộ bước chấm điểm này vô nghĩa.
5. reasoning ĐẶT TRƯỚC triage_state.
6. Trả lời bằng tiếng Việt.
"""


def build_judge_prompt(
    finding_json,
    auditor_verdict_json,
    skeptic_verdict_json,
    llm_failed,
    debate_hard_stopped,
    cwe,
) -> list[dict]:
    ctx = []
    if llm_failed:
        ctx.append("⚠️ llm_failed=true. Áp fail-open.")
    if debate_hard_stopped:
        ctx.append("⚠️ Debate hard-stop (round=3), phải chốt.")
    if cwe in SENSITIVE_CWES:
        ctx.append(f"⚠️ CWE {cwe} nhạy cảm. Áp anti-over-suppression.")
    ctx_str = "\n".join(ctx) if ctx else "(không có policy đặc biệt)"

    skeptic_section = (
        f"\nSkeptic verdict:\n```json\n{skeptic_verdict_json}\n```"
        if skeptic_verdict_json
        else ""
    )

    return [
        {"role": "system", "content": SYSTEM_PROMPT_JUDGE},
        {
            "role": "user",
            "content": f"""Finding:
```json
{finding_json}
```

Auditor verdict:
```json
{auditor_verdict_json}
```
{skeptic_section}

Context:
{ctx_str}

Trả JSON JudgeDecision, reasoning trước, triage_state sau.""",
        },
    ]

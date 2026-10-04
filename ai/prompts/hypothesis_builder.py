"""Prompt cho Hypothesis Builder (VulAgent Phase II)."""

SYSTEM_PROMPT = """Bạn là chuyên gia phân tích bảo mật mã nguồn.
Nhiệm vụ DUY NHẤT: chuyển EvidenceBundle thành StructuredHypothesis gồm (assumptions, trigger_path, guards).

QUY TẮC BẮT BUỘC:
1. KHÔNG được lọc/pruning hypothesis. Chỉ xây, không loại bỏ.
2. Mọi guard tìm thấy phải ghi vào guards_on_path, KHÔNG dùng nó để loại path.
3. Assumption phải cụ thể, kiểm chứng được (ví dụ: "input length > buffer size").
4. Chỉ trả JSON đúng schema, không thêm text ngoài JSON.
5. Trả lời bằng tiếng Việt cho các trường mô tả.
"""


def build_hypothesis_prompt(finding_json: str) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Finding:\n```json\n{finding_json}\n```\n\nTrả JSON StructuredHypothesis.",
        },
    ]

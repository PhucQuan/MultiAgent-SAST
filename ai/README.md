# `ai/` — Multi-agent triage layer

Tầng multi-agent chạy trên NVIDIA NIM + LangGraph, nhận `NormalizedFinding` từ
Core SAST và trả về `triage_state` cuối cùng. Không chứa detector, benchmark
hay SARIF — những phần đó thuộc `aegis_sast/`.

## Chạy

### Cách 1 — một lệnh, dùng cho code của bạn (khuyến nghị)

```bash
python scripts/scan_with_ai.py <file-hoặc-thư-mục>
```

Lệnh này làm cả ba bước: quét tất định bằng Core SAST → gắn tool backend đọc mã
nguồn thật của target → đưa từng finding qua LangGraph multi-agent. Artifact ghi
vào `reports/ai_scans/<target>-<timestamp>/`.

Tuỳ chọn hay dùng:

| Cờ | Ý nghĩa |
|---|---|
| `--limit N` | Chỉ triage N finding đầu. Dùng để thử trước khi chạy cả dự án. |
| `--workers N` | Số finding chạy song song (mặc định 4). |
| `--family SQL_INJECTION` | Chỉ triage một loại lỗ hổng, lặp lại được. |
| `--no-ai-triage` | Chỉ quét tất định, không gọi LLM, không tốn credit. |
| `--exclude-dir test` | Bỏ qua thư mục, lặp lại được. |

### Cách 2 — hai bước, dùng cho benchmark

Khi đã có sẵn report JSON và muốn triage lại bằng multi-agent:

```bash
python scripts/run_ai_multiagent_benchmark.py \
  --report <aegis_sast_report.json> \
  --source-root <thư-mục-mã-nguồn> \
  --output-dir <thư-mục-kết-quả> \
  --workers 4
```

Runner này ghi `checkpoint.jsonl` sau mỗi finding, nên lần chạy dài bị đứt có thể
tiếp tục bằng `--resume <checkpoint.jsonl>`. Nó cũng xuất một report overlay có
`triage_status` thay bằng quyết định của multi-agent, để chấm lại bằng đúng
`scripts/score_owasp_benchmark.py` mà Core dùng.

### Cài đặt và kiểm tra

```bash
pip install -r requirements-ai.txt
cp .env.example .env          # rồi điền NVIDIA_API_KEY=nvapi-...
python -m ai.e2e_demo         # chạy 1 finding mẫu, xác nhận API thông
pytest ai/tests -q            # 94 test, toàn bộ dùng LLM giả, không chạm mạng
```

### Đọc kết quả

`triage_state` có 4 mức: `confirmed`, `likely`, `needs-review`, `suppressed`.
Chỉ `suppressed` mới là "bỏ đi"; ba mức còn lại đều được giữ lại để xem.

Dòng `[!] N finding rơi vào fail-open` nghĩa là LLM hỏng ở N finding đó và chính
sách fail-open đã đẩy chúng về `needs-review` — **kết quả của chúng không phải
phán quyết của agent**. Nếu N lớn thì đừng dùng lần chạy đó để kết luận.

Dòng `[!] N call bị cắt output` nghĩa là N lượt gọi chạm `AEGIS_MAX_TOKENS`; nâng
biến đó lên nếu con số này cao.

### Nhiều API key để chia tải

Một key bị 4 worker dội vào sẽ xếp hàng phía server. Nếu có nhiều key trên cùng
tài khoản NVIDIA, khai báo hết vào `NVIDIA_API_KEYS`, client sẽ xoay vòng:

```bash
NVIDIA_API_KEYS=nvapi-KEY1,nvapi-KEY2
```

Đo thực tế 2026-09-11, 8 lời gọi song song vào cùng một model:

| | Tổng | Latency TB |
|---|---:|---:|
| 1 key | 150,5s | 53,4s |
| 2 key | **84,6s** | **36,0s** |

Không khai báo thì hệ thống dùng `NVIDIA_API_KEY` như cũ.

## Cơ chế chịu lỗi

Mỗi cơ chế dưới đây sinh ra từ một lỗi đã quan sát được trên tải thật, không
phải phòng xa lý thuyết.

| Cơ chế | Chống lỗi gì |
|---|---|
| Retry 5xx, timeout, rate-limit (tenacity) | 503 thoáng qua của NVIDIA |
| `call_raw()` có retry riêng | vòng tool-use gọi thẳng SDK nên mất retry khi đặt `max_retries=0` |
| Vòng tool-use hỏng thì bỏ tool, vẫn chốt verdict | một lỗi tool không được giết cả finding |
| Nới trần token khi `finish_reason=length` | JSON dở dang làm mọi nấc parse trượt |
| `extract_json` quét mọi vị trí `{` | guided decoding phát dấu mở thừa |
| Ngân sách thời gian mỗi finding | model kẹt đốt hàng giờ cho một finding |
| Trần tool call theo finding | `auditor_reround` nhân trần lên theo số vòng |
| Pool nhiều API key xoay vòng | xếp hàng phía server khi nhiều worker dội một key |
| Fallback chain | model chính chết |
| Fail-open | mọi trường hợp còn lại: không bao giờ `suppressed` oan |

Tham số đã hiệu chỉnh bằng đo đạc (xem `.env.example`): `AEGIS_MAX_TOKENS=8192`,
trần khi bị cắt 16384, `AEGIS_FINDING_BUDGET_SEC=1200`, `AEGIS_TIMEOUT_SEC=150`,
`AEGIS_MAX_RETRIES=3`.

> `truncated_calls` trong báo cáo đếm **sự kiện bị cắt**, không phải thất bại —
> mỗi lần cắt đều được gọi lại với trần lớn hơn.

## Giới hạn hiện tại

- **Tool backend chỉ đọc Python.** `scripts/python_code_tools_backend.py` dựng chỉ
  mục bằng `ast`. Với target JS/Java/PHP, tool call trả về "không tìm thấy" và
  agent chỉ suy luận trên evidence của detector.
- **Chưa tái lập được.** `AEGIS_TEMP_HYPOTHESIS=0.5` khiến cùng một input có thể
  ra kết luận khác nhau giữa hai lần chạy. Hạ về 0 nếu cần số liệu cho báo cáo.
- **Endpoint NVIDIA có lúc trả 503.** Client đã retry 5xx, nhưng khi dịch vụ quá
  tải kéo dài thì tỉ lệ fail-open sẽ tăng. Chạy lại sau là cách xử lý.
- **Chi phí.** Đo trên OWASP BenchmarkPython 2026-09-06: 8,85 LLM call và ~43k
  token mỗi finding, khoảng 49 giây mỗi finding với 4 worker.

## Luồng

```
Planner (rule-based)
  └─ evidence_quality < 0.3 → NEEDS_REVIEW, dừng, không tốn token
Hypothesis Builder (qwen3-coder-480b)   → StructuredHypothesis, không pruning
Knowledge Loader (≤ 2 card)             → RAG tĩnh từ ai/knowledge/cards/
Auditor (qwen3-coder-480b + tool-use ≤5)
  └─ confidence ≥ 0.8 → thẳng tới Judge
Skeptic (deepseek-v3.1)                 → neutral, hoặc adversarial khi conf < 0.5
  └─ đồng thuận + conf ≥ 0.7 → Judge; bất đồng → debate lại, hard-stop ở round 3
Judge (nemotron-49b)                    → 3 tiêu chí + enforce policy trong Python
```

## Ba bất biến không được phá

1. **reasoning trước verdict** trong mọi schema — thứ tự field là thứ tự LLM
   sinh token, đảo lại là mất chuỗi suy luận.
2. **Fail-open** — LLM lỗi thì finding về `needs-review`, không bao giờ
   `suppressed`. Enforce ở cả prompt và `ai/nodes/judge.py`.
3. **Anti-over-suppression** — CWE trong `SENSITIVE_CWES` tối đa
   `needs-review`, kể cả khi LLM khăng khăng `suppressed`.

## Tích hợp với Core SAST

- `ai/schemas/finding.py` là contract với Core. Sửa file này phải thống nhất
  với người phụ trách Core.
- `ai/tools/code_tools.py` là interface tool-use. Gắn backend thật bằng:

```python
from ai.tools.code_tools import code_tools
code_tools.bind(get_callers=..., get_callees=..., get_body=...)
```

Mặc định là mock trả về rỗng, đủ để agent chạy độc lập.

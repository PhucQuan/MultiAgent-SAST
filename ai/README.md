# `ai/` — Multi-agent triage layer

Tầng multi-agent chạy trên NVIDIA NIM + LangGraph, nhận `NormalizedFinding` từ
Core SAST và trả về `triage_state` cuối cùng. Không chứa detector, benchmark
hay SARIF — những phần đó thuộc `aegis_sast/`.

Nguyên tắc chi phối toàn bộ tầng này: **phân tích tĩnh là nguồn bằng chứng, LLM
chỉ phân loại và giải thích.** LLM không bao giờ là nguồn sự thật — mọi kết
luận thay đổi được output đều phải trích được bằng chứng do chương trình sinh
ra.

## Chế độ chạy

NVIDIA Build free tier là tài nguyên khan hiếm, nên mặc định **không** phải
`active`. Đặt bằng `AEGIS_AI_MODE`:

| Mode | Hành vi | Dùng khi |
|---|---|---|
| `disabled` | Không gọi LLM | Baseline, CI nhanh, debug core |
| `heuristic` | Chỉ filter tất định | Cắt FP mà không tốn API |
| `shadow` *(mặc định)* | Chạy AI, ghi log, **không đổi output** | Thu dữ liệu, kiểm tra an toàn |
| `review-only` | AI tóm tắt evidence, không gắn verdict | Demo, người review |
| `active` | AI gắn verdict theo policy | Chỉ bật sau khi benchmark ổn định |

Ở `shadow` và `review-only`, verdict vẫn được sinh nhưng mang cờ
`applies_to_output=False`. Phía gọi phải tôn trọng cờ này.

## Điểm vào duy nhất

Core, CLI và script chỉ được import từ `aegis_sast.ai.api`:

```python
from aegis_sast.ai.api import AITriageService, TriageRequest

service = AITriageService(run_id="run-1")
verdict = service.triage(TriageRequest(
    finding_id="f-001", commit_sha=sha, normalized_finding=finding.model_dump()
))
```

Import thẳng `ai.graph` hay `ai.llm.nvidia_client` từ bên ngoài là đi vòng qua
eligibility gate và policy suppression — bỏ qua đúng hai cơ chế giữ cho verdict
an toàn và chi phí có trần.

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
pytest ai/tests -q            # 154 test, toàn bộ dùng LLM giả, không chạm mạng
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
Eligibility gate (rule-based, KHÔNG gọi LLM)
  └─ severity thấp / evidence mỏng / hết ngân sách → NEEDS_REVIEW, 0 token
Evidence inventory (KHÔNG gọi LLM)      → nạp evidence của Core vào ledger
Planner (rule-based)
  └─ evidence_quality < 0.3 → NEEDS_REVIEW, dừng
Investigation planner (rule-based)      → chọn ≤ 2 tool static cần chạy
Tool executor (KHÔNG gọi LLM)           → chạy tool, ghi artifact có hash
Hypothesis Builder                      → StructuredHypothesis, không pruning
Knowledge Loader (≤ 2 card)             → RAG tĩnh từ ai/knowledge/cards/
Auditor (+ tool-use ≤ 5)
Skeptic                                 → neutral, hoặc adversarial khi conf thấp
Deterministic validator (KHÔNG gọi LLM) → chạy lại tool static, trả lời bằng
                                           dữ liệu chương trình
  └─ còn bất đồng / thiếu evidence VÀ vòng trước có artifact mới
       → quay lại Investigation planner (hard-stop ở debate_round_max)
Judge                                   → 3 tiêu chí + policy enforce trong Python
```

Điểm khác cốt lõi so với bản đầu: nhánh quay lại dẫn về **planner**, không về
Auditor. Hỏi lại cùng một mô hình trên cùng một ngữ cảnh chỉ lặp lại cùng thiên
kiến với chi phí gấp đôi — bất đồng phải được giải quyết bằng dữ kiện mới. Nếu
một vòng không thu thêm được artifact nào, graph chốt luôn thay vì tranh luận
tiếp.

Bốn node đầu và validator đều không gọi LLM, nên một finding bị gate loại hoặc
được tool static giải quyết dứt điểm sẽ không tốn token nào.

## Năm bất biến không được phá

Tất cả đều enforce bằng Python trong `ai/policies/suppression.py`, không chỉ
bằng lời dặn trong prompt: một mô hình có thể bỏ qua lời dặn, không thể bỏ qua
câu lệnh `if`.

1. **reasoning trước verdict** trong mọi schema — thứ tự field là thứ tự LLM
   sinh token, đảo lại là mất chuỗi suy luận.
2. **Fail-open** — LLM lỗi thì finding về `needs-review`, không bao giờ
   `suppressed`.
3. **Anti-over-suppression** — CWE trong `SENSITIVE_CWES` tối đa
   `needs-review`, kể cả khi LLM khăng khăng `suppressed`.
4. **High/Critical không bao giờ auto-suppress.** Cần bật tường minh
   `AEGIS_HIGH_CRITICAL_AUTO_SUPPRESS=true` mới cho phép, và khi đó vẫn phải có
   validator chứng minh. Một cảnh báo thừa tốn vài phút của người review; một
   lỗ hổng bị giấu có thể lên production.
5. **Suppress phải có bằng chứng tất định.** Verdict "false positive" của LLM
   chỉ được ghi vào output khi validator chứng minh được mẫu an toàn (hằng số
   ràng buộc, hoặc sanitizer tác động đúng biến mà sink đọc) VÀ citation của
   agent trỏ tới `file:line` có thật. "Không tìm thấy dấu hiệu nguy hiểm" khác
   hẳn "chứng minh được an toàn".

## Tích hợp với Core SAST

- `ai/schemas/finding.py` là contract với Core. Sửa file này phải thống nhất
  với người phụ trách Core.
- `ai/tools/code_tools.py` là interface tool-use. Gắn backend thật bằng:

```python
from ai.tools.code_tools import code_tools
code_tools.bind(
    get_callers=..., get_callees=..., get_body=...,
    get_dataflow_path=..., get_sanitizer_trace=...,
    get_backward_slice=..., get_forward_slice=...,
    get_control_flow_context=..., get_constant_propagation=...,
    resolve_symbol=...,
)
```

`scripts/python_code_tools_backend.py` đã cài sẵn toàn bộ backend trên cho
Python; gọi `bind_python_backend(root)` là xong.

Tool chưa gắn backend trả `ToolResult(success=False)` kèm lý do — **không** trả
dữ liệu rỗng. Một `get_callers` trả `[]` vì backend chưa gắn sẽ bị agent đọc
thành "không ai gọi hàm này" và dẫn thẳng tới kết luận không khai thác được.
Cần mock tường minh thì dùng `make_mock_tools()`.

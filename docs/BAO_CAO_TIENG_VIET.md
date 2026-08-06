# Báo cáo tiến độ Aegis-SAST AI

Ngày cập nhật: 2026-08-06

## 1. Mục tiêu

Dự án đã bổ sung tầng AI triage cho Aegis-SAST. Mục tiêu của tầng này là nhận kết quả phân tích tĩnh đã được chuẩn hóa từ deterministic core, sau đó đánh giá lại mức độ tin cậy của finding, hỗ trợ giảm false positive và tạo phần giải thích/remediation có cấu trúc.

Tầng AI không tự đọc lại repository, không tự phân tích AST và không tự tạo bằng chứng mới. AI chỉ làm việc trên dữ liệu đã được deterministic core cung cấp, gồm:

- `NormalizedFinding`
- `EvidenceBundle`
- `BenchmarkMetadata`

Cách thiết kế này giúp tách rõ trách nhiệm:

- Deterministic core phụ trách scan code, tìm source-to-sink path, evidence, sanitizer và call chain.
- AI phụ trách review bằng chứng, phân tích khả năng false positive, đưa ra trạng thái triage và viết giải thích.

## 2. Schema và contract AI

Đã khóa schema đầu vào và đầu ra bằng Pydantic.

Đầu vào tối thiểu của AI gồm:

- `finding_id`
- `language`
- `vuln_type`
- `severity`
- `confidence`
- `source_location`
- `sink_location`
- `evidence_snippets`
- `data_flow_path`
- `sanitizer_info`
- `cross_file`
- `call_chain_depth`
- `rule_id`

Bốn trạng thái triage cuối cùng đã được chuẩn hóa:

| Trạng thái | Ý nghĩa |
| --- | --- |
| `confirmed` | Bằng chứng đủ mạnh, có source-to-sink path hợp lệ |
| `likely` | Khả năng cao là lỗ hổng nhưng còn thiếu một phần bằng chứng |
| `needs-review` | AI không đủ cơ sở kết luận, cần chuyên gia kiểm tra |
| `suppressed` | Finding được xác định là false positive hoặc không reachable |

Mỗi node AI đều có output riêng bằng Pydantic, không trả về văn bản tự do. Các contract chính gồm:

- `PlannerResult`
- `AuditorResult`
- `SkepticResult`
- `TriageDecision`
- `ReporterResult`

File liên quan:

- `aegis_sast/triage/schema.py`
- `aegis_sast/orchestration/state.py`
- `aegis_sast/orchestration/contracts.py`
- `docs/ai_contract.md`
- `tests/test_triage_schema.py`
- `tests/test_agent_contracts.py`

## 3. Workflow AI và LangGraph

Đã xây dựng workflow nhiều node cho AI triage:

1. `Planner`: đánh giá chất lượng evidence và chọn route xử lý.
2. `KnowledgeLoader`: nạp tri thức CWE/ngôn ngữ/framework phù hợp.
3. `Auditor`: đánh giá khả năng khai thác dựa trên source, sink, data flow và sanitizer.
4. `Skeptic`: tìm dấu hiệu false positive, sanitizer hiệu quả hoặc dead code.
5. `Judge`: đưa ra quyết định triage cuối cùng.
6. `Reporter`: bổ sung giải thích và remediation cho báo cáo.

Workflow có thể chạy bằng engine nội bộ và có adapter để compile sang LangGraph khi môi trường đã cài `langgraph`.

Ý nghĩa của LangGraph trong dự án:

- Nếu không có LangGraph: workflow vẫn chạy được bằng orchestration nội bộ.
- Nếu có LangGraph: các node được đóng gói thành graph rõ ràng, dễ quan sát route, mở rộng pipeline, chạy ablation và debug luồng xử lý.

Lệnh kiểm tra LangGraph:

```bash
/opt/anaconda3/bin/python - <<'PY'
from aegis_sast.orchestration.langgraph_adapter import build_langgraph_workflow

graph = build_langgraph_workflow()
print(type(graph).__name__)
PY
```

Nếu in ra `CompiledStateGraph` thì LangGraph đã compile được.

## 4. Kết nối Groq API

Dự án đã hỗ trợ Groq theo OpenAI-compatible chat completions API.

Thêm API key:

```bash
export GROQ_API_KEY="gsk_your_key_here"
```

Có thể chọn model:

```bash
export GROQ_MODEL="llama-3.1-8b-instant"
```

Chạy smoke test thật với Groq:

```bash
/opt/anaconda3/bin/python scripts/smoke_groq_structured.py
```

Kết quả smoke test thành công trên máy đã trả về `TriageDecision` hợp lệ, ví dụ:

- `finding_id`: `PY-CMD-001`
- `status`: `confirmed`
- `confidence`: `0.87`
- `route_taken`: `planner -> auditor -> judge`
- `token_usage`: `693`

Điều này chứng minh Groq API đã gọi được và output AI đã được validate theo schema.

## 5. Test tự động

Đã bổ sung test để đảm bảo:

- Pydantic validate được input/output.
- Thiếu trường bắt buộc sẽ báo lỗi rõ.
- Python, JavaScript, Java và PHP dùng chung schema.
- Node AI không được trả output không cấu trúc.
- Groq/Gemini client retry khi output sai schema và fallback về `needs-review`.
- Workflow AI chạy được end-to-end trên fixture mock.
- Evaluator tính được precision proxy, false positive reduction và suppression error.
- Script OWASP BenchmarkJava tính đúng TP/FP/TN/FN.

Lệnh chạy toàn bộ test:

```bash
/opt/anaconda3/bin/python -m pytest
```

Kết quả gần nhất:

```text
117 passed, 1 skipped
```

## 6. Experiment và đánh giá AI

Đã có pipeline chạy experiment trên dataset mock:

```bash
/opt/anaconda3/bin/python scripts/run_ai_experiments.py \
  --config benchmarks/ai_experiments/e3_workflow_ablation.json
```

Đánh giá kết quả:

```bash
/opt/anaconda3/bin/python scripts/evaluate_ai_results.py \
  --raw benchmarks/ai_experiments/results/E3-workflow-ablation-mock.jsonl \
  --out benchmarks/ai_experiments/results/E3-workflow-ablation-mock.evaluation.json
```

Kết quả mẫu từ mock benchmark:

```json
{
  "precision_proxy": 1.0,
  "false_positive_reduction_rate": 1.0,
  "suppression_error_rate": 0.0,
  "labeled_rows": 3,
  "total_rows": 4
}
```

Lưu ý: đây là dataset mock nhỏ, dùng để kiểm tra pipeline và logic tính điểm, chưa phải kết quả thực nghiệm cuối cùng.

## 7. Chạy trên OWASP BenchmarkJava

OWASP Benchmark là bộ benchmark dùng để đánh giá độ chính xác, độ phủ và tốc độ của các công cụ SAST. Trong dự án này đã tích hợp script chạy Aegis-SAST trên OWASP BenchmarkJava v1.2.

Nguồn benchmark:

- https://owasp.org/www-project-benchmark/
- https://github.com/OWASP-Benchmark/BenchmarkJava

Tải benchmark:

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git /tmp/BenchmarkJava
```

Chạy Aegis-SAST và tính điểm:

```bash
cd /Users/ductue/Documents/NCKH/SAST_tool4pentester

/opt/anaconda3/bin/python scripts/run_owasp_benchmark_java.py \
  --benchmark-root /tmp/BenchmarkJava \
  --out-dir benchmarks/owasp_benchmark_java
```

File kết quả:

- `benchmarks/owasp_benchmark_java/aegis_owasp_benchmark_java_score.json`
- `benchmarks/owasp_benchmark_java/aegis_owasp_benchmark_java_cases.csv`

Kết quả gần nhất trên OWASP BenchmarkJava:

```text
Benchmark commit: 0eed5dd930cfcb619e1dde13d21591086e65531a
Số file scan: 2766
Số case benchmark: 2740
Lỗi scanner: 0
Thời gian chạy: 34.46 giây
```

Kết quả trên tất cả category:

| Metric | Giá trị |
| --- | ---: |
| TP | 12 |
| FP | 3 |
| TN | 1322 |
| FN | 1403 |
| Precision | 0.8000 |
| Recall | 0.0085 |
| False positive rate | 0.0023 |
| F1 | 0.0168 |

Kết quả chỉ tính các category Aegis-SAST hiện đang map được với OWASP BenchmarkJava: `cmdi`, `pathtraver`, `sqli`, `xss`.

| Metric | Giá trị |
| --- | ---: |
| Total | 1478 |
| TP | 12 |
| FP | 3 |
| TN | 698 |
| FN | 765 |
| Precision | 0.8000 |
| Recall | 0.0154 |
| False positive rate | 0.0043 |
| F1 | 0.0303 |

Kết quả theo category chính:

| Category | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `xss` | 12 | 3 | 206 | 234 | 0.8000 | 0.0488 | 0.0920 |
| `sqli` | 0 | 0 | 232 | 272 | 0.0000 | 0.0000 | 0.0000 |
| `cmdi` | 0 | 0 | 125 | 126 | 0.0000 | 0.0000 | 0.0000 |
| `pathtraver` | 0 | 0 | 135 | 133 | 0.0000 | 0.0000 | 0.0000 |

Nhận xét:

- Công cụ đã chạy thành công trên OWASP BenchmarkJava, scan 2766 file và không bị lỗi scanner.
- Precision đạt 0.8 vì số false positive thấp.
- Recall còn rất thấp, nghĩa là scanner Java hiện mới bắt được một phần nhỏ trong benchmark.
- Kết quả hiện tại phù hợp để báo cáo rằng pipeline benchmark đã hoạt động, nhưng rules Java cần được cải thiện tiếp nếu muốn tăng độ phủ.

## 8. Nội dung đã push lên Git

Nhánh làm việc:

```text
tuệ
```

Commit benchmark gần nhất:

```text
16d720b test(benchmark): add OWASP BenchmarkJava scoring
```

Nội dung chính đã triển khai:

- Schema và contract AI.
- Multi-node AI workflow.
- LangGraph adapter.
- Groq structured client.
- Smoke test Groq.
- Fixture mock và experiment runner.
- Evaluator tính chỉ số AI.
- Script chạy OWASP BenchmarkJava.
- Artifact kết quả OWASP BenchmarkJava.

## 9. Kết luận báo cáo

Đến thời điểm hiện tại, dự án đã hoàn thành phần nền tảng AI triage và pipeline đánh giá:

- AI layer đã có schema rõ ràng, output có cấu trúc và có validate.
- Workflow nhiều node đã chạy được và có thể compile với LangGraph.
- Groq API đã được tích hợp và smoke test thành công.
- Hệ thống có test tự động và experiment runner.
- Đã có script chạy benchmark thực tế trên OWASP BenchmarkJava.
- Đã có số liệu TP/FP/TN/FN, precision, recall, false positive rate và F1 để đưa vào báo cáo.

Hướng phát triển tiếp theo:

- Cải thiện rule Java cho SQL Injection, Command Injection và Path Traversal.
- Bổ sung mapping thêm các category OWASP như `crypto`, `hash`, `weakrand`, `ldapi`, `xpathi`, `securecookie`.
- Chạy lại benchmark sau mỗi đợt cải thiện rule để so sánh recall/F1.
- Thu thập dataset thực tế có label từ Quân để đánh giá AI triage ngoài benchmark mock.

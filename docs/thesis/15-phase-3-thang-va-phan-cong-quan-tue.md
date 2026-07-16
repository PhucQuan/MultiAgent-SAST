# KẾ HOẠCH NGHIÊN CỨU 3 THÁNG VÀ PHÂN CÔNG NHIỆM VỤ

## Đề tài: Aegis-SAST - Hệ thống Agentic Hybrid SAST đa ngôn ngữ

**Thành viên thực hiện:** Phúc Quân và Tuệ  
**Thời lượng:** 12 tuần  
**Nguyên tắc phân công:** Tuệ phụ trách mảng AI, agent và knowledge; Quân phụ trách mảng cyber, core scanner, backend và benchmark.

---

## 1. Mục tiêu của giai đoạn 3 tháng

Trong 12 tuần, nhóm tập trung nâng Aegis-SAST từ scanner AST-based hiện có lên một hệ thống đủ tầm khóa luận và NCKH với bốn trục kỹ thuật:

1. Củng cố `NormalizedFinding` và `EvidenceBundle`.
2. Nâng Python lên mức phân tích sâu hơn bằng `DFG-lite` và `CFG-lite`.
3. Hoàn thiện workflow triage có trạng thái bằng LangGraph.
4. Xây dựng benchmark đối chứng, SARIF và tài liệu báo cáo.

Định hướng kỹ thuật của giai đoạn này là **đi sâu theo chiều dọc ở Python**, đồng thời giữ JavaScript, Java và PHP ở vai trò mở rộng kiến trúc đa ngôn ngữ.

---

## 2. Phân công vai trò

### 2.1. Quân - Core Scanner, Cyber và Benchmark

Quân phụ trách các phần việc thiên về backend, static analysis và thực nghiệm:

- Chuẩn hóa `NormalizedFinding`, `EvidenceBundle`, path summary và metadata benchmark.
- Nâng cấp deterministic core: AST, taint propagation, call graph và các phần mở rộng DFG-lite/CFG-lite cho Python.
- Hoàn thiện đầu ra JSON, Markdown, SARIF và phần tích hợp CI/CD ở mức demo.
- Xây dựng benchmark harness, script đánh giá và đối chứng với Semgrep.
- Thiết kế và gắn nhãn bộ synthetic dataset Python cùng Tuệ.

### 2.2. Tuệ - AI, Agent và Knowledge

Tuệ phụ trách các phần việc thiên về AI và workflow:

- Thiết kế và triển khai workflow LangGraph với các node Planner, KnowledgeLoader, Auditor, SkepticValidator, Judge và Reporter.
- Xây dựng `Knowledge Cards`, sanitizer rubric, false-positive patterns và remediation hints.
- Thiết kế structured output cho triage, explanation và route decision.
- Thực hiện các kịch bản ablation liên quan đến AI triage, knowledge và workflow stability.
- Viết các phần báo cáo liên quan đến AI triage, agent orchestration và knowledge layer.

### 2.3. Cơ chế phối hợp

- Hai thành viên review chéo ít nhất 1 lần mỗi tuần.
- Mọi thay đổi lớn đều đi qua pull request hoặc review nội bộ trước khi gộp.
- Dùng chung schema finding để tránh lệch dữ liệu giữa core và agent.
- Các bộ dữ liệu benchmark phải được gắn nhãn và rà soát bởi cả hai thành viên.

---

## 3. Lộ trình triển khai theo 5 giai đoạn

### Giai đoạn 1. Tuần 1-2: Schema, Evidence và Triage Model

**Mục tiêu:** chốt dữ liệu đầu vào chung cho scanner, workflow agent và benchmark.

**Quân thực hiện:**

- Rà soát finding model hiện tại.
- Chuẩn hóa `NormalizedFinding`.
- Thiết kế `EvidenceBundle` gồm source, sink, sanitizer, path summary, snippet và confidence.
- Tạo bộ finding mẫu để Tuệ phát triển workflow song song.

**Tuệ thực hiện:**

- Chốt các trạng thái triage: `confirmed`, `likely`, `needs-review`, `suppressed`.
- Thiết kế structured output cho từng node agent.
- Chốt template cho `Knowledge Card`.
- Chốt điều kiện route giữa Auditor, SkepticValidator và Judge.

**KPI giai đoạn 1:**

- Có schema finding thống nhất.
- Có bộ sample finding dùng chung cho core và agent.
- Có mô hình triage status và route decision thống nhất.

### Giai đoạn 2. Tuần 3-4: DFG-lite và Knowledge Layer

**Mục tiêu:** làm evidence đủ sâu để AI triage có cơ sở kỹ thuật tốt hơn.

**Quân thực hiện:**

- Theo dõi assignment từ biến sang biến trong Python.
- Theo dõi argument -> parameter.
- Theo dõi return value -> biến nhận.
- Cải thiện path summary phục vụ evidence.

**Tuệ thực hiện:**

- Viết `Knowledge Cards` cho 5 nhóm lỗi ưu tiên: SQLi, XSS, Command Injection, Path Traversal, SSRF.
- Xây sanitizer rubric theo Python, JavaScript, Java và PHP.
- Xây knowledge loader và cơ chế chọn card phù hợp theo finding.

**KPI giai đoạn 2:**

- Python có `DFG-lite` ở mức thực dụng.
- Có knowledge library nền tảng cho 5 nhóm CWE.
- Workflow triage có thể dùng evidence + knowledge để đánh giá finding.

### Giai đoạn 3. Tuần 5-7: CFG-lite và LangGraph Workflow

**Mục tiêu:** tăng khả năng path reasoning và hoàn thiện workflow triage.

**Quân thực hiện:**

- Bổ sung `CFG-lite` cho Python.
- Xử lý branch-aware path.
- Kiểm tra sanitizer có nằm trên đường tới sink hay không.
- Xử lý guard clause, return sớm và loại bỏ path không hợp lệ rõ ràng.

**Tuệ thực hiện:**

- Triển khai LangGraph workflow đầy đủ.
- Hoàn thiện các node Planner, KnowledgeLoader, Auditor, SkepticValidator, Judge, Reporter.
- Thiết lập conditional routing theo confidence.
- Tối ưu prompt, caching và structured output cho từng node.

**KPI giai đoạn 3:**

- Python có path reasoning tốt hơn AST-only.
- Workflow LangGraph chạy được end-to-end trên finding thực.
- Có route summary và triage summary rõ ràng trong pipeline.

### Giai đoạn 4. Tuần 8-10: Reporting, SARIF và Benchmark

**Mục tiêu:** xây lớp chứng minh giá trị kỹ thuật và học thuật của hệ thống.

**Quân thực hiện:**

- Hoàn thiện exporter JSON, Markdown và SARIF.
- Xây benchmark harness chạy batch.
- Chạy baseline với Semgrep.
- Chuẩn bị synthetic dataset Python và dữ liệu Juliet/OWASP Benchmark ở phạm vi phù hợp.

**Tuệ thực hiện:**

- Thực hiện các kịch bản ablation:
  - E1: Static-only vs Static + AI Triage
  - E2: Không Knowledge vs Có Knowledge
  - E3: Single-prompt vs LangGraph workflow
  - E4: AST/Taint vs AST/Taint + DFG-lite/CFG-lite
- Tổng hợp explanation, route decision và token usage.
- Viết phần phân tích kết quả agent.

**KPI giai đoạn 4:**

- Có báo cáo SARIF tích hợp được với GitHub Code Scanning ở mức demo.
- Có bảng Precision, Recall, F1 và False-Positive Reduction.
- Có số liệu đối chứng với Semgrep.

### Giai đoạn 5. Tuần 11-12: Hoàn thiện báo cáo và chuẩn bị bảo vệ

**Mục tiêu:** đóng gói sản phẩm và hồ sơ khoa học.

**Quân thực hiện:**

- Rà soát scanner core, exporter, benchmark scripts.
- Hoàn thiện phần báo cáo về static analysis, DFG-lite, CFG-lite, benchmark.
- Chuẩn bị demo kỹ thuật.

**Tuệ thực hiện:**

- Hoàn thiện phần báo cáo về LangGraph, AI triage, knowledge loading và ablation.
- Chuẩn bị slide, kịch bản demo và phần trình bày đóng góp nghiên cứu.
- Rà soát tính thống nhất giữa báo cáo, code và số liệu thực nghiệm.

**KPI giai đoạn 5:**

- Có bản báo cáo hoàn chỉnh.
- Có demo scan -> triage -> report.
- Có bộ số liệu đủ để bảo vệ hướng NCKH.

---

## 4. Phân công chi tiết theo tuần

| Tuần | Quân | Tuệ | Đầu ra chính |
|---|---|---|---|
| 1 | Rà soát finding model, rule flow, call graph | Rà soát AI verification hiện có, chốt triage statuses | Báo cáo hiện trạng và scope kỹ thuật |
| 2 | Chốt `NormalizedFinding`, `EvidenceBundle`, sample findings | Chốt workflow state và output schema | Schema thống nhất |
| 3 | Cài `DFG-lite` cho assignment và argument flow | Viết knowledge cards cho SQLi, XSS | Evidence tốt hơn cho Python |
| 4 | Cài `DFG-lite` cho return flow, path summary | Viết knowledge cards cho Command Injection, Path Traversal, SSRF; hoàn thiện loader | Knowledge layer nền tảng |
| 5 | Cài `CFG-lite` cho branch-aware path | Xây LangGraph graph và node contracts | Graph workflow bản đầu |
| 6 | Cài sanitizer reachability và guard clauses | Tối ưu Auditor, SkepticValidator, Judge | Triage logic rõ hơn |
| 7 | Tích hợp finding thực vào workflow | Tối ưu Reporter, route summary, explanation | Pipeline end-to-end |
| 8 | Hoàn thiện SARIF và reporting | Chuẩn bị E1, E2 | Report và evaluation layer |
| 9 | Xây benchmark harness, dataset loader | Chạy E1, E2 | Số liệu triage ban đầu |
| 10 | Chạy baseline Semgrep, tổng hợp metrics | Chạy E3, E4 | Bộ số liệu đối chứng |
| 11 | Viết chương core, benchmark, demo kỹ thuật | Viết chương agent, knowledge, ablation | Bản báo cáo gần hoàn chỉnh |
| 12 | Rà soát cuối, chuẩn bị bảo vệ | Rà soát cuối, chuẩn bị slide và script demo | Hồ sơ bảo vệ hoàn chỉnh |

---

## 5. Quy trình xây dựng bộ dữ liệu benchmark

### 5.1. Synthetic Dataset cho Python

Bộ dữ liệu này là trọng tâm vì Python là ngôn ngữ phân tích sâu của đề tài.

- Quy mô mục tiêu: 50-100 mẫu.
- Nhóm lỗi ưu tiên: SQLi, XSS, Command Injection, Path Traversal, SSRF.
- Mỗi mẫu phải có source, sink, ngữ cảnh dữ liệu và nhãn kỳ vọng rõ ràng.

### 5.2. Quy trình gắn nhãn

1. Quân gắn nhãn vòng đầu dựa trên góc nhìn scanner/core.
2. Tuệ gắn nhãn vòng hai dựa trên góc nhìn evidence và triage.
3. Các trường hợp bất đồng được review lại thủ công.
4. Bộ nhãn cuối cùng mới được dùng cho benchmark và ablation.

### 5.3. Bộ dữ liệu đối chứng

- Juliet Test Suite dùng cho Java ở mức đối chứng mở rộng.
- OWASP Benchmark chỉ dùng nếu kịp thời gian.
- `examples/` và `test_projects/` dùng cho smoke test và demo.

---

## 6. Rủi ro và phương án giảm thiểu

| Rủi ro | Ảnh hưởng | Hướng giảm thiểu |
|---|---|---|
| Phạm vi quá rộng | Không đủ chiều sâu nghiên cứu | Khóa sâu ở Python, giữ JS/Java/PHP ở mức mở rộng |
| AI triage thiếu ổn định | Kết quả không nhất quán | Dùng structured output, rubric rõ và route có điều kiện |
| DFG/CFG quá nặng | Trễ tiến độ | Chỉ triển khai mức `lite`, tập trung trực tiếp vào false positive |
| Benchmark thiếu ground truth | Khó chứng minh giá trị học thuật | Tự tạo synthetic dataset và gắn nhãn chéo bởi 2 người |
| Token API quá cao | Hạn chế số lần chạy thí nghiệm | Dùng conditional routing, caching và batch có kiểm soát |
| Môi trường Windows không ổn định | Trễ kiểm thử | Chuẩn hóa môi trường CPython riêng cho scanner core và AI extras |

---

## 7. Kết luận

Kế hoạch 3 tháng này được thiết kế theo hướng thực dụng nhưng vẫn đủ chiều sâu cho khóa luận và nghiên cứu khoa học. Phần khó nhất không nằm ở việc “gắn thêm agent”, mà nằm ở việc làm cho finding có bằng chứng đủ mạnh, sau đó mới dùng LangGraph để triage và benchmark một cách thuyết phục.

# KẾ HOẠCH NGHIÊN CỨU VÀ PHÂN CÔNG NHIỆM VỤ

## Đề tài: Aegis-SAST — Hệ thống Agentic Hybrid SAST đa ngôn ngữ

**Sinh viên thực hiện:** Phúc Quân (Core & Benchmark) — Tuệ (AI Agent & Knowledge)
**Thời lượng:** 12 tuần (3 tháng)
**Cập nhật lần cuối:** 2026-07-11

---

## 1. Tổng quan mục tiêu

### 1.1. Mục tiêu cốt lõi

Trong 12 tuần, dự án chuyển đổi Aegis-SAST từ một bộ quét tĩnh cấp portfolio thành nền tảng **Agentic Hybrid SAST** đạt chuẩn nghiên cứu khoa học. Hệ thống lai ghép giữa phân tích cú pháp deterministic (AST, Taint Flow, Call Graph) và đồ thị đa tác nhân AI (Multi-Agent Graph) nhằm giảm tỷ lệ báo động giả (False Positive) một cách có kiểm chứng định lượng.

### 1.2. Bốn trụ cột giá trị

| # | Trụ cột | Mô tả ngắn |
|---|---------|-------------|
| 1 | **Deterministic Core** | Chuẩn hóa bằng chứng phát hiện lỗi từ AST, Taint Flow và Call Graph (Cross-file cho Python). |
| 2 | **Stateful Agent Workflow** | Đồ thị trạng thái LangGraph với chu trình lập luận–phản biện (Planner → Auditor → SkepticValidator → Judge). |
| 3 | **Structured Knowledge Base** | Kho tri thức bảo mật cục bộ (Knowledge Cards) cung cấp ngữ cảnh chuyên sâu cho tác nhân AI. |
| 4 | **Scientific Verification** | Thực nghiệm định lượng trên Juliet Test Suite, bộ Synthetic Dataset tự tạo, và đối chứng với Semgrep. |

### 1.3. Ngăn xếp công nghệ (Technology Stack)

| Thành phần | Công nghệ |
|------------|-----------|
| Ngôn ngữ chính | Python 3.12+ |
| Phân tích cú pháp | Tree-sitter (đa ngôn ngữ) |
| Điều phối đa tác nhân | LangGraph (StateGraph) |
| Mô hình ngôn ngữ lớn | Gemini 2.0 Flash (qua Google AI API) |
| Kiểm soát schema | Pydantic v2 (Structured Outputs) |
| Giao diện dòng lệnh | Rich CLI |
| Định dạng đầu ra | JSON, Markdown, SARIF v2.1.0 |
| Quản lý cấu hình quy tắc | YAML Rule Files |
| Thư viện hỗ trợ | tenacity (retry), diskcache (caching), pytest |

---

## 2. Nguyên tắc phân công vai trò

### 2.1. Quân — Trưởng mảng Core Engine & Benchmark

- Chịu trách nhiệm toàn bộ tầng phân tích tĩnh: bộ phân tích AST, Taint Flow Engine, Call Graph hỗ trợ Cross-file cho Python.
- Thiết kế lược đồ dữ liệu chuẩn hóa (`NormalizedFinding`, `EvidenceBundle`).
- Tạo **Mock JSON Data** (finding giả lập đúng schema) giao cho Tuệ từ tuần 2–3 để phát triển Agent song song.
- Triển khai bộ xuất dữ liệu (JSON, Markdown, SARIF) và module benchmark tự động.
- Chạy thực nghiệm đối chứng với Semgrep, thu thập số liệu TP/FP/FN.

### 2.2. Tuệ — Trưởng mảng AI Agent & Knowledge Layer

- Thiết kế và lập trình đồ thị trạng thái đa tác nhân LangGraph (Planner, Auditor, SkepticValidator, Judge).
- Xây dựng kho tri thức bảo mật cục bộ (Knowledge Cards) và module `KnowledgeLoader`.
- Thiết lập cơ chế **Conditional Routing**: finding có Confidence = High đi thẳng qua Judge; chỉ finding Medium/Low mới qua SkepticValidator.
- Thực hiện nghiên cứu phân rã (Ablation Study) để chứng minh hiệu quả từng thành phần.
- Viết báo cáo các chương về Agent Workflow và Knowledge Base.

### 2.3. Nguyên tắc cộng tác

- Mỗi tuần tổ chức ít nhất 1 buổi review chéo (code review hoặc sync meeting).
- Mọi deliverable phải có commit trên nhánh riêng, merge qua pull request.
- Sử dụng Mock Data Strategy (xem Mục 8) để hai nhánh công việc phát triển song song mà không bị nghẽn.

---

## 3. Lộ trình thực hiện chi tiết — 5 Phase, 12 Tuần

### Phase 1. Tuần 1–2: Khóa thiết kế kiến trúc và Lược đồ dữ liệu

**Mục tiêu:** Thống nhất lược đồ dữ liệu chung giữa bộ quét tĩnh, đồ thị AI Agent, hệ thống báo cáo và bộ benchmark. Tạo Mock Data sớm để mở khóa công việc song song.

**Công việc của Quân:**

1. Rà soát (audit) mã nguồn bộ quét tĩnh hiện tại (`aegis_sast/plugins/`, `analysis/rule_engine.py`, `call_graph.py`).
2. Thiết kế lược đồ `NormalizedFinding` và cấu trúc `EvidenceBundle` (gồm: source location, sink location, dataflow path, code snippet, confidence score).
3. Tạo bộ **Mock JSON Data** gồm 20–30 finding giả lập bao phủ các trường hợp: True Positive, False Positive, finding có confidence High/Medium/Low. Giao cho Tuệ cuối tuần 2.

**Công việc của Tuệ:**

1. Phân tích cơ chế AI verification cũ (`gemini_client.py`), xác định khoảng trống: thiếu trạng thái, thiếu phản biện, thiếu structured output.
2. Định nghĩa trạng thái Triage: `confirmed`, `likely`, `needs-review`, `suppressed`.
3. Phác thảo sơ đồ đồ thị LangGraph (các node, edge, điều kiện rẽ nhánh) dưới dạng tài liệu markdown.

**KPI Phase 1:**

- Lược đồ `NormalizedFinding` v1 được commit vào `aegis_sast/core/models.py`.
- Bộ Mock JSON Data hoàn thành và sẵn sàng cho Tuệ sử dụng.
- Tài liệu thiết kế đồ thị LangGraph v1 hoàn thành.

---

### Phase 2. Tuần 3–5: Chuẩn hóa Core Engine và Xây dựng Knowledge Base

**Mục tiêu:** Nâng cấp bộ quét tĩnh để xuất bằng chứng giàu ngữ cảnh; xây dựng kho tri thức bảo mật cục bộ; bắt đầu phát triển Agent trên Mock Data.

**Công việc của Quân:**

1. Cập nhật pipeline phân tích của plugin Python để điền đầy đủ vào `EvidenceBundle` (tọa độ dòng, code snippet, dataflow trace).
2. Cập nhật pipeline của plugin JavaScript, Java, PHP ở mức intra-file.
3. Sửa cơ chế truyền tham số `--rules` xuyên suốt từ CLI đến detector pipeline.
4. Cập nhật Mock Data khi schema thay đổi, đảm bảo Tuệ luôn có dữ liệu giả lập nhất quán.

**Công việc của Tuệ:**

1. Soạn thảo **Knowledge Cards** (định dạng YAML) cho 5 lớp lỗ hổng ưu tiên: SQL Injection (CWE-89), XSS (CWE-79), Command Injection (CWE-78), Path Traversal (CWE-22), SSRF (CWE-918).
2. Định nghĩa Sanitizer rubrics cho từng ngôn ngữ và các mẫu False Positive phổ biến (ví dụ: biến đã ép kiểu int trong SQLi, URL cố định trong SSRF).
3. Lập trình module `KnowledgeLoader` để tự động chọn và nạp thẻ tri thức phù hợp dựa trên ngôn ngữ và CWE.
4. **Bắt đầu phát triển prototype LangGraph** trên Mock Data của Quân — chạy giả lập luồng Planner → Auditor → Judge mà chưa cần Core thật.

**KPI Phase 2:**

- Bộ quét tĩnh Python xuất được kết quả có đầy đủ `EvidenceBundle`.
- Knowledge Cards cho 5 CWE được commit vào repo.
- Module `KnowledgeLoader` hoạt động và có unit test.
- Prototype LangGraph chạy được trên Mock Data (ít nhất 10 finding giả lập).

---

### Phase 3. Tuần 6–8: Triển khai đồ thị đa tác nhân LangGraph

**Mục tiêu:** Xây dựng hệ thống Agentic Loop hoàn chỉnh với cơ chế phản biện và Conditional Routing. Tích hợp với bộ quét tĩnh thật.

**Công việc của Quân:**

1. Lập trình lớp Adapter chuyển đổi đầu ra của bộ quét tĩnh thành đầu vào cho đồ thị LangGraph (`ScanResultToGraphAdapter`).
2. Viết module hỗ trợ Agent truy vấn nhanh mã nguồn (file reading skill) để AI có thể đọc thêm ngữ cảnh xung quanh finding.
3. Cập nhật module báo cáo (`reporting/`) để xuất kết quả cuối cùng có nhãn Triage, Confidence, và CVSS từ Agent.

**Công việc của Tuệ:**

1. Triển khai đồ thị trạng thái LangGraph với 4 tác nhân: **Planner** (phân tích sơ bộ), **Auditor** (kiểm tra bằng chứng), **SkepticValidator** (tìm sanitizer và phản bác), **Judge** (phân xử cuối cùng).
2. Thiết lập **Conditional Routing** theo nguyên tắc:
   - Finding có `confidence = high` từ Deterministic Core → đi thẳng từ Auditor sang Judge, bỏ qua SkepticValidator.
   - Finding có `confidence = medium` hoặc `low` → bắt buộc qua SkepticValidator trước khi đến Judge.
   - Lợi ích: tiết kiệm token API và giảm thời gian xử lý cho các finding rõ ràng.
3. Thiết lập ép kiểu đầu ra bằng Pydantic Structured Outputs cho mọi node Agent.
4. Viết integration test cho toàn bộ luồng: Quét tĩnh → Chuẩn hóa → AI Triage → Xuất báo cáo.

**KPI Phase 3:**

- Luồng lai ghép chạy thành công end-to-end trên ít nhất 3 dự án mẫu.
- Conditional Routing hoạt động đúng: finding High bỏ qua SkepticValidator.
- Alpha Demo: trình diễn được luồng hoàn chỉnh từ CLI.

---

### Phase 4. Tuần 9–10: Thực nghiệm, Ablation Study và Đánh giá đối chứng

**Mục tiêu:** Thu thập số liệu khoa học chứng minh đóng góp của đề tài. Thực hiện Nghiên cứu phân rã (Ablation Study) có hệ thống.

#### 4.1. Bộ dữ liệu Ground Truth

| Bộ dữ liệu | Mô tả | Phạm vi |
|-------------|--------|---------|
| **Juliet Test Suite** | Bộ mẫu chuẩn của NIST, có nhãn TP/FP rõ ràng | Java CWE-89 (SQLi), CWE-79 (XSS) |
| **Synthetic Dataset tự tạo** | 50–100 mẫu Python có gắn nhãn True/False, bao phủ 5 CWE ưu tiên | Python: CWE-89, CWE-79, CWE-78, CWE-22, CWE-918 |
| **OWASP Benchmark** | Bộ benchmark chuẩn công nghiệp (nếu đủ thời gian) | Java — phạm vi mở rộng |

#### 4.2. Nghiên cứu phân rã (Ablation Study) — 3 kịch bản

| Ký hiệu | Kịch bản so sánh | Giả thuyết cần kiểm chứng |
|----------|-------------------|---------------------------|
| **E1** | Static-only (Core thuần) vs. Static + AI Triage | AI Triage giảm FP mà không làm mất TP đáng kể. |
| **E2** | AI Triage không có Knowledge Base vs. AI Triage có Knowledge Base | Knowledge Cards cung cấp ngữ cảnh giúp Agent triage chính xác hơn. |
| **E3** | Single-prompt (1 lần gọi LLM) vs. LangGraph Multi-Agent (4 node) | Cấu trúc phản biện đa tác nhân cho Precision cao hơn prompt đơn. |

#### 4.3. Các chỉ số đo lường

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1-Score** = 2 x Precision x Recall / (Precision + Recall)
- **FP Reduction Rate** = (FP_before - FP_after) / FP_before x 100%
- **Token Usage**: tổng số token tiêu thụ trên mỗi kịch bản
- **Runtime**: thời gian quét trung bình trên mỗi dự án

**Công việc của Quân:**

1. Xây dựng script benchmark tự động (`benchmark_suite/evaluator.py`) có khả năng chạy batch và xuất CSV.
2. Chuẩn bị Juliet Test Suite (CWE-89, CWE-79) và bộ Synthetic Dataset Python.
3. Chạy Semgrep trên cùng tập mẫu, thu thập TP/FP/FN làm baseline đối chứng.

**Công việc của Tuệ:**

1. Chạy kịch bản **E1**: Aegis-SAST Core thuần vs. Aegis-SAST Hybrid.
2. Chạy kịch bản **E2**: AI Triage không Knowledge vs. có Knowledge.
3. Chạy kịch bản **E3**: Single-prompt vs. LangGraph Multi-Agent.
4. Tổng hợp số liệu, vẽ biểu đồ so sánh Precision, Recall, F1-Score, và Token Usage.

**KPI Phase 4:**

- Bảng số liệu thực nghiệm hoàn chỉnh cho cả 3 kịch bản Ablation.
- Biểu đồ trực quan (bar chart hoặc grouped bar chart) cho báo cáo.
- Kết quả đối chứng Semgrep trên Juliet Test Suite.

---

### Phase 5. Tuần 11–12: Tích hợp SARIF, Viết báo cáo và Chuẩn bị bảo vệ

**Mục tiêu:** Đóng gói sản phẩm chuẩn công nghiệp, hoàn thiện hồ sơ khoa học, và chuẩn bị bảo vệ trước hội đồng.

**Công việc của Quân:**

1. Triển khai module `sarif_formatter.py` chuyển đổi kết quả triage sang SARIF v2.1.0.
2. Thử nghiệm đẩy SARIF lên GitHub Code Scanning để minh họa tích hợp CI/CD.
3. Viết báo cáo: Chương 3 (Core Engine & Detection Pipeline) và Chương 5 (Thực nghiệm đối chứng).
4. Rà soát lỗi kỹ thuật, đóng gói mã nguồn sạch sẽ với README và hướng dẫn cài đặt.

**Công việc của Tuệ:**

1. Viết báo cáo: Chương 3 (LangGraph Agent Workflow) và Chương 4 (Knowledge Base & Ablation Study).
2. Tổng hợp, rà soát toàn văn báo cáo trước khi gửi giảng viên hướng dẫn.
3. Chuẩn bị bộ slide thuyết trình, poster tóm tắt, và kịch bản demo chi tiết.
4. Viết demo script tự động: chạy scan → triage → xuất báo cáo trong 1 lệnh.

**KPI Phase 5:**

- Toàn văn báo cáo khóa luận đạt chuẩn học thuật, đã review bởi GVHD.
- Module SARIF hoạt động và tương thích GitHub Code Scanning.
- Slide + poster + demo script sẵn sàng cho buổi bảo vệ.
- Mã nguồn đóng gói trên GitHub với tag release chính thức.

---

## 4. Ma trận tiến độ chi tiết từng tuần

| Tuần | Phase | Công việc của Quân | Công việc của Tuệ | KPI tuần |
|------|-------|--------------------|--------------------|----------|
| 1 | P1 | Rà soát detector, rule flow, call graph hiện tại. | Phân tích cơ chế Gemini cũ, xác định khoảng trống. | Báo cáo hiện trạng dự án hoàn thành. |
| 2 | P1 | Thiết kế schema `NormalizedFinding` + `EvidenceBundle`. Tạo bộ Mock JSON Data (20–30 finding). | Thiết kế đồ thị LangGraph v1. Định nghĩa trạng thái Triage. | Schema v1 commit. Mock Data giao cho Tuệ. |
| 3 | P2 | Cập nhật `core/models.py` theo schema mới. Bắt đầu nâng cấp plugin Python. | Soạn Knowledge Cards cho CWE-89 và CWE-79. Bắt đầu prototype LangGraph trên Mock Data. | Cấu trúc models mới trong repo. |
| 4 | P2 | Hoàn thành plugin Python với EvidenceBundle. | Soạn Knowledge Cards cho CWE-78, CWE-22, CWE-918. Lập trình `KnowledgeLoader`. | Plugin Python xuất evidence. KnowledgeLoader có unit test. |
| 5 | P2 | Cập nhật plugin JS, Java, PHP. Fix truyền `--rules`. | Hoàn thiện Sanitizer rubrics. Prototype LangGraph chạy trên Mock Data. | Bộ quét đa ngôn ngữ hoạt động ổn định. |
| 6 | P3 | Triển khai Adapter: kết quả quét → đầu vào Graph. | Triển khai LangGraph StateGraph: Planner + Auditor nodes. | Adapter hoạt động. 2 node đầu chạy được. |
| 7 | P3 | Module hỗ trợ Agent đọc file nguồn. Cập nhật reporting. | Cài đặt SkepticValidator + Judge. Thiết lập Conditional Routing. | Đồ thị 4 node chạy thông suốt. |
| 8 | P3 | Integration test cho luồng end-to-end. | Pydantic Structured Outputs. Alpha Demo trên 3 dự án mẫu. | Alpha Demo thành công. |
| 9 | P4 | Viết script benchmark. Chuẩn bị Juliet + Synthetic Dataset. | Chạy Ablation E1 (Static-only vs. Static+AI). | Script benchmark chạy batch tự động. |
| 10 | P4 | Chạy Semgrep đối chứng trên Juliet. Thu thập baseline. | Chạy Ablation E2 (Knowledge) và E3 (Multi-Agent). Tổng hợp biểu đồ. | Bảng số liệu + biểu đồ hoàn chỉnh. |
| 11 | P5 | Triển khai SARIF formatter. Thử tích hợp GitHub Actions. | Viết báo cáo Chương 3 (Agent) + Chương 4 (Knowledge & Ablation). | Module SARIF hoạt động. Bản thảo báo cáo sơ bộ. |
| 12 | P5 | Đóng gói mã nguồn. Viết Chương 3 (Core) + Chương 5 (Thực nghiệm). | Tổng hợp báo cáo. Slide + poster + demo script. | Toàn bộ deliverable sẵn sàng bảo vệ. |

---

## 5. Quản lý rủi ro kỹ thuật và Phương án dự phòng

| # | Rủi ro | Mức ảnh hưởng | Phương án dự phòng |
|---|--------|---------------|---------------------|
| R1 | **API LLM không ổn định hoặc trễ mạng** | Số liệu benchmark không đồng nhất, thực nghiệm bị gián đoạn. | Cache kết quả cục bộ bằng `diskcache`; cơ chế retry tự động bằng `tenacity`; ghi log mọi lần gọi API. |
| R2 | **Dàn trải quá nhiều ngôn ngữ** | Không đạt chiều sâu phân tích cần thiết cho nghiên cứu. | Cross-file chỉ áp dụng cho Python; JS, Java, PHP chỉ intra-file để minh họa tính đa ngôn ngữ. |
| R3 | **Đồ thị LangGraph quá phức tạp** | Khó debug, tốn token, tăng thời gian quét. | Giữ tối đa 4 node lõi (Planner, Auditor, SkepticValidator, Judge); áp dụng Conditional Routing để bỏ qua node không cần thiết. |
| R4 | **Semgrep cho kết quả quá mạnh** | Khó làm nổi bật ưu thế của Aegis-SAST. | Tập trung so sánh ở chỉ số Precision và FP Reduction Rate — điểm mạnh của lớp AI Triage mà Semgrep không có. |
| R5 | **Chi phí token API cao khi chạy 4 node cho hàng trăm finding** | Vượt ngân sách API, không đủ quota chạy thực nghiệm. | (a) Batch grouping: gom 3–5 finding cùng CWE vào 1 prompt. (b) Conditional Routing: finding High bỏ qua SkepticValidator, giảm 25% số lượt gọi. (c) Caching: không gọi lại finding đã triage. (d) Ước tính budget trước khi chạy batch lớn. |
| R6 | **Bottleneck tiến độ giữa Core và Agent** | Tuệ phải chờ Quân xong Core mới có dữ liệu để phát triển Agent. | Mock Data Strategy (xem Mục 8): Quân giao Mock JSON từ tuần 2, Tuệ phát triển Agent song song trên dữ liệu giả lập. |

---

## 6. Chiến lược giảm nghẽn tiến độ (Bottleneck Mitigation)

### 6.1. Vấn đề

Trong mô hình phân công truyền thống, nhánh AI Agent (Tuệ) phụ thuộc vào đầu ra thực tế của nhánh Core Engine (Quân). Nếu Core chưa sẵn sàng, Tuệ sẽ bị nghẽn từ tuần 3 đến tuần 5 — lãng phí gần 25% thời gian dự án.

### 6.2. Giải pháp: Mock Data Strategy

1. **Tuần 2:** Quân tạo bộ Mock JSON Data gồm 20–30 finding giả lập đúng schema `NormalizedFinding`, bao phủ:
   - 10 finding True Positive (có dataflow path rõ ràng)
   - 10 finding False Positive (có sanitizer hoặc dead code)
   - 5–10 finding biên (confidence medium, cần phản biện)

2. **Tuần 3–5:** Tuệ sử dụng Mock Data để:
   - Phát triển và test prototype LangGraph
   - Tinh chỉnh prompt cho từng node Agent
   - Kiểm tra Conditional Routing logic
   - Viết unit test cho `KnowledgeLoader`

3. **Tuần 6:** Khi Quân hoàn thành Adapter, Tuệ chuyển sang dữ liệu thực từ Core Engine. Việc chuyển đổi suôn sẻ vì Mock Data và dữ liệu thực cùng schema.

### 6.3. Lợi ích

- Hai nhánh công việc phát triển hoàn toàn song song từ tuần 2.
- Tuệ phát hiện lỗi thiết kế Agent sớm hơn 3 tuần.
- Giảm rủi ro tích hợp ở Phase 3 vì schema đã được kiểm chứng trước.

---

## 7. Cơ chế Conditional Routing cho Agent

### 7.1. Nguyên lý

Không phải mọi finding đều cần đi qua toàn bộ 4 node Agent. Việc cho finding rõ ràng đi qua SkepticValidator là lãng phí token và thời gian.

### 7.2. Quy tắc định tuyến

| Confidence từ Core | Luồng xử lý | Lý do |
|---------------------|--------------|-------|
| **High** (score >= 0.8) | Planner → Auditor → **Judge** (bỏ qua SkepticValidator) | Bằng chứng deterministic đã đủ mạnh, không cần phản biện thêm. |
| **Medium** (0.4 <= score < 0.8) | Planner → Auditor → **SkepticValidator** → Judge | Cần kiểm tra sanitizer và ngữ cảnh bổ sung. |
| **Low** (score < 0.4) | Planner → Auditor → **SkepticValidator** → Judge | Khả năng False Positive cao, cần phản biện kỹ. |

### 7.3. Tác động ước tính

- Giảm khoảng 25–30% số lượt gọi LLM nếu tỷ lệ finding High chiếm 30% trở lên.
- Giảm thời gian triage trung bình từ 4 lượt gọi xuống còn 3 lượt cho finding High.
- Dữ liệu token usage sẽ được ghi nhận trong Ablation Study E3 để so sánh.

---

## 8. Bộ dữ liệu Ground Truth cho thực nghiệm

### 8.1. Juliet Test Suite (NIST)

- **Nguồn:** Software Assurance Reference Dataset, NIST.
- **Phạm vi sử dụng:** Java CWE-89 (SQL Injection) và CWE-79 (XSS).
- **Đặc điểm:** Mỗi test case có phiên bản "good" (đã vá) và "bad" (có lỗi), cho phép tính chính xác TP và FP.

### 8.2. Synthetic Dataset tự tạo

- **Quy mô:** 50–100 mẫu Python.
- **Phạm vi:** 5 CWE ưu tiên (CWE-89, CWE-79, CWE-78, CWE-22, CWE-918).
- **Nhãn:** Mỗi mẫu được gắn nhãn True Positive hoặc False Positive bằng tay (manual labeling).
- **Mục đích:** Đánh giá Aegis-SAST trên ngôn ngữ phân tích sâu nhất (Python) với ground truth do nhóm kiểm soát.

### 8.3. OWASP Benchmark (mở rộng)

- **Điều kiện:** Chỉ sử dụng nếu hoàn thành Phase 4 trước tuần 10.
- **Phạm vi:** Java — bổ sung thêm chiều sâu đánh giá nếu thời gian cho phép.

---

## 9. Cân nhắc đạo đức nghiên cứu (Ethical Considerations)

1. **Chỉ phân tích tĩnh:** Aegis-SAST chỉ quét và phân tích mã nguồn ở dạng tĩnh (Static Analysis). Hệ thống không thực thi mã, không khai thác lỗ hổng (exploit), và không tấn công bất kỳ hệ thống thực nào.

2. **Dữ liệu thực nghiệm:** Toàn bộ mã nguồn sử dụng trong thực nghiệm là mẫu công khai (Juliet Test Suite, OWASP Benchmark) hoặc do nhóm tự tạo. Không sử dụng mã nguồn bí mật hoặc dữ liệu cá nhân.

3. **Mô hình AI:** Dữ liệu gửi đến Gemini API chỉ bao gồm đoạn mã nguồn mẫu và mô tả kỹ thuật, không chứa thông tin nhạy cảm. Kết quả từ AI được sử dụng như gợi ý tham khảo, quyết định cuối cùng thuộc về hệ thống triage có kiểm soát.

4. **Mục đích:** Công cụ được phát triển nhằm hỗ trợ lập trình viên phát hiện lỗi bảo mật sớm trong quá trình phát triển phần mềm, đóng góp vào việc nâng cao chất lượng và an toàn mã nguồn.

---

## 10. Tài liệu tham chiếu nội bộ

| Tài liệu | Đường dẫn |
|-----------|-----------|
| Tổng hợp hiện trạng | `docs/thesis/00-tong-hop-da-lam.md` |
| Kiến trúc mục tiêu | `docs/thesis/04-kien-truc-muc-tieu.md` |
| Kế hoạch benchmark | `docs/thesis/07-ke-hoach-benchmark.md` |
| Đề cương nghiên cứu | `docs/thesis/14-de-cuong-nghien-cuu-de-tai.md` |
| Đề cương báo cáo (bản GV) | `docs/thesis/16-de-cuong-bao-cao-de-tai-ban-giang-vien.md` |

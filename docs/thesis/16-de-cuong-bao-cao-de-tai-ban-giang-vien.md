# ĐỀ CƯƠNG BÁO CÁO ĐỀ TÀI

## TÊN ĐỀ TÀI

**Phát hiện và phân loại lỗ hổng bảo mật trong mã nguồn bằng phân tích tĩnh kết hợp đồ thị đa tác nhân AI**

**Tên tiếng Anh:**
**Detecting and Classifying Security Vulnerabilities in Source Code Using Static Analysis Combined with Multi-Agent AI Graphs**

---

# PHẦN MỘT: MỞ ĐẦU

## 1. Lý do chọn đề tài

Phát hiện lỗ hổng bảo mật ngay trong giai đoạn viết mã là yêu cầu quan trọng trong quy trình phát triển phần mềm an toàn. SAST (Static Application Security Testing) có lợi thế lớn vì có thể rà quét trực tiếp mã nguồn mà không cần triển khai hoặc chạy hệ thống.

Tuy nhiên, các công cụ SAST truyền thống vẫn gặp ba vấn đề chính:

- tỷ lệ cảnh báo giả (false positive) còn cao, khiến developer mất thời gian và dần mất niềm tin vào kết quả quét;
- thiếu khả năng giải thích tại sao một finding thực sự nguy hiểm;
- thiếu khả năng gợi ý cách sửa lỗi gắn với ngữ cảnh cụ thể.

Trong khi đó, các mô hình ngôn ngữ lớn (LLM) có khả năng đọc hiểu mã nguồn và sinh gợi ý khắc phục. Tuy nhiên, nếu dùng LLM độc lập để quét mã nguồn thì thiếu bằng chứng kỹ thuật deterministic, dễ hallucination, khó ổn định trên dự án nhiều tệp, chi phí token cao và khó benchmark.

Vì vậy, hướng tiếp cận phù hợp hơn là **kết hợp phân tích tĩnh với AI**:

1. Dùng phân tích tĩnh để quét mã nguồn, sinh finding kèm bằng chứng kỹ thuật.
2. Dùng AI triage theo mô hình đa tác nhân để đánh giá, phản biện, giải thích và phân loại finding.
3. Dùng benchmark đối chứng để đo lường hiệu quả.

Đề tài này phát triển hệ thống Aegis-SAST theo hướng đó. Trọng tâm không phải là thay scanner bằng AI, mà là xây dựng một hệ thống kết hợp có bằng chứng, có workflow agent rõ ràng và có đánh giá định lượng.

## 2. Cơ sở hình thành đề tài

Đề tài được hình thành trên nền project Aegis-SAST mà nhóm đã xây dựng trước đó. Đây không phải là đề tài bắt đầu từ con số 0, mà là bước phát triển tiếp theo của một scanner đã có nền tảng kỹ thuật tương đối rõ.

Ở thời điểm lập đề cương, Aegis-SAST đã có các thành phần nền tảng sau:

**Bảng 1. Nền tảng kỹ thuật hiện có**

| Thành phần | Hiện trạng | Ý nghĩa |
|---|---|---|
| CLI scanner | Đã có | Điểm vào thống nhất cho pipeline |
| Plugin đa ngôn ngữ | Python, JavaScript, Java, PHP | Nền cho kiến trúc đa ngôn ngữ |
| AST parsing | Tree-sitter | Phân tích cấu trúc cú pháp |
| Rule engine | YAML rules | Dễ mở rộng coverage |
| Detection core | Source → Sink đã hoạt động | Phù hợp nhóm lỗi injection |
| Python graph core | CFG/DFG, taint kill, dead-path pruning, function summary | Đóng góp kỹ thuật mạnh nhất |
| Cross-file analysis | Có cho Python | Call graph xuyên tệp |
| Workflow triage seed | Repo intake, knowledge-assisted triage, auditor/skeptic/judge seed | Nền cho workflow agent |
| Reporting | JSON, Markdown, SARIF | Đầu ra cho benchmark |
| Mini benchmark | Synthetic ablation cho Python graph | Nền cho thực nghiệm |

Tuy nhiên, dự án hiện tại còn hai khoảng trống lớn:

### 2.1. Sự lệch pha giữa các ngôn ngữ

Python hiện là ngôn ngữ duy nhất được phát triển theo chiều sâu (cross-file, CFG/DFG, graph reasoning, evidence slicing). JavaScript, Java và PHP mới dừng ở mức intra-file, pattern-level. Điều này khiến hệ thống trông như "chỉ có Python", làm giảm giá trị đa ngôn ngữ khi bảo vệ trước hội đồng.

### 2.2. Lớp AI chưa hoàn thiện

LangGraph chưa tích hợp hoàn chỉnh, multi-agent workflow chưa chạy end-to-end, AI chưa phải lớp triage hoàn chỉnh có thể benchmark đầy đủ.

### 2.3. Hướng giải quyết: Capability Parity

Thay vì tiếp tục mô hình "Python sâu, còn lại demo", đề tài chuyển sang hướng **capability parity** — 4 ngôn ngữ cùng đi qua một pipeline năng lực chung:

AST → Evidence Extraction → DFG-lite → CFG-lite → NormalizedFinding + EvidenceBundle → Knowledge Loading → Agent Triage → Benchmark

"Parity" ở đây có nghĩa là: cùng chuẩn đầu ra, cùng workflow agent, cùng cách benchmark. Không nhất thiết nội bộ từng ngôn ngữ phải triển khai giống hệt nhau. Python vẫn có thể có cross-file và call graph mạnh hơn, nhưng JavaScript, Java, PHP phải đạt được mức evidence đủ tốt để agent triage có dữ liệu thật để làm việc.

## 3. Mục tiêu của đề tài

### 3.1. Mục tiêu tổng quát

Phát triển Aegis-SAST thành hệ thống Hybrid SAST đa ngôn ngữ theo mô hình capability parity, kết hợp giữa:

- deterministic static analysis có bằng chứng kỹ thuật cho cả 4 ngôn ngữ;
- AI triage có điều phối theo workflow đa tác nhân;
- benchmark đối chứng đồng nhất trên tất cả ngôn ngữ.

### 3.2. Mục tiêu cụ thể

1. Chuẩn hóa NormalizedFinding và EvidenceBundle cho toàn bộ pipeline. Mọi finding từ bất kỳ ngôn ngữ nào đều có cùng format output.
2. Nâng cấp JavaScript, Java, PHP từ mức pattern-level lên mức evidence-aware: có taint analysis intra-file, có DFG-lite, có evidence extraction đủ tốt để agent triage hoạt động.
3. Duy trì và củng cố Python với cross-file, call graph, CFG/DFG, function summary, evidence slicing — đây là ngôn ngữ đã phát triển sâu nhất.
4. Xây dựng Knowledge Cards theo CWE/OWASP cho 5 nhóm lỗ hổng ưu tiên, với sanitizer rubric riêng cho từng ngôn ngữ.
5. Thiết kế và cài đặt workflow AI triage bằng LangGraph: Planner, KnowledgeLoader, Auditor, SkepticValidator, Judge, Reporter.
6. Hoàn thiện đầu ra JSON, Markdown, SARIF.
7. Benchmark đồng nhất trên cả 4 ngôn ngữ, so sánh với Semgrep.
8. Đánh giá bằng: Precision, Recall, F1-Score, FP Reduction Rate, Runtime, Token Usage.

**Bảng 2. Nhóm mục tiêu**

| Nhóm | Nội dung |
|---|---|
| Core scanner | Chuẩn hóa finding/evidence, nâng 4 ngôn ngữ lên capability parity |
| Đa ngôn ngữ | Python, JS, Java, PHP cùng chuẩn đầu ra, cùng workflow, cùng benchmark |
| AI triage | Workflow đa tác nhân bằng LangGraph |
| Knowledge | Tri thức cục bộ cho 5 CWE, sanitizer rubric theo từng ngôn ngữ |
| Benchmark | Benchmark đồng nhất 4 ngôn ngữ, đối chứng Semgrep |
| Reporting | JSON, Markdown, SARIF, CI/CD |

## 4. Câu hỏi nghiên cứu

**Bảng 3. Câu hỏi nghiên cứu**

| Mã | Câu hỏi |
|---|---|
| RQ1 | AI triage có giúp giảm false positive so với chỉ dùng static analysis hay không? |
| RQ2 | Knowledge Loading có giúp explanation và triage ổn định hơn hay không? |
| RQ3 | Mô hình capability parity có đảm bảo chất lượng triage đồng nhất giữa các ngôn ngữ hay không? |
| RQ4 | Workflow LangGraph đa tác nhân có ổn định hơn single-prompt verification hay không? |

Lưu ý: RQ3 là câu hỏi mới so với phiên bản trước, phản ánh trực tiếp hướng capability parity. Câu hỏi này kiểm tra xem khi 4 ngôn ngữ cùng đi qua một pipeline chung, chất lượng triage có thực sự đồng nhất hay vẫn lệch pha.

## 5. Phương pháp nghiên cứu

### 5.1. Nghiên cứu tài liệu

- Các kỹ thuật phân tích tĩnh dựa trên AST, DFG, CFG, Call Graph.
- Các công cụ SAST phổ biến: Semgrep (rule-based), CodeQL (query-based).
- Các hướng dùng LLM cho vulnerability triage, explanation và repair.
- Các mô hình agent có trạng thái cho xử lý mã nguồn.

### 5.2. Thiết kế và cài đặt

- Thiết kế pipeline năng lực chung (capability pipeline) cho 4 ngôn ngữ.
- Xây evidence extraction framework có thể tái sử dụng pattern giữa các ngôn ngữ.
- Triển khai DFG-lite và taint analysis cho JavaScript, Java, PHP.
- Xây LangGraph workflow và knowledge layer.
- Tổ chức reporting và benchmark harness đồng nhất.

### 5.3. Thực nghiệm và nghiên cứu phân rã (Ablation Study)

**Bảng 4. Các nhóm thực nghiệm chính**

| Ký hiệu | So sánh | Mục đích | Giả thuyết |
|---|---|---|---|
| E1 | Static-only vs Static + AI Triage | Đo tác động AI triage lên FP | AI triage giảm FP mà không mất TP đáng kể |
| E2 | AI không Knowledge vs có Knowledge | Đo tác động Knowledge Cards | Knowledge giúp agent triage chính xác hơn |
| E3 | Single-prompt vs LangGraph workflow | Đo tác động multi-agent | Đa tác nhân cho kết quả ổn định hơn |
| E4 | So sánh Precision/Recall giữa 4 ngôn ngữ | Đo mức parity thực tế | 4 ngôn ngữ đạt chất lượng triage tương đương |
| Baseline | Aegis-SAST vs Semgrep (trên 4 ngôn ngữ) | So sánh với công cụ rule-based | Xác định ưu/nhược của hướng hybrid |

## 6. Đối tượng và phạm vi nghiên cứu

### 6.1. Đối tượng nghiên cứu

- Các kỹ thuật static analysis phục vụ SAST.
- Evidence-aware finding schema.
- Workflow AI triage có điều phối đa tác nhân.
- Tri thức có cấu trúc về CWE, OWASP, source, sink, sanitizer.
- Benchmark đối chứng đa ngôn ngữ.

### 6.2. Phạm vi nghiên cứu — Capability Parity

**Bảng 5. Pipeline năng lực chung cho 4 ngôn ngữ**

| Bước pipeline | Python | JavaScript | Java | PHP |
|---|---|---|---|---|
| AST parsing (Tree-sitter) | Có | Có | Có | Có |
| Rule engine (YAML) | Có | Có | Có | Có |
| Taint analysis (source → sink) | Có (cross-file + call graph) | Có (intra-file) | Có (intra-file) | Có (intra-file) |
| DFG-lite | Có | Có (cần xây mới) | Có (cần xây mới) | Có (cần xây mới) |
| CFG-lite | Có | Có (cần xây mới) | Có (cần xây mới) | Có (cần xây mới) |
| Evidence extraction | Có (đầy đủ) | Có (cần nâng cấp) | Có (cần nâng cấp) | Có (cần nâng cấp) |
| NormalizedFinding output | Cùng schema | Cùng schema | Cùng schema | Cùng schema |
| EvidenceBundle output | Cùng format | Cùng format | Cùng format | Cùng format |
| Knowledge Loading | Có | Có | Có | Có |
| Agent Triage (LangGraph) | Cùng workflow | Cùng workflow | Cùng workflow | Cùng workflow |
| Benchmark | Có | Có | Có | Có |

Ghi chú quan trọng:

- "Parity" nghĩa là cùng chuẩn đầu ra, cùng workflow, cùng benchmark. Nội bộ từng ngôn ngữ có thể khác nhau về triển khai.
- Python vẫn mạnh nhất vì có cross-file và call graph. Các ngôn ngữ khác chưa cần cross-file nhưng phải có evidence đủ tốt cho agent triage.
- C++ không nằm trong phạm vi, được ghi nhận trong hướng phát triển.

Nhóm lỗ hổng ưu tiên: SQL Injection (CWE-89), Command Injection (CWE-78), Path Traversal (CWE-22), XSS (CWE-79), SSRF (CWE-918).

Baseline chính: Semgrep (chạy trên cả 4 ngôn ngữ). Baseline mở rộng: CodeQL nếu đủ thời gian.

### 6.3. Phạm vi không đặt mục tiêu

- Không đặt mục tiêu thay thế công cụ SAST thương mại.
- Không thêm ngôn ngữ mới ngoài 4 ngôn ngữ đã có plugin (C++, Go, Rust... để hướng phát triển).
- Không đặt mục tiêu auto-fix hoàn chỉnh cho mọi finding.
- Không mở rộng sớm sang dashboard doanh nghiệp.
- Không yêu cầu cross-file cho JavaScript, Java, PHP trong giai đoạn chính.

---

# PHẦN HAI: NỘI DUNG

## CHƯƠNG 1: TỔNG QUAN VỀ SAST VÀ HƯỚNG TIẾP CẬN KẾT HỢP

### 1.1. Bài toán phát hiện lỗ hổng bằng phân tích tĩnh

SAST cho phép rà quét mã nguồn mà không cần thực thi chương trình, phù hợp chiến lược shift-left security. Hiệu quả thực tế phụ thuộc vào: chất lượng bằng chứng, khả năng triage, khả năng giải thích và khả năng giảm false positive.

### 1.2. Cơ sở kỹ thuật: AST, DFG, CFG và Call Graph

- **AST:** cây cú pháp trừu tượng — tầng phân tích cơ bản nhất.
- **DFG:** đồ thị luồng dữ liệu — theo dõi giá trị từ source đến sink.
- **CFG:** đồ thị luồng điều khiển — xác định đường nào thực sự reachable.
- **Call Graph:** đồ thị gọi hàm — hỗ trợ reasoning xuyên hàm và xuyên tệp.

Đề tài triển khai DFG-lite và CFG-lite cho cả 4 ngôn ngữ. "Lite" nghĩa là không theo đuổi mức lý thuyết hoàn chỉnh mà tập trung vào giá trị thực nghiệm: đủ để sinh evidence có chất lượng cho agent triage.

### 1.3. LLM và giới hạn khi dùng trực tiếp cho SAST

LLM hỗ trợ giải thích finding và sinh gợi ý khắc phục, nhưng nếu không có bằng chứng deterministic đi kèm thì khó kiểm chứng, tốn token, thiếu ổn định và khó benchmark.

### 1.4. Hướng tiếp cận kết hợp

1. Dùng deterministic core để quét mã nguồn, sinh finding và evidence cho cả 4 ngôn ngữ.
2. Dùng knowledge layer để bổ sung tri thức có cấu trúc.
3. Dùng multi-agent workflow để triage, phản biện và giải thích.
4. Dùng benchmark đối chứng đồng nhất trên 4 ngôn ngữ.

## CHƯƠNG 2: CÁC CÔNG TRÌNH VÀ HỆ THỐNG LIÊN QUAN

### 2.1. Công cụ SAST tham khảo

- **Semgrep:** rule-based, nhanh, dễ viết rule. Hạn chế: không AI triage, finding thiếu explanation, FP phụ thuộc chất lượng rule. Hỗ trợ nhiều ngôn ngữ nhưng mỗi ngôn ngữ ở mức rule coverage khác nhau.
- **CodeQL:** query-based, dataflow analysis mạnh. Hạn chế: cần viết query phức tạp, setup nặng.

### 2.2. Hệ thống agent tham khảo

Đề tài đi theo workflow có trạng thái và có điều kiện rẽ nhánh, không phải agent đối thoại tự do.

### 2.3. Khoảng trống nghiên cứu

- Kết hợp evidence-aware SAST với AI triage có kiểm soát.
- Đảm bảo capability parity giữa các ngôn ngữ thay vì chỉ tập trung 1 ngôn ngữ.
- Có benchmark đối chứng đồng nhất trên nhiều ngôn ngữ.

## CHƯƠNG 3: KIẾN TRÚC HỆ THỐNG ĐỀ XUẤT

Hệ thống thiết kế theo 6 lớp, mọi ngôn ngữ đều đi qua cùng pipeline.

**Bảng 6. Kiến trúc 6 lớp**

| Lớp | Tên | Chức năng | Đầu ra |
|---|---|---|---|
| 1 | Repo Intake | Nhận mã nguồn, nhận diện ngôn ngữ/framework, chọn scan profile | Repo metadata |
| 2 | Deterministic Detection Core | AST parser, rule engine, taint engine, DFG-lite, CFG-lite — cho cả 4 ngôn ngữ | Raw findings |
| 3 | Finding Normalization | Chuẩn hóa finding về cùng schema, tạo Evidence Bundle — format đồng nhất bất kể ngôn ngữ | Normalized findings |
| 4 | Knowledge Loading | Nạp Knowledge Cards theo CWE + ngôn ngữ, sanitizer rubric riêng từng ngôn ngữ | Finding + knowledge |
| 5 | AI Triage | Multi-agent workflow: Planner, Auditor, SkepticValidator, Judge, Reporter — cùng workflow cho mọi ngôn ngữ | Triaged results |
| 6 | Reporting và Evaluation | JSON, Markdown, SARIF, benchmark harness đồng nhất 4 ngôn ngữ | Báo cáo, số liệu |

Điểm quan trọng: AI agent không thay phần quét tĩnh. Agent chỉ hoạt động sau khi finding đã có evidence. Mọi ngôn ngữ đều được xử lý bình đẳng bởi cùng một workflow agent.

### 3.1. Repo Intake Layer

Xác định ngôn ngữ, framework, scan profile. Nếu dự án có nhiều ngôn ngữ thì quét từng ngôn ngữ rồi gom kết quả.

### 3.2. Deterministic Detection Core — Capability Parity

Đây là lớp thay đổi lớn nhất so với phiên bản trước. Thay vì chỉ Python có analysis sâu, giờ cả 4 ngôn ngữ đều đi qua:

1. **AST parsing** bằng Tree-sitter (đã có cho cả 4).
2. **Rule engine** dựa trên YAML rules (đã có cho cả 4).
3. **Taint analysis** intra-file: theo dõi luồng dữ liệu từ source đến sink. Python có thêm cross-file qua call graph.
4. **DFG-lite:** đồ thị luồng dữ liệu đơn giản hóa — đủ để xác định data dependency giữa các biến. Cần xây mới cho JS/Java/PHP.
5. **CFG-lite:** đồ thị luồng điều khiển đơn giản hóa — đủ để xác định đường nào reachable. Cần xây mới cho JS/Java/PHP.
6. **Evidence extraction:** sinh EvidenceBundle đồng nhất cho mọi finding.

Chiến lược triển khai: xây evidence extraction framework chung, tái sử dụng pattern giữa các ngôn ngữ. Các ngôn ngữ cùng họ cú pháp (JS/Java/PHP đều C-style) có thể chia sẻ logic DFG-lite/CFG-lite ở mức nhất định.

### 3.3. Finding Normalization

Mọi finding từ bất kỳ ngôn ngữ nào đều được chuẩn hóa về cùng một schema:

**NormalizedFinding:** finding ID, ngôn ngữ, loại lỗ hổng, CWE/OWASP mapping, severity, triage status, evidence summary, metadata.

**EvidenceBundle:** source location, sink location, sanitizer (nếu có), dataflow path, code snippet, rule metadata, confidence score. Format giống nhau cho cả 4 ngôn ngữ.

### 3.4. Knowledge Loading Layer

Knowledge Cards chứa tri thức cục bộ theo CWE, với sanitizer rubric riêng cho từng ngôn ngữ:

- Ví dụ SQLi (CWE-89): Python dùng parameterized query (`cursor.execute(sql, params)`), Java dùng PreparedStatement, PHP dùng PDO prepared, JS dùng parameterized query trong mysql2/pg.
- False positive pattern theo ngôn ngữ: Python int cast, Java Integer.parseInt(), PHP intval(), JS parseInt().
- Remediation hint theo ngôn ngữ: mỗi ngôn ngữ có secure code template riêng.

### 3.5. AI Triage Layer

Workflow LangGraph với các node:

1. **Planner:** chọn luồng xử lý theo loại finding và ngôn ngữ.
2. **KnowledgeLoader:** nạp Knowledge Card phù hợp CWE + ngôn ngữ.
3. **Auditor:** đánh giá finding dựa trên evidence + knowledge.
4. **SkepticValidator:** phản biện finding — tìm sanitizer, dead code, lý do FP.
5. **Judge:** gán triage status: `confirmed`, `likely`, `needs-review`, `suppressed`.
6. **Reporter:** sinh explanation, remediation note, output record.

**Conditional routing:** finding confidence cao đi thẳng Auditor → Judge. Finding confidence trung bình/thấp đi qua SkepticValidator. Tiết kiệm token khi có nhiều finding.

Workflow này chạy giống nhau cho mọi ngôn ngữ — agent nhận NormalizedFinding + EvidenceBundle + Knowledge Card, không cần biết nội bộ ngôn ngữ nào đã sinh ra finding đó.

### 3.6. Reporting và Evaluation Layer

- JSON, Markdown, SARIF v2.1.0.
- Benchmark harness chạy batch trên cả 4 ngôn ngữ.
- Baseline comparison với Semgrep trên cùng dataset, cùng ngôn ngữ.

## CHƯƠNG 4: THIẾT KẾ VÀ XÂY DỰNG CÔNG CỤ THỰC NGHIỆM

### 4.1. Tổ chức module

- Module CLI và Repo Intake.
- Module Core Scanner (4 ngôn ngữ, capability parity).
- Module Finding Normalization và Evidence (schema đồng nhất).
- Module Knowledge Loading (cards theo CWE + ngôn ngữ).
- Module AI Triage Workflow (LangGraph, ngôn ngữ-agnostic).
- Module Reporting và Benchmark (harness đa ngôn ngữ).

### 4.2. Công nghệ sử dụng

**Bảng 7. Technology Stack**

| Thành phần | Công nghệ | Ghi chú |
|---|---|---|
| Ngôn ngữ phát triển | Python 3.12+ | |
| AST parsing | Tree-sitter | Parser cho Python, JS, Java, PHP |
| Điều phối workflow | LangGraph | StateGraph multi-agent |
| LLM | Gemini 2.0 Flash | Google AI API |
| Schema validation | Pydantic v2 | Structured output |
| Rule format | YAML | Rules cho 4 ngôn ngữ |
| CLI | click + Rich | |
| Reporting | SARIF v2.1.0 | Chuẩn OASIS |
| Cache | diskcache | Cache kết quả AI |
| Retry | tenacity | API retry logic |
| Testing | pytest | Unit + integration test |
| CI/CD | GitHub Actions | Code Scanning |

### 4.3. Đầu ra dự kiến

- Prototype Aegis-SAST quét được 4 ngôn ngữ ở cùng mức capability.
- Evidence extraction cho cả 4 ngôn ngữ, cùng output format.
- Workflow AI triage chạy end-to-end, ngôn ngữ-agnostic.
- Knowledge layer với sanitizer rubric riêng từng ngôn ngữ.
- Benchmark đồng nhất 4 ngôn ngữ, đối chứng Semgrep.

## CHƯƠNG 5: THỰC NGHIỆM VÀ ĐÁNH GIÁ

### 5.1. Thiết lập thực nghiệm

Mô tả rõ: phần cứng/phần mềm, phiên bản parser, mô hình LLM, cấu hình workflow, cách đo runtime và token usage.

### 5.2. Bộ dữ liệu thực nghiệm

**Bảng 8. Bộ dữ liệu cho benchmark**

| Bộ dữ liệu | Ngôn ngữ | Đặc điểm | Vai trò |
|---|---|---|---|
| Synthetic Dataset tự tạo | Python, JS, Java, PHP | 50-100 mẫu mỗi ngôn ngữ, gắn nhãn TP/FP, bao phủ 5 CWE | Ground truth chính cho benchmark parity |
| Juliet Test Suite (NIST) | Java | Nhãn good/bad rõ ràng | Ground truth chuẩn quốc tế |
| Dự án mẫu nội bộ | Python, JS, Java, PHP | Các project trong examples/ và test_projects/ | Kiểm thử chức năng và demo |
| OWASP Benchmark | Java | Benchmark chuẩn công nghiệp | Bổ sung nếu đủ thời gian |

Lưu ý: Synthetic Dataset giờ bao gồm mẫu cho cả 4 ngôn ngữ, không chỉ Python, để đo capability parity thực tế.

### 5.3. Chỉ số đánh giá

Định lượng:

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1-Score** = 2 x Precision x Recall / (Precision + Recall)
- **FP Reduction Rate** = (FP_before - FP_after) / FP_before x 100%
- **Runtime** — thời gian quét trung bình
- **Token Usage** — chi phí token cho AI triage
- **Parity Score** — so sánh Precision/Recall giữa 4 ngôn ngữ để đo mức đồng nhất

Định tính: explanation có dùng đúng evidence không, có nêu đúng source/sink/sanitizer không, có remediation phù hợp không.

### 5.4. Các kịch bản thực nghiệm

#### 5.4.1. E1: Static-only vs Static + AI Triage

Chạy trên cả 4 ngôn ngữ. Đo FP reduction cho từng ngôn ngữ.

#### 5.4.2. E2: AI không Knowledge vs có Knowledge

Đo tác động Knowledge Cards. So sánh trên cả 4 ngôn ngữ.

#### 5.4.3. E3: Single-prompt vs LangGraph workflow

Đo tác động multi-agent. So sánh consistency giữa các lần chạy.

#### 5.4.4. E4: Parity Test — So sánh Precision/Recall giữa 4 ngôn ngữ

Đây là kịch bản mới, đo trực tiếp: khi 4 ngôn ngữ cùng đi qua pipeline chung, kết quả triage có thực sự đồng nhất hay vẫn lệch pha? Nếu Python đạt Precision 85% nhưng PHP chỉ 60%, nghĩa là parity chưa đạt.

#### 5.4.5. So sánh với baseline Semgrep

Chạy trên cả 4 ngôn ngữ. Phân tích ưu/nhược cho từng ngôn ngữ.

---

# PHẦN BA: KẾT QUẢ KỲ VỌNG, ĐÓNG GÓP VÀ HƯỚNG PHÁT TRIỂN

## 1. Kết quả kỳ vọng

- Prototype quét được 4 ngôn ngữ ở cùng mức capability, không còn "chỉ có Python".
- Workflow LangGraph chạy end-to-end, ngôn ngữ-agnostic.
- Knowledge layer có sanitizer rubric riêng từng ngôn ngữ.
- Benchmark đồng nhất 4 ngôn ngữ, có số liệu parity thực tế.
- Bộ số liệu đủ để bảo vệ trước hội đồng.

## 2. Đóng góp kỹ thuật

- Thiết kế pipeline capability parity cho SAST đa ngôn ngữ — cùng chuẩn đầu ra, cùng workflow, cùng benchmark.
- Evidence extraction framework có thể tái sử dụng giữa các ngôn ngữ.
- Multi-agent workflow ngôn ngữ-agnostic cho AI triage.
- Knowledge Cards với sanitizer rubric riêng từng ngôn ngữ.

## 3. Đóng góp nghiên cứu

- Đo tác động AI triage lên false positive (RQ1).
- Đo tác động Knowledge Loading (RQ2).
- Đo mức capability parity thực tế giữa 4 ngôn ngữ (RQ3).
- Đo sự khác biệt LangGraph workflow vs single-prompt (RQ4).

## 4. Hướng phát triển

- Thêm C++, Go, Rust vào pipeline capability parity.
- Mở rộng cross-file reasoning sang JavaScript và Java.
- Nghiên cứu Local LLM, RAG, fine-tuning/LoRA cho triage.
- Nghiên cứu auto-remediation có kiểm soát.
- Dashboard trực quan cho môi trường doanh nghiệp.

## 5. Rủi ro và hướng giảm thiểu

**Bảng 9. Rủi ro**

| Rủi ro | Ảnh hưởng | Hướng giảm thiểu |
|---|---|---|
| Nâng 3 ngôn ngữ lên parity tốn nhiều thời gian | Trễ tiến độ, ảnh hưởng benchmark | Xây evidence extraction framework chung, tái sử dụng pattern giữa JS/Java/PHP (cùng C-style syntax) |
| Parity không đồng đều | Một ngôn ngữ đạt Precision thấp hơn hẳn | Ghi nhận rõ trong kết quả, phân tích nguyên nhân — đây cũng là finding nghiên cứu có giá trị |
| AI chưa ổn định | Kết quả triage không nhất quán | Pydantic structured output, rubric rõ, conditional routing, log đầy đủ |
| Dataset thiếu ground truth đa ngôn ngữ | Không đo được parity chính xác | Synthetic dataset cho cả 4 ngôn ngữ, gắn nhãn bởi 2 thành viên |
| Chi phí token cao | Vượt ngân sách API | Batch grouping, conditional routing, caching bằng diskcache |
| Semgrep mạnh hơn ở ngôn ngữ nào đó | Khó nổi bật ưu thế | So sánh ở Precision và FP Reduction — thế mạnh AI triage |
| Phạm vi quá rộng | Không đủ sâu | Không thêm ngôn ngữ mới, không cross-file cho JS/Java/PHP |

## 6. Giới hạn đạo đức

Hệ thống chỉ phân tích tĩnh mã nguồn được cung cấp. Không thực thi mã, không khai thác lỗ hổng, không tấn công hệ thống thật, không thu thập dữ liệu cá nhân.

## 7. Tài liệu tham khảo

1. OWASP Foundation. *OWASP Top 10 Application Security Risks*.
2. MITRE. *Common Weakness Enumeration (CWE)*.
3. OASIS. *Static Analysis Results Interchange Format (SARIF) v2.1.0*.
4. LangGraph Documentation. https://langchain-ai.github.io/langgraph/
5. NIST. *Juliet Test Suite for C/C++ and Java*.
6. OWASP Benchmark Project.
7. Semgrep Documentation. https://semgrep.dev/
8. CodeQL Documentation. https://codeql.github.com/
9. Google. *Gemini API Documentation*. https://ai.google.dev/
10. Các nghiên cứu về LLM-based vulnerability triage và automated repair.

## 8. Kết luận

Đề tài này dựa trên scanner Aegis-SAST có nền tảng kỹ thuật thật, và nâng cấp theo hướng capability parity — 4 ngôn ngữ cùng đi qua một pipeline năng lực chung, cùng chuẩn đầu ra, cùng workflow agent, cùng benchmark. Kết hợp với AI triage có điều phối đa tác nhân và benchmark đối chứng, đề tài hướng đến một prototype Hybrid SAST có giá trị học thuật đủ mạnh cho báo cáo NCKH và khóa luận tốt nghiệp.

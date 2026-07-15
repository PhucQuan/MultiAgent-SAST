# ĐỀ CƯƠNG BÁO CÁO ĐỀ TÀI NGHIÊN CỨU KHOA HỌC

## TÊN ĐỀ TÀI ĐỀ XUẤT

**Nghiên cứu và phát triển hệ thống Agentic Hybrid SAST đa ngôn ngữ sử dụng phân tích tĩnh, Knowledge Loading và AI Triage để phát hiện, phân loại và giải thích lỗ hổng mã nguồn**

*Tên tiếng Anh đề xuất:* **Aegis-SAST: An Evidence-Aware Multi-Language Hybrid SAST Platform with Multi-Agent AI Triage and Knowledge Loading**

---

# PHẦN MỘT: MỞ ĐẦU

## 1. Lý do chọn đề tài

Phát hiện sớm lỗ hổng bảo mật trong giai đoạn phát triển phần mềm đóng vai trò quan trọng trong việc xây dựng hệ thống an toàn và tối ưu hóa chi phí khắc phục. Kiểm thử an ninh ứng dụng tĩnh (SAST — Static Application Security Testing) là một giải pháp thiết yếu hỗ trợ rà quét mã nguồn trực tiếp mà không cần triển khai hệ thống. Tuy nhiên, các công cụ SAST truyền thống (như các bộ rà quét dựa trên luật cứng hoặc phân tích luồng dữ liệu) gặp phải ba hạn chế lớn:

- Số lượng cảnh báo giả (**False Positives**) còn cao, khiến nhà phát triển mất thời gian xử lý và dần mất niềm tin vào kết quả quét.
- Thiếu khả năng giải thích vì sao một cảnh báo thực sự nguy hiểm, dẫn đến khó phân loại mức ưu tiên xử lý.
- Thiếu khả năng đưa ra gợi ý khắc phục (**Remediation**) gắn với ngữ cảnh cụ thể của đoạn mã.

Trong những năm gần đây, sự trỗi dậy của Mô hình Ngôn ngữ Lớn (LLM) mở ra tiềm năng lớn trong việc đọc hiểu và phân tích mã nguồn. Dù vậy, việc áp dụng LLM trực tiếp rà quét mã nguồn (LLM-only approach) thường dẫn đến hiện tượng "ảo tưởng" (Hallucination), mất dấu ngữ cảnh khi kích thước dự án tăng, thiếu đi các bằng chứng phân tích cú pháp mang tính xác thực (deterministic), đồng thời tiêu hao lượng token rất lớn.

Từ thực tế đó, hướng tiếp cận lai ghép (**Hybrid SAST**) giữa Phân tích tĩnh và Trí tuệ nhân tạo là giải pháp tối ưu. Đề tài này tập trung nghiên cứu phát triển hệ thống Aegis-SAST từ một bộ quét dựa trên AST thành hệ thống **Agentic Hybrid SAST** toàn diện:

- Dùng phân tích tĩnh để sinh finding và bằng chứng kỹ thuật.
- Dùng Knowledge Loading để nạp tri thức lỗ hổng có cấu trúc.
- Dùng AI Triage để phân loại, phản biện và giải thích finding.
- Dùng Agent Orchestration để điều phối toàn bộ workflow theo các bước rõ ràng.
- Dùng Benchmark để đo và chứng minh giá trị của hệ thống.

Đây chính là lý do đề tài tập trung vào mô hình Agentic Hybrid SAST thay vì chỉ mở rộng scanner theo cách thông thường.

## 2. Cơ sở hình thành đề tài

Đề tài này được hình thành trên nền project Aegis-SAST mà nhóm đã xây dựng trước đó. Đây không phải là một ý tưởng bắt đầu từ con số 0, mà là bước phát triển tiếp theo của một hệ thống quét mã nguồn đã có các thành phần nền tảng tương đối rõ ràng. Việc kế thừa trực tiếp từ project đang tồn tại giúp đề tài có hai lợi thế quan trọng:

- Thứ nhất, nhóm không mất thời gian làm lại toàn bộ scanner cơ bản.
- Thứ hai, đề tài có cơ sở kỹ thuật thật để mở rộng sang hướng nghiên cứu sâu hơn, đặc biệt ở các lớp Triage, Agent Orchestration, Knowledge Loading và Benchmark.

Hiện tại, Aegis-SAST đã có những thành phần chính được liệt kê trong Bảng 1 dưới đây.

**Bảng 1. Nền tảng kỹ thuật hiện có của Aegis-SAST**

| Thành phần | Hiện trạng | Ý nghĩa đối với đề tài |
|---|---|---|
| CLI Scanner | Đã có | Có điểm vào thống nhất cho toàn bộ pipeline |
| Plugin đa ngôn ngữ | Python, JavaScript, Java, PHP | Tạo nền cho định hướng multi-language |
| Rule Engine | YAML rules | Thuận lợi cho mở rộng rule và coverage |
| AST Parsing | Tree-sitter | Hỗ trợ phân tích theo cấu trúc mã nguồn |
| Taint Analysis | Đã có | Phù hợp với nhóm lỗi injection và traversal |
| Cross-file Analysis | Có cho Python | Là điểm mạnh kỹ thuật hiện tại |
| AI Verification | Đã có seed ban đầu | Là cơ sở để phát triển thành AI Triage |
| Reporting | JSON, Markdown | Có đầu ra để mở rộng benchmark và SARIF |

Tuy nhiên, nếu nhìn dưới góc độ một đề tài báo cáo lớn hoặc một đề tài nghiên cứu khoa học, project hiện tại vẫn còn những khoảng trống cần giải quyết:

- Finding chưa được chuẩn hóa đủ sâu để phục vụ benchmark và triage.
- AI mới ở mức verification, chưa phải một workflow agent hoàn chỉnh.
- Chưa có lớp tri thức lỗ hổng có cấu trúc.
- Chưa có SARIF và CI-oriented reporting.
- Chưa có benchmark đủ mạnh với baseline như Semgrep hay CodeQL.
- Chưa có một lớp orchestration rõ ràng để điều phối scanner, knowledge và AI.

Từ nền tảng đó, đề tài này được lựa chọn như một bước phát triển tiếp theo để biến Aegis-SAST từ một scanner kỹ thuật thành một prototype nghiên cứu có cấu trúc, có số liệu và có khả năng trình bày học thuật.

## 3. Mục tiêu của đề tài

### 3.1. Mục tiêu tổng quát

Xây dựng hệ thống Aegis-SAST lai ghép giữa Phân tích tĩnh (SAST) deterministic dựa trên cấu trúc cây cú pháp (AST) và Trí tuệ nhân tạo điều phối dạng đa tác nhân (Multi-Agent), nhằm tự động phát hiện, phân loại lỗi và giải thích lỗ hổng với tỷ lệ cảnh báo giả ở mức tối thiểu.

### 3.2. Mục tiêu cụ thể

1. Thiết kế **Normalized Finding Schema** cho toàn bộ pipeline, bao gồm cấu trúc **Evidence Bundle** (chứa thông tin source, sink, dataflow, code snippets).
2. Duy trì hỗ trợ đa ngôn ngữ nhưng phân tầng độ sâu phân tích theo từng ngôn ngữ (xem chi tiết tại Bảng 3 — Ma trận ngôn ngữ).
3. Xây dựng tầng tri thức bảo mật cục bộ (**Knowledge Cards**) ánh xạ trực tiếp với các phân loại lỗi CWE/OWASP cho các lỗ hổng ưu tiên.
4. Thiết kế và cài đặt quy trình điều phối đa tác nhân (**Agentic Loop**) sử dụng LangGraph để thực hiện các nhiệm vụ: Lập kế hoạch ngữ cảnh (Planner), Đánh giá an toàn (Auditor), Biện luận phản bác (Skeptic/Validator) và Trọng tài ra quyết định (Judge).
5. Nâng cấp khả năng xuất báo cáo theo chuẩn quốc tế **SARIF** (Static Analysis Results Interchange Format) để tích hợp trực tiếp vào quy trình CI/CD.
6. Phát triển AI Triage với các trạng thái confirmed, likely, needs-review, suppressed.
7. Thực nghiệm đánh giá hệ thống bằng các chỉ số Precision, Recall, F1-Score, False-Positive Reduction và chất lượng explanation trên các bộ dữ liệu chuẩn, so sánh với công cụ baseline Semgrep.

**Bảng 2. Hệ thống mục tiêu của đề tài**

| Nhóm mục tiêu | Nội dung |
|---|---|
| Mục tiêu hệ thống | Củng cố scanner core, schema và reporting |
| Mục tiêu AI | Triage finding dựa trên evidence và knowledge context |
| Mục tiêu Agent | Build workflow có trạng thái bằng LangGraph |
| Mục tiêu đánh giá | So sánh với baseline và lượng hóa hiệu quả |
| Mục tiêu học thuật | Tạo đầu ra phù hợp cho báo cáo và nghiên cứu khoa học |

## 4. Câu hỏi nghiên cứu

Đề tài tập trung trả lời các câu hỏi sau:

1. Việc kết hợp phân tích tĩnh với AI Triage có giúp giảm False Positive so với chỉ dùng phân tích tĩnh hay không?
2. Việc nạp tri thức lỗ hổng (Knowledge Loading) có giúp AI Triage ổn định và hữu ích hơn hay không?
3. Việc tổ chức agent theo workflow có trạng thái bằng LangGraph có hiệu quả hơn cách gọi AI theo prompt đơn lẻ hay không?
4. Việc sử dụng bằng chứng luồng dữ liệu (Dataflow Evidence) có giúp quá trình triage chính xác hơn hay không?

**Bảng 3. Hệ thống câu hỏi nghiên cứu**

| Mã câu hỏi | Nội dung |
|---|---|
| RQ1 | AI Triage có giúp giảm False Positive so với static analysis đơn thuần hay không? |
| RQ2 | Knowledge Loading có giúp explanation và remediation tốt hơn hay không? |
| RQ3 | Workflow agent bằng LangGraph có ổn định hơn prompt tuyến tính hay không? |
| RQ4 | Evidence về dataflow có giúp triage đáng tin cậy hơn hay không? |

## 5. Phương pháp nghiên cứu

### 5.1. Nghiên cứu tài liệu và khảo sát hệ thống tham khảo

Khảo cứu các công trình nghiên cứu khoa học hàng đầu thế giới về:

- Phân tích tĩnh dựa trên đồ thị (AST, CFG, DFG, Call Graph).
- Kiến trúc Agent tương tác trong công nghệ an toàn phần mềm.
- Các hệ thống query-based analysis (Semgrep, CodeQL).
- Các mô hình agent hỗ trợ kiểm thử bảo mật.
- Các nghiên cứu về LLM-based vulnerability triage và repair.

### 5.2. Phân tích, thiết kế và cài đặt hệ thống

- Kế thừa và cải tiến bộ nhân quét tĩnh có sẵn của Aegis-SAST.
- Xây dựng schema cho finding, triage và knowledge.
- Thiết kế workflow agent bằng LangGraph.
- Cài đặt các thành phần detection, normalization, triage và reporting.

### 5.3. Thực nghiệm, đánh giá và nghiên cứu phân rã (Ablation Study)

Đề tài thực hiện các nhóm so sánh sau:

1. Phân tích tĩnh thuần túy so với phân tích tĩnh kết hợp AI Triage.
2. AI Triage không có Knowledge so với AI Triage có Knowledge.
3. Prompt đơn lẻ tuyến tính so với workflow agent bằng LangGraph.
4. Hệ thống đề xuất so với baseline Semgrep.
5. Benchmark sâu trên Python và benchmark mở rộng trên JavaScript, Java, PHP.

Ngoài ra, đề tài thực hiện **Nghiên cứu phân rã (Ablation Study)** bằng cách đo hiệu năng của AI Triage khi có và không có Knowledge Loading, hoặc khi dùng Prompt đơn lẻ so với LangGraph Workflow, nhằm chứng minh tính hiệu quả của từng thành phần đề xuất một cách độc lập.

**Bảng 4. Các nhóm thực nghiệm chính**

| Nhóm thực nghiệm | Mục đích |
|---|---|
| Static-only vs Static + AI Triage (E1) | Đo tác động trực tiếp của AI Triage lên False Positive |
| AI không Knowledge vs có Knowledge (E2) | Đo tác động của Knowledge Loading lên chất lượng explanation |
| Prompt đơn lẻ vs LangGraph workflow (E3) | Đo tác động của Agent Orchestration lên độ ổn định |
| Aegis-SAST vs Semgrep | So sánh với baseline rule-based |
| Python sâu vs đa ngôn ngữ mở rộng | Kiểm tra mức độ phù hợp của chiến lược phân tầng ngôn ngữ |

## 6. Đối tượng và phạm vi nghiên cứu

### 6.1. Đối tượng nghiên cứu

- Các thuật toán phân tích tĩnh mã nguồn.
- Cơ chế phân tích taint flow xuyên hàm (Cross-file).
- Các mô hình điều phối AI Agent hỗ trợ phân tích mã nguồn bảo mật.
- Finding sinh ra từ quá trình phân tích tĩnh.
- Tri thức về các nhóm lỗ hổng web phổ biến.
- Đầu ra triage và báo cáo cuối.

### 6.2. Phạm vi nghiên cứu

- **Ngôn ngữ trọng tâm:** Tập trung phân tích sâu và phân tích xuyên file (Cross-file) cho ngôn ngữ **Python**. Hỗ trợ rà quét ở mức tệp đơn (Intra-file) đối với **JavaScript, Java và PHP** để chứng minh tính đa ngôn ngữ của kiến trúc.
- **Nhóm lỗ hổng ưu tiên:** SQL Injection, Command Injection, Path Traversal, XSS, SSRF.
- **Công cụ đối chứng chính:** Semgrep.
- **Công cụ đối chứng mở rộng:** CodeQL trong phạm vi hẹp nếu đủ thời gian.

**Bảng 5. Ma trận phân tầng ngôn ngữ (Language Matrix)**

| Ngôn ngữ | Mức phân tích | Taint Analysis | Cross-file | Agent Triage | Benchmark |
|---|---|---|---|---|---|
| **Python** | Phân tích sâu | Có (Source-Sanitizer-Sink) | Có (Call Graph) | Có đầy đủ Evidence | Benchmark chính |
| **JavaScript** | Intra-file | Pattern matching | Không | Triage trên AST rule | Benchmark mở rộng |
| **Java** | Intra-file | Pattern matching | Không | Triage trên AST rule | Benchmark mở rộng |
| **PHP** | Intra-file | Pattern matching | Không | Triage trên AST rule | Benchmark mở rộng |

**Lưu ý quan trọng:** Phạm vi thực nghiệm đầy đủ của Agent Triage và Benchmark (với Dataflow Evidence) chủ yếu áp dụng trên Python. Đối với các ngôn ngữ mở rộng (JavaScript, Java, PHP), hệ thống chỉ áp dụng AI Triage trên các rule dạng Pattern Matching hoặc cấu trúc AST đơn giản. Kết quả thực nghiệm RQ4 (về Dataflow Evidence) không áp dụng cho các ngôn ngữ mở rộng.

### 6.3. Phạm vi không đặt mục tiêu

- Không xây dựng hệ thống thay thế hoàn toàn công cụ SAST thương mại.
- Không mở rộng đồng thời quá nhiều ngôn ngữ ở mức phân tích sâu.
- Không đưa các ngôn ngữ chưa có plugin ổn định vào benchmark chính.
- Không đặt mục tiêu auto-fix hoàn chỉnh cho mọi finding.
- Không tập trung vào dashboard lớn trong giai đoạn chính của đề tài.

**Bảng 6. Tổng hợp phạm vi thực hiện của đề tài**

| Nội dung | Phạm vi lựa chọn |
|---|---|
| Ngôn ngữ chính | Python (cross-file, taint analysis đầy đủ) |
| Ngôn ngữ mở rộng | JavaScript, Java, PHP (intra-file, pattern matching) |
| Nhóm lỗi chính | SQLi, Command Injection, Path Traversal, XSS, SSRF |
| Baseline chính | Semgrep |
| Baseline mở rộng | CodeQL trong phạm vi hẹp |
| Ngoài phạm vi | Dashboard lớn, auto-fix hoàn chỉnh, enterprise-scale SAST |

---

# PHẦN HAI: NỘI DUNG

## CHƯƠNG 1: TỔNG QUAN VỀ PHÂN TÍCH TĨNH (SAST) VÀ CÁC KỸ THUẬT TẤN CÔNG WEB

### 1.1. Tổng quan

An toàn ứng dụng Web ngày càng phức tạp khi kẻ tấn công liên tục cải tiến kỹ thuật nhằm vượt qua các bức tường lửa ứng dụng (WAF) và các hệ thống phát hiện xâm nhập. Việc rà quét và đảm bảo mã nguồn sạch ngay từ giai đoạn lập trình (Shift Left Security) là bắt buộc. Phân tích tĩnh (SAST) đóng vai trò trung tâm trong quy trình này.

### 1.2. Cơ sở lý thuyết

#### 1.2.1. Khái niệm và vai trò của An ninh ứng dụng Web

Giới thiệu tổng quan về chu kỳ phát triển phần mềm an toàn (SSDLC) và vị trí của công cụ SAST trong việc bảo vệ ứng dụng Web trước các nguy cơ tấn công từ môi trường mạng.

#### 1.2.2. Phân loại tấn công Web (SQLi, XSS, Path Traversal, Command Injection...)

Định nghĩa cơ chế hoạt động, nguồn sinh (Source), điểm thực thi nguy hiểm (Sink) và cách thức khai thác của các lỗ hổng phổ biến theo phân loại của OWASP Top 10 và CWE.

#### 1.2.3. Các phương pháp che giấu payload (Encoding, Obfuscation...)

Phân tích cách thức kẻ tấn công sử dụng các kỹ thuật mã hóa (Hex, Base64, URL Encoding), ghép chuỗi động, hoặc obfuscation mã nguồn nhằm làm mù các bộ quét dựa trên đối khớp chuỗi (Regex) truyền thống.

#### 1.2.4. WAF truyền thống và hạn chế

Đánh giá điểm yếu của các hệ thống ngăn chặn dạng Signature-based: dễ bị bypass bằng payload biến thể, tỷ lệ cảnh báo sai cao và không có khả năng hiểu luồng xử lý nội bộ của ứng dụng.

#### 1.2.5. Hướng tiếp cận lai ghép (Hybrid) và sự xuất hiện của AI Agent

Phân tích lý do vì sao LLM thuần túy không thể thay thế SAST (giới hạn context window, hallucination, chi phí token) và tại sao mô hình lai (Deterministic Scanner sinh bằng chứng + AI Agent đánh giá ngữ cảnh) là xu hướng đột phá hiện nay.

---

## CHƯƠNG 2: CÁC CÔNG TRÌNH NGHIÊN CỨU LIÊN QUAN

### 2.1. Các công trình nghiên cứu trong nước

Khảo sát các nghiên cứu của các tác giả trong nước về việc ứng dụng học máy, học sâu và luật AST để phát hiện mã độc hoặc lỗ hổng phần mềm. Đánh giá ưu điểm và hạn chế về độ chính xác cũng như quy mô thực nghiệm của các nghiên cứu này.

### 2.2. Các công trình nghiên cứu nước ngoài

- Khảo sát các nghiên cứu về việc tích hợp LLM làm nhiệm vụ triage lỗ hổng (ví dụ: các công cụ như Strix, utkusen/sast-skills).
- Phân tích các mô hình Program Slicing (lát cắt chương trình) phối hợp với RAG (Retrieval-Augmented Generation) để tối ưu ngữ cảnh đưa vào LLM.
- Đánh giá các benchmark lớn như **SWE-bench**, **Juliet Test Suite** trong việc đo lường năng lực của các AI Agent bảo mật.

---

## CHƯƠNG 3: KIẾN TRÚC HỆ THỐNG AGENTIC HYBRID SAST ĐỀ XUẤT

Hệ thống được thiết kế theo mô hình kiến trúc phân tầng chuyên biệt gồm 6 lớp nhằm tách biệt phần phân tích tĩnh có tính xác thực cao và phần AI Agent lập luận ngữ cảnh.

**Bảng 7. Kiến trúc 6 lớp của hệ thống Aegis-SAST**

| Lớp | Tên lớp | Chức năng chính | Đầu ra |
|---|---|---|---|
| 1 | Repo Intake Layer | Tiếp nhận mã nguồn (Local Directory / Git URL), nhận diện ngôn ngữ và framework, chọn cấu hình quét (Scan Profile) | Repo Metadata |
| 2 | Deterministic Detection Core | Tree-sitter AST Parsers, Rule Engine (YAML rules), Taint Engine (Source → Sanitizer → Sink), Call Graph Generator (Cross-file Python) | Raw Findings |
| 3 | Finding Normalization | Ánh xạ sang Normalized Finding Schema, thu thập Evidence Bundle và Code Snippets | Normalized Findings |
| 4 | Knowledge Loading Layer | Trích xuất local Knowledge Cards, liên kết luật CWE, OWASP, Sanitizer Rubrics | Finding + Knowledge Context |
| 5 | AI Triage Layer (LangGraph) | Planner Node, Auditor Node, Skeptic Validator Node, Judge Node — điều phối lập luận có phản biện | Triaged Results |
| 6 | Reporting và CI/CD Layer | Remediation Node, Exporters (JSON, Markdown, SARIF), CI/CD Adapters (GitHub Code Scanning) | Báo cáo cuối cùng |

*Điểm cần nhấn mạnh: AI Agent không thay thế lớp phân tích tĩnh. Agent chỉ hoạt động sau khi finding đã được tạo ra cùng với evidence. Nhờ đó, hệ thống giữ được tính kiểm chứng và giảm rủi ro suy diễn không có căn cứ.*

### 3.1. Tầng Phân tích Tĩnh (Deterministic Core)

Sử dụng các bộ parser Tree-sitter để phân tích mã nguồn thành cây cú pháp trừu tượng (AST). Cơ chế Taint Analysis lần theo dấu vết luồng dữ liệu truyền từ điểm nhận dữ liệu đầu vào (Source) qua các bước trung gian đến điểm thực thi nhạy cảm (Sink). Đối với Python, tích hợp module Call Graph để giải quyết bài toán luồng dữ liệu xuyên tệp tin (Cross-file).

### 3.2. Chuẩn hóa lỗi (Finding Normalization)

Mọi lỗ hổng thô phát hiện từ tầng quét tĩnh được chuẩn hóa về một cấu trúc dữ liệu thống nhất (**Normalized Finding Schema**) bao gồm:

- **Evidence Bundle:** Chứa thông tin chi tiết về điểm Source, điểm Sink, đường đi dữ liệu (DataFlowPath), và đoạn mã nguồn tương ứng (Code Snippets).
- **Metadata:** Định danh lỗi, mức độ nghiêm trọng ban đầu (Severity), và các liên kết CWE.

### 3.3. Tầng Tri thức Bảo mật (Knowledge Loading)

Nạp thông tin từ các **Knowledge Cards** (thẻ tri thức) dạng cấu trúc cục bộ. Mỗi thẻ chứa tri thức về một lớp lỗi cụ thể:

- Mã CWE và nhóm OWASP tương ứng.
- Các hàm Sanitizer hợp lệ của từng ngôn ngữ.
- Các mẫu báo động giả phổ biến (**False Positive Patterns**).
- Các đoạn mã sửa lỗi mẫu chuẩn (**Secure Fix Templates**).
- Source phổ biến và sink phổ biến.

### 3.4. Điều phối Đa tác nhân (AI Triage Stateful Graph)

Sử dụng framework **LangGraph** để xây dựng trạng thái (State) và điều phối luồng xử lý lặp (**Agentic Loop**):

1. **Planner Agent:** Phân tích cấu trúc thư mục chứa tệp lỗi, xác định các file liên quan (dependency, configuration) để gom nhóm và chuẩn bị ngữ cảnh phân tích (Context Matrix).
2. **Auditor Agent:** Đọc Finding, Evidence Bundle kết hợp với dữ liệu từ Knowledge Card tương ứng nhằm thực hiện phân tích chuyên sâu xem luồng dữ liệu thực tế có khả năng kích hoạt lỗ hổng hay không.
3. **Skeptic Validator Agent:** Đóng vai trò phản biện phòng thủ. Tác nhân này cố gắng tìm kiếm các cơ chế lọc dữ liệu, kiểm tra kiểu dữ liệu hoặc các hàm sanitizer ẩn trong code để chứng minh phát hiện này là cảnh báo giả (**False Positive**).
4. **Judge Agent:** Đóng vai trò trọng tài. Dựa trên lập luận của Auditor và Skeptic, Judge đưa ra quyết định gán trạng thái phân loại cuối cùng (**Triage Status**) gồm một trong các nhãn: `confirmed` (xác thực lỗi), `likely` (nhiều khả năng lỗi), `needs-review` (cần con người đánh giá) và `suppressed` (loại bỏ do báo động giả). Đồng thời tính toán điểm số nguy hại CVSS dựa trên ngữ cảnh thực tế.

**Bảng 8. Các node chính của LangGraph Agent**

| Node | Vai trò | Điều kiện kích hoạt |
|---|---|---|
| Planner | Chọn luồng xử lý theo loại finding và ngôn ngữ | Luôn chạy |
| KnowledgeLoader | Nạp Knowledge Card phù hợp | Luôn chạy |
| Auditor (SecurityReviewer) | Đánh giá finding ở vòng đầu | Luôn chạy |
| SkepticValidator | Phản biện finding chưa đủ thuyết phục | Chỉ khi Confidence từ Core ở mức Medium/Low |
| Judge (TriageJudge) | Gán trạng thái triage cuối cùng | Luôn chạy |
| Reporter | Tạo explanation, remediation note và output record | Luôn chạy |

**Cơ chế Conditional Routing:** Finding có Confidence High từ Core sẽ đi thẳng từ Auditor đến Judge, không qua SkepticValidator. Chỉ những finding có Confidence Medium hoặc Low, hoặc thuộc nhóm lỗ hổng phức tạp mới đẩy qua SkepticValidator. Thiết kế này giúp tiết kiệm đáng kể chi phí API token và thời gian xử lý khi project có hàng trăm finding.

---

## CHƯƠNG 4: THIẾT KẾ VÀ XÂY DỰNG CÔNG CỤ THỰC NGHIỆM AEGIS-SAST

### 4.1. Kiến trúc hệ thống phần mềm và Cấu trúc thư mục dự án

Hệ thống Aegis-SAST được tổ chức cấu trúc thư mục dạng module chuyên nghiệp, đảm bảo tính dễ bảo trì và mở rộng:

- `aegis_core/`: Chứa bộ quét tĩnh, parser Tree-sitter, phân tích taint flow và phân tích call graph.
- `aegis_agents/`: Triển khai đồ thị LangGraph điều phối các tác nhân AI.
- `aegis_knowledge/`: Quản lý việc nạp các thẻ tri thức lỗi cục bộ và tra cứu quy tắc.
- `aegis_ci/`: Định dạng đầu ra báo cáo, bao gồm parser sinh file theo chuẩn SARIF quốc tế.

### 4.2. Các module chức năng chính

- **Module CLI và Repo Intake:** Điểm vào của ứng dụng, chịu trách nhiệm tiếp nhận tham số từ người dùng, nhận diện cấu trúc dự án cần quét và phân phối luồng xử lý.
- **Module Core Scanner:** Rà quét, sinh AST và lọc ra danh sách các điểm nghi ngờ ban đầu (Raw Candidates).
- **Module Agentic Triage:** Gọi API mô hình ngôn ngữ lớn (sử dụng Gemini API), thực thi đồ thị LangGraph và cập nhật trạng thái lỗi.
- **Module Exporter:** Kết xuất báo cáo ra các định dạng JSON, Markdown trực quan và tệp SARIF chuẩn.

### 4.3. Công nghệ sử dụng và Môi trường phát triển

**Bảng 9. Công nghệ sử dụng (Technology Stack)**

| Thành phần | Công nghệ | Phiên bản / Ghi chú |
|---|---|---|
| Ngôn ngữ phát triển | Python | 3.12+ |
| AST Parsing | Tree-sitter | Bộ parser đa ngôn ngữ |
| Agent Orchestration | LangGraph | Framework đồ thị trạng thái |
| Mô hình LLM | Google Gemini | Gemini 2.0 Flash (API) |
| Schema Validation | Pydantic | Structured output enforcement |
| CLI Framework | Rich | Terminal UI nâng cao |
| Output Format | SARIF | v2.1.0 (chuẩn OASIS) |
| Quản lý phụ thuộc | pip / venv | Cô lập môi trường |
| Hệ điều hành | Đa nền tảng | Windows, Linux, macOS |
| CI/CD Integration | GitHub Actions | Code Scanning alerts |

---

## CHƯƠNG 5: THỰC NGHIỆM VÀ ĐÁNH GIÁ

### 5.1. Thiết lập kịch bản thực nghiệm

Mô tả chi tiết môi trường thử nghiệm (cấu hình phần cứng, API LLM sử dụng, các tham số hyper-parameters của agent workflow).

#### Tập dữ liệu thử nghiệm (Dataset)

Để tính được Recall, F1-Score và False-Positive Reduction một cách khoa học, bắt buộc phải có **Ground Truth Dataset** — tức là bộ mã nguồn đã biết trước chính xác dòng nào là lỗ hổng thật, dòng nào là False Positive. Đề tài sử dụng các nguồn sau:

**Bảng 10. Bộ dữ liệu Ground Truth cho Benchmark**

| Bộ dữ liệu | Ngôn ngữ | Đặc điểm | Vai trò |
|---|---|---|---|
| Juliet Test Suite | Java (CWE-89 SQLi, CWE-79 XSS) | Có nhãn True/False đầy đủ do NIST cung cấp | Ground truth chuẩn quốc tế |
| Synthetic Dataset tự tạo | Python | 50-100 sample tự viết, có gắn nhãn True Positive / False Positive rõ ràng | Ground truth chính cho Python |
| Dự án mẫu nội bộ | Python, JS, Java, PHP | Các project trong `examples/` và `test_projects/` | Kiểm thử chức năng |
| OWASP Benchmark | Java | Benchmark mở rộng | Bổ sung nếu đủ thời gian |

### 5.2. Kết quả thực nghiệm của bộ quét Deterministic Core

Đánh giá năng lực của phần quét tĩnh độc lập. Ghi nhận số lượng lỗ hổng thô phát hiện được, thời gian quét và các trường hợp bỏ sót lỗi (False Negatives).

### 5.3. Kết quả thực nghiệm sau khi tích hợp lớp AI Triage

Đo lường sự thay đổi của kết quả sau khi luồng Agentic Loop chạy qua:

- Số lượng lỗi được gán nhãn `suppressed` (loại bỏ cảnh báo giả).
- Số lượng lỗi được xác nhận chính xác (`confirmed`).
- Thời gian xử lý trung bình của Agent trên mỗi lỗi phát hiện.
- Chi phí token trung bình trên mỗi finding.

### 5.4. Đánh giá phân rã (Ablation Study) và So sánh Baseline

#### 5.4.1. So sánh hiệu năng với công cụ Baseline (Semgrep)

Chạy cả Aegis-SAST và Semgrep trên cùng một tập dữ liệu benchmark. Tính toán và vẽ biểu đồ so sánh dựa trên 3 chỉ số chính:

- **Precision** = TP / (TP + FP) — Tỷ lệ cảnh báo đúng trong tổng số cảnh báo phát ra.
- **Recall** = TP / (TP + FN) — Tỷ lệ lỗ hổng thật được phát hiện trong tổng số lỗ hổng thực tế.
- **F1-Score** = 2 x Precision x Recall / (Precision + Recall) — Trung bình điều hòa giữa Precision và Recall.

Chứng minh bằng số liệu thực tế rằng lớp AI Triage giúp nâng cao đáng kể chỉ số Precision thông qua việc lọc bỏ các cảnh báo sai mà không làm giảm Recall.

#### 5.4.2. Đo lường hiệu quả của lớp Knowledge Loading (Ablation E2)

So sánh kết quả phân loại lỗi của AI Agent trong 2 kịch bản: có nạp Knowledge Cards và không nạp Knowledge Cards. Đánh giá chất lượng của phần diễn giải lỗi (Explanation) và hướng sửa lỗi (Remediation Notes).

#### 5.4.3. Đo lường hiệu quả của cấu trúc đồ thị LangGraph (Ablation E3)

So sánh độ ổn định và tính nhất quán đầu ra của cấu trúc đồ thị LangGraph có phản biện (Stateful Multi-agent) so với việc chỉ gọi LLM bằng một câu lệnh Prompt tuyến tính duy nhất (Single-prompt Verification).

---

# PHẦN BA: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

## Tóm tắt kết quả đạt được

Hệ thống Aegis-SAST đã chuyển đổi thành công sang kiến trúc Agentic Hybrid SAST. Bằng chứng phân tích tĩnh từ bộ quét AST đã tạo nền tảng vững chắc cho lớp AI Agent phân tích, giúp giảm tỷ lệ False Positive xuống mức tối thiểu, đồng thời cung cấp hướng sửa lỗi chất lượng cao thông qua định dạng SARIF tiêu chuẩn.

## Đóng góp khoa học của đề tài

### Đóng góp kỹ thuật

- Tích hợp phân tích tĩnh đa ngôn ngữ với AI Triage trong cùng một pipeline.
- Xây workflow agent bằng LangGraph cho bài toán SAST.
- Bổ sung lớp Knowledge Loading cho quá trình triage.
- Tạo đầu ra báo cáo giàu ngữ cảnh hơn scanner truyền thống.

### Đóng góp nghiên cứu

- Đánh giá tác động của AI Triage lên False Positive (RQ1).
- Đánh giá tác động của Knowledge Loading lên chất lượng explanation (RQ2).
- Đánh giá tác động của workflow có trạng thái lên độ ổn định của AI (RQ3).
- Đánh giá vai trò của Dataflow Evidence trong quá trình triage (RQ4).

## Hướng phát triển

- Mở rộng cơ chế Cross-file sang các ngôn ngữ khác (Java, JavaScript).
- Nghiên cứu tích hợp cơ chế tự động sửa lỗi và kiểm thử hồi quy (Auto-remediation và Agentic Regression Testing).
- Xây dựng dashboard trực quan hóa kết quả quét cho môi trường doanh nghiệp.

---

## Rủi ro và Hướng giảm thiểu

**Bảng 11. Phân tích rủi ro và phương án giảm thiểu**

| Rủi ro | Hướng giảm thiểu |
|---|---|
| Phạm vi quá rộng | Khóa ngôn ngữ và nhóm lỗ hổng ưu tiên ngay từ đầu |
| AI Triage thiếu ổn định | Dùng structured output (Pydantic), rubric rõ ràng và log đầy đủ |
| Benchmark thiếu Ground Truth | Ưu tiên bộ Synthetic Dataset có kiểm chứng thủ công + Juliet Test Suite |
| Agent quá phức tạp | Giữ số node ở mức cần thiết, không mở rộng quá sớm |
| Chi phí API token cao khi chạy Agent cho hàng trăm finding | Áp dụng Conditional Routing (finding High Confidence đi thẳng Judge), batch grouping, caching kết quả với diskcache |
| Self-bias giữa Reviewer và Skeptic cùng dùng một LLM | Dùng prompt persona khác nhau, temperature khác nhau cho mỗi agent role |

---

## Giới hạn đạo đức (Ethical Considerations)

Hệ thống Aegis-SAST chỉ thực hiện phân tích tĩnh trên mã nguồn đã được cung cấp. Hệ thống không thực thi mã nguồn, không gửi payload tấn công, không khai thác lỗ hổng trên hệ thống thật và không thu thập dữ liệu cá nhân. Mục đích duy nhất của công cụ là hỗ trợ nhà phát triển phát hiện và khắc phục lỗ hổng bảo mật trong giai đoạn phát triển phần mềm.

---

# TÀI LIỆU THAM KHẢO

1. OWASP Foundation. (2025). *OWASP Top 10 Application Security Risks*. https://owasp.org/www-project-top-ten/
2. MITRE Corporation. (2025). *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/
3. Al-Amin, M., et al. (2024). *Large Language Models for Code Vulnerability Detection: Bridges and Gaps*. arXiv preprint.
4. LangGraph documentation. https://langchain-ai.github.io/langgraph/
5. OASIS Open. (2024). *Static Analysis Results Interchange Format (SARIF) v2.1.0*. https://www.oasis-open.org/committees/sarif/
6. OWASP Foundation. (2024). *OWASP Benchmark Project*. https://owasp.org/www-project-benchmark/
7. NIST. (2024). *Juliet Test Suite for C/C++ and Java*. https://samate.nist.gov/
8. Semgrep Inc. (2025). *Semgrep — Lightweight static analysis*. https://semgrep.dev/
9. Google DeepMind. (2025). *Gemini API Documentation*. https://ai.google.dev/
10. Li, H., et al. (2024). *LLM-Assisted Static Analysis for Detecting Security Vulnerabilities*. IEEE S&P Workshop.

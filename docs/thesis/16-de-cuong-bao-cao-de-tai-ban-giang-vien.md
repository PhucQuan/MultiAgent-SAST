# ĐỀ CƯƠNG BÁO CÁO ĐỀ TÀI NGHIÊN CỨU KHOA HỌC

## TÊN ĐỀ TÀI ĐỀ XUẤT

**Nghiên cứu và phát triển hệ thống Agentic Hybrid SAST đa ngôn ngữ sử dụng phân tích tĩnh, Knowledge Loading và AI Triage để phát hiện, phân loại và giải thích lỗ hổng mã nguồn**

*Tên tiếng Anh đề xuất:* **Aegis-SAST: An Evidence-Aware Multi-Language Hybrid SAST Platform with Multi-Agent AI Triage and Knowledge Loading**

---

# PHẦN MỘT: MỞ ĐẦU

## 1. Lý do chọn đề tài

Phát hiện sớm lỗ hổng bảo mật ngay trong giai đoạn phát triển phần mềm là yêu cầu quan trọng đối với quy trình phát triển an toàn. Trong các kỹ thuật hỗ trợ mục tiêu này, kiểm thử an ninh ứng dụng tĩnh (SAST - Static Application Security Testing) có lợi thế lớn vì có thể rà quét trực tiếp mã nguồn mà không cần triển khai hệ thống. Tuy nhiên, các công cụ SAST truyền thống vẫn tồn tại ba hạn chế lớn:

- Tỷ lệ cảnh báo giả (false positive) còn cao, làm giảm giá trị thực tiễn của kết quả quét.
- Nhiều công cụ đưa ra cảnh báo nhưng giải thích chưa rõ bằng chứng kỹ thuật, nên khó ưu tiên xử lý.
- Hầu hết công cụ rule-based chỉ mạnh ở phát hiện, chưa mạnh ở bước triage, phản biện và gợi ý khắc phục theo ngữ cảnh.

Trong khi đó, các mô hình ngôn ngữ lớn (LLM) cho thấy khả năng đọc hiểu mã nguồn, diễn giải lỗi và sinh gợi ý khắc phục khá tốt. Tuy nhiên, nếu dùng LLM theo hướng quét mã nguồn thuần túy, hệ thống sẽ gặp các vấn đề quen thuộc như thiếu bằng chứng xác thực, dễ hallucination, tiêu tốn token lớn và khó ổn định khi quét dự án nhiều tệp.

Từ thực tế đó, hướng tiếp cận phù hợp hơn là **Hybrid SAST**: dùng phân tích tĩnh deterministic để sinh finding và bằng chứng kỹ thuật, sau đó dùng AI để triage, phản biện, giải thích và hỗ trợ ra quyết định. Đề tài này lựa chọn phát triển Aegis-SAST theo hướng đó, với trọng tâm không phải là thay thế scanner bằng AI, mà là xây dựng một **hệ thống SAST lai ghép có bằng chứng, có quy trình agent rõ ràng và có benchmark đối chứng**.

## 2. Cơ sở hình thành đề tài

Đề tài được hình thành trên nền project Aegis-SAST mà nhóm đã xây dựng trước đó. Đây không phải là đề tài bắt đầu từ con số 0, mà là bước nâng cấp có định hướng nghiên cứu từ một scanner thực nghiệm đã có các thành phần kỹ thuật nền tảng.

Ở thời điểm xây dựng đề cương, Aegis-SAST đã có một số thành phần khả dụng để kế thừa:

**Bảng 1. Nền tảng kỹ thuật hiện có của Aegis-SAST**

| Thành phần | Hiện trạng kỹ thuật | Ý nghĩa đối với đề tài |
|---|---|---|
| CLI Scanner | Đã có điểm vào quét thống nhất | Thuận lợi cho việc tích hợp toàn bộ pipeline |
| Plugin đa ngôn ngữ | Python, JavaScript, Java, PHP | Tạo nền cho định hướng multi-language |
| AST Parsing | Tree-sitter | Hỗ trợ phân tích theo cấu trúc mã nguồn |
| Rule Engine | Quy tắc YAML | Thuận lợi cho mở rộng coverage |
| Taint-style Analysis | Đã có ở mức source -> sink | Phù hợp cho nhóm lỗi injection và traversal |
| Cross-file Analysis | Đã có cho Python | Là điểm mạnh kỹ thuật hiện tại của project |
| Workflow triage nền tảng | Đã có seed theo các bước intake, knowledge, auditor, skeptic, judge | Tạo nền để nâng thành workflow LangGraph hoàn chỉnh |
| Reporting | Đã có JSON, Markdown và SARIF seed | Thuận lợi cho benchmark và tích hợp CI/CD |

Tuy nhiên, nếu xét theo yêu cầu của một đề tài nghiên cứu khoa học hoặc khóa luận tốt nghiệp quy mô lớn, project hiện tại vẫn còn những khoảng trống kỹ thuật quan trọng:

- Bằng chứng finding chưa đủ sâu để phục vụ benchmark và triage ở mức nghiên cứu.
- Phân tích sâu hiện mới mạnh chủ yếu ở Python; JavaScript, Java và PHP mới ở mức intra-file.
- Chưa có lớp `DFG-lite` và `CFG-lite` tường minh cho Python để tăng chất lượng dataflow/control-flow reasoning.
- Workflow triage mới là nền tảng thực thi ban đầu, chưa hoàn thiện thành mô hình agent có đánh giá phân rã đầy đủ.
- Benchmark đối chứng với Semgrep và CodeQL chưa được triển khai thành một bộ thực nghiệm hệ thống.

Từ nền tảng đang có và các khoảng trống đó, đề tài được xác định như một bước phát triển tiếp theo nhằm chuyển Aegis-SAST từ một scanner cấp portfolio thành một **prototype nghiên cứu có kiến trúc rõ, có số liệu đối chứng và có đóng góp kỹ thuật cụ thể**.

## 3. Mục tiêu của đề tài

### 3.1. Mục tiêu tổng quát

Đề xuất, thiết kế và phát triển hệ thống Aegis-SAST theo mô hình Agentic Hybrid SAST lai ghép giữa phân tích tĩnh deterministic và AI triage có điều phối, nhằm phát hiện, phân loại, giải thích lỗ hổng mã nguồn và giảm false positive một cách có kiểm chứng.

### 3.2. Mục tiêu cụ thể

1. Chuẩn hóa `Normalized Finding Schema` cho toàn bộ pipeline, trong đó `Evidence Bundle` phải thể hiện rõ source, sink, sanitizer, path summary, snippet và metadata phục vụ benchmark.
2. Nâng độ sâu phân tích cho Python bằng cách bổ sung `DFG-lite` và `CFG-lite` nhằm cải thiện reasoning về luồng dữ liệu và đường đi điều khiển.
3. Duy trì kiến trúc đa ngôn ngữ cho Python, JavaScript, Java và PHP, nhưng phân tầng rõ độ sâu phân tích theo từng ngôn ngữ.
4. Xây dựng kho tri thức cục bộ (`Knowledge Cards`) ánh xạ với CWE, OWASP, sanitizer rubric, false-positive pattern và remediation hint.
5. Thiết kế workflow triage bằng LangGraph với các vai trò Planner, KnowledgeLoader, Auditor, SkepticValidator, Judge và Reporter.
6. Nâng cấp đầu ra báo cáo theo các định dạng JSON, Markdown và SARIF để phục vụ tích hợp CI/CD và so sánh baseline.
7. Xây dựng bộ thực nghiệm định lượng với các chỉ số Precision, Recall, F1-Score, False-Positive Reduction, Runtime và Token Usage.
8. So sánh hệ thống đề xuất với baseline Semgrep, và nếu đủ thời gian thì mở rộng thêm một phạm vi hẹp với CodeQL.

**Bảng 2. Hệ thống mục tiêu của đề tài**

| Nhóm mục tiêu | Nội dung |
|---|---|
| Mục tiêu hệ thống | Củng cố scanner core, schema, evidence và reporting |
| Mục tiêu kỹ thuật | Bổ sung DFG-lite và CFG-lite cho Python |
| Mục tiêu AI | Triage finding dựa trên evidence và knowledge context |
| Mục tiêu agent | Xây workflow có trạng thái bằng LangGraph |
| Mục tiêu đánh giá | So sánh với baseline và lượng hóa hiệu quả |
| Mục tiêu học thuật | Tạo đầu ra phù hợp cho báo cáo, khóa luận và NCKH |

## 4. Câu hỏi nghiên cứu

Đề tài tập trung trả lời các câu hỏi nghiên cứu sau:

1. Việc kết hợp phân tích tĩnh với AI triage có giúp giảm false positive so với chỉ dùng phân tích tĩnh hay không?
2. Việc nạp tri thức bảo mật có cấu trúc (Knowledge Loading) có giúp quá trình triage ổn định và hữu ích hơn hay không?
3. Việc bổ sung bằng chứng `DFG-lite` và `CFG-lite` cho Python có giúp finding đáng tin cậy hơn và cải thiện Precision hay không?
4. Workflow có trạng thái bằng LangGraph có ổn định hơn cách gọi LLM theo prompt tuyến tính đơn lẻ hay không?

**Bảng 3. Hệ thống câu hỏi nghiên cứu**

| Mã câu hỏi | Nội dung |
|---|---|
| RQ1 | AI triage có giúp giảm false positive so với static analysis đơn thuần hay không? |
| RQ2 | Knowledge Loading có giúp explanation và triage ổn định hơn hay không? |
| RQ3 | DFG-lite và CFG-lite có làm tăng chất lượng evidence và Precision cho Python hay không? |
| RQ4 | Workflow LangGraph có cho đầu ra nhất quán hơn single-prompt verification hay không? |

## 5. Phương pháp nghiên cứu

### 5.1. Nghiên cứu tài liệu và khảo sát hệ thống tham khảo

Đề tài khảo sát các nhóm công trình và hệ thống sau:

- Các kỹ thuật phân tích tĩnh dựa trên AST, DFG, CFG và Call Graph.
- Các công cụ SAST tiêu biểu như Semgrep và CodeQL.
- Các hướng tiếp cận sử dụng LLM cho vulnerability triage, explanation và repair.
- Các mô hình điều phối agent có trạng thái cho bài toán phân tích mã nguồn.

### 5.2. Phân tích, thiết kế và cài đặt hệ thống

Đề tài kế thừa scanner Aegis-SAST hiện có và phát triển theo các hướng:

- Chuẩn hóa schema finding và evidence.
- Bổ sung DFG-lite và CFG-lite cho Python.
- Xây dựng workflow triage có trạng thái bằng LangGraph.
- Tổ chức lại knowledge layer, reporting layer và benchmark harness.

### 5.3. Thực nghiệm, đánh giá và nghiên cứu phân rã

Đề tài thực hiện bốn nhóm thực nghiệm chính:

1. Static-only so với Static + AI Triage.
2. AI Triage không có Knowledge so với AI Triage có Knowledge.
3. Single-prompt verification so với LangGraph workflow.
4. Python AST/taint baseline so với Python có thêm DFG-lite và CFG-lite.

**Bảng 4. Các nhóm thực nghiệm chính**

| Nhóm thực nghiệm | Mục đích |
|---|---|
| E1. Static-only vs Static + AI Triage | Đo tác động trực tiếp của AI triage lên false positive |
| E2. Không Knowledge vs Có Knowledge | Đo tác động của Knowledge Loading lên explanation và triage |
| E3. Single-prompt vs LangGraph workflow | Đo tác động của agent orchestration lên độ ổn định |
| E4. AST/Taint vs AST/Taint + DFG-lite/CFG-lite | Đo tác động của evidence sâu lên Precision và path reasoning |
| Baseline Aegis-SAST vs Semgrep | So sánh với công cụ rule-based phổ biến |

## 6. Đối tượng và phạm vi nghiên cứu

### 6.1. Đối tượng nghiên cứu

- Các kỹ thuật phân tích tĩnh mã nguồn.
- Cơ chế dataflow/control-flow reasoning phục vụ SAST.
- Workflow AI agent hỗ trợ triage finding bảo mật.
- Tri thức có cấu trúc về CWE, OWASP và sanitizer.
- Hệ thống benchmark đối chứng cho bài toán false-positive reduction.

### 6.2. Phạm vi nghiên cứu

- **Ngôn ngữ trọng tâm:** Python là ngôn ngữ phân tích sâu, có mục tiêu triển khai taint reasoning, cross-file, DFG-lite, CFG-lite và benchmark chính.
- **Ngôn ngữ mở rộng:** JavaScript, Java và PHP được giữ ở mức intra-file, pattern-level/AST-level để chứng minh khả năng mở rộng đa ngôn ngữ của kiến trúc.
- **Nhóm lỗ hổng ưu tiên:** SQL Injection, Command Injection, Path Traversal, XSS và SSRF.
- **Baseline chính:** Semgrep.
- **Baseline mở rộng:** CodeQL trong phạm vi hẹp nếu đủ thời gian.

**Bảng 5. Ma trận phân tầng ngôn ngữ**

| Ngôn ngữ | Mức phân tích | Dataflow/Control-flow | Cross-file | Agent Triage | Benchmark |
|---|---|---|---|---|---|
| Python | Phân tích sâu | Taint + DFG-lite + CFG-lite | Có | Đầy đủ evidence | Benchmark chính |
| JavaScript | Intra-file | Pattern-level / AST-level | Không | Có nhưng mức cơ bản | Benchmark mở rộng |
| Java | Intra-file | Pattern-level / AST-level | Không | Có nhưng mức cơ bản | Benchmark mở rộng |
| PHP | Intra-file | Pattern-level / AST-level | Không | Có nhưng mức cơ bản | Benchmark mở rộng |

### 6.3. Phạm vi không đặt mục tiêu

- Không đặt mục tiêu thay thế hoàn toàn các công cụ SAST thương mại.
- Không triển khai full graph-based engine cho tất cả ngôn ngữ trong thời gian 3 tháng.
- Không đặt mục tiêu auto-fix hoàn chỉnh cho mọi finding.
- Không tập trung vào dashboard doanh nghiệp trong giai đoạn chính của đề tài.

---

# PHẦN HAI: NỘI DUNG

## CHƯƠNG 1: TỔNG QUAN VỀ SAST, FALSE POSITIVE VÀ HƯỚNG TIẾP CẬN HYBRID

### 1.1. Bài toán phát hiện lỗ hổng bằng phân tích tĩnh

Phân tích tĩnh cho phép rà quét mã nguồn mà không cần thực thi chương trình. Đây là hướng phù hợp với quy trình “shift-left security”. Tuy nhiên, hiệu quả thực tế của SAST không chỉ phụ thuộc vào khả năng phát hiện lỗi, mà còn phụ thuộc mạnh vào chất lượng triage, khả năng giải thích và khả năng giảm false positive.

### 1.2. Cơ sở kỹ thuật: AST, DFG, CFG và Call Graph

- **AST** cho biết cấu trúc cú pháp của chương trình, là nền tảng để nhận diện source, sink, sanitizer và các mẫu vi phạm.
- **DFG** mô tả luồng truyền dữ liệu giữa các biến, hữu ích để theo dõi assignment, argument, parameter và return value.
- **CFG** mô tả đường đi điều khiển, hữu ích để xét branch-aware path, guard clause, return sớm và sanitizer reachability.
- **Call Graph** hỗ trợ nối các lời gọi hàm, đặc biệt quan trọng với phân tích xuyên hàm và xuyên tệp.

Trong phạm vi đề tài này, DFG và CFG không được theo đuổi ở mức học thuật đầy đủ cho mọi ngôn ngữ, mà được triển khai theo hướng `lite`, tập trung vào giá trị thực nghiệm cho Python.

### 1.3. LLM và giới hạn khi áp dụng trực tiếp cho SAST

LLM có thể hỗ trợ diễn giải finding, tổng hợp ngữ cảnh và gợi ý khắc phục. Tuy nhiên, nếu dùng LLM theo hướng quét mã nguồn trực tiếp mà không có bằng chứng deterministic đi kèm, hệ thống sẽ khó kiểm chứng, tốn token và dễ cho đầu ra thiếu ổn định.

### 1.4. Hướng tiếp cận Hybrid SAST

Hướng đề xuất của đề tài là:

1. Dùng deterministic detection core để sinh finding và evidence.
2. Dùng Knowledge Loading để bổ sung ngữ cảnh bảo mật có cấu trúc.
3. Dùng workflow LangGraph để triage, phản biện và ra quyết định.
4. Dùng benchmark đối chứng để chứng minh hiệu quả nghiên cứu.

## CHƯƠNG 2: CÁC CÔNG TRÌNH VÀ HỆ THỐNG LIÊN QUAN

### 2.1. Công cụ SAST tham khảo

- **Semgrep** đại diện cho hướng quét dựa trên rule và pattern matching.
- **CodeQL** đại diện cho hướng query-based static analysis có chiều sâu học thuật hơn.

Hai công cụ này phù hợp để làm baseline đối chứng cho đề tài.

### 2.2. Hệ thống agent và workflow tham khảo

- Các dự án agent hỗ trợ làm việc với mã nguồn như Strix hoặc các skill-based workflow cho SAST cho thấy vai trò của orchestration.
- Tuy nhiên, đề tài không đi theo hướng “nhiều agent trò chuyện tự do”, mà đi theo **workflow có trạng thái và có điều kiện rẽ nhánh**.

### 2.3. Các nghiên cứu liên quan đến LLM-based vulnerability triage

Các nghiên cứu gần đây tập trung vào:

- Giảm false positive bằng LLM triage.
- Tăng chất lượng explanation và remediation note.
- Kết hợp program slicing, retrieval hoặc structured evidence để nâng độ tin cậy.

Khoảng trống mà đề tài hướng tới là: **kết hợp evidence-aware SAST, workflow LangGraph và benchmark đối chứng trong một hệ thống thực nghiệm thống nhất**.

## CHƯƠNG 3: KIẾN TRÚC HỆ THỐNG AGENTIC HYBRID SAST ĐỀ XUẤT

Đề tài đề xuất kiến trúc 6 lớp để tách phần phân tích tĩnh deterministic khỏi phần triage có sử dụng AI.

**Bảng 6. Kiến trúc 6 lớp của hệ thống đề xuất**

| Lớp | Tên lớp | Chức năng chính | Đầu ra |
|---|---|---|---|
| 1 | Repo Intake Layer | Nhận mã nguồn, nhận diện ngôn ngữ và framework, chọn scan profile | Repo metadata |
| 2 | Deterministic Detection Core | AST parser, rule engine, taint engine, call graph, DFG-lite/CFG-lite cho Python | Raw findings |
| 3 | Finding Normalization Layer | Chuẩn hóa finding và tạo Evidence Bundle | Normalized findings |
| 4 | Knowledge Loading Layer | Nạp Knowledge Cards, CWE/OWASP mapping và sanitizer rubric | Finding + knowledge context |
| 5 | AI Triage Layer | LangGraph workflow với Planner, Auditor, SkepticValidator, Judge, Reporter | Triaged results |
| 6 | Reporting, Evaluation and CI Layer | Xuất JSON, Markdown, SARIF; benchmark; CI/CD integration | Báo cáo và số liệu |

### 3.1. Repo Intake Layer

Lớp này chịu trách nhiệm xác định:

- loại đầu vào cần quét;
- ngôn ngữ lập trình hiện diện trong dự án;
- framework hoặc dấu hiệu công nghệ liên quan;
- kế hoạch quét tương ứng.

### 3.2. Deterministic Detection Core

Đây là lớp nền tảng của hệ thống. Phần này sử dụng:

- Tree-sitter để tạo AST đa ngôn ngữ;
- Rule engine để nhận diện các mẫu nguy hiểm;
- Taint propagation để nối source đến sink;
- Call graph cho Python để hỗ trợ phân tích xuyên hàm và xuyên tệp.

Nâng cấp kỹ thuật trọng tâm của đề tài nằm ở hai phần:

- **DFG-lite cho Python:** theo dõi assignment, argument -> parameter, return value -> biến nhận, và tóm tắt dataflow path.
- **CFG-lite cho Python:** xét branch-aware path, return sớm, guard clause, sanitizer reachability và loại bỏ path không hợp lệ rõ ràng.

### 3.3. Finding Normalization Layer

Mọi finding từ deterministic core được chuẩn hóa về một cấu trúc thống nhất.

`Normalized Finding` dự kiến bao gồm các nhóm trường sau:

- thông tin định danh finding;
- ngôn ngữ và loại lỗ hổng;
- CWE/OWASP mapping;
- severity ban đầu;
- triage status;
- evidence summary;
- metadata phục vụ benchmark và reporting.

`Evidence Bundle` là thành phần quan trọng nhất, dự kiến bao gồm:

- source location;
- sink location;
- sanitizer location nếu có;
- path summary;
- code snippet liên quan;
- confidence từ deterministic core.

### 3.4. Knowledge Loading Layer

`Knowledge Cards` là đơn vị tri thức cục bộ để hỗ trợ triage. Mỗi card có thể chứa:

- mã CWE và nhóm OWASP liên quan;
- source/sink phổ biến;
- sanitizer rubric theo ngôn ngữ;
- false-positive pattern thường gặp;
- remediation hint ở mức kỹ thuật.

### 3.5. AI Triage Layer bằng LangGraph

Đề tài đề xuất workflow LangGraph theo các node:

1. **Planner:** xác định bối cảnh xử lý finding.
2. **KnowledgeLoader:** nạp tri thức phù hợp với finding.
3. **Auditor:** đánh giá finding dựa trên evidence và knowledge context.
4. **SkepticValidator:** tìm lập luận phản biện, sanitizer hoặc điều kiện giảm mức nghi ngờ.
5. **Judge:** gán nhãn `confirmed`, `likely`, `needs-review` hoặc `suppressed`.
6. **Reporter:** sinh explanation và remediation suggestion.

Lớp này áp dụng **Conditional Routing**:

- finding có confidence cao từ core có thể đi thẳng từ Auditor đến Judge;
- finding trung bình hoặc thấp phải đi qua SkepticValidator để giảm false positive.

Lưu ý: trong phạm vi đề tài, phần này tập trung vào **triage và giải thích**, không đặt mục tiêu auto-fix hoàn chỉnh.

### 3.6. Reporting, Evaluation and CI Layer

Lớp đầu ra bao gồm:

- báo cáo JSON để phục vụ xử lý máy;
- báo cáo Markdown để phục vụ đọc thủ công;
- báo cáo SARIF để tích hợp GitHub Code Scanning;
- benchmark harness để chạy batch và so sánh kết quả.

## CHƯƠNG 4: THIẾT KẾ VÀ XÂY DỰNG CÔNG CỤ THỰC NGHIỆM

### 4.1. Thiết kế theo module chức năng

Để phù hợp với cả nghiên cứu và triển khai, hệ thống được tổ chức theo các module chức năng:

- Module CLI và Repo Intake.
- Module Core Scanner.
- Module Finding Normalization và Evidence.
- Module Knowledge Loading.
- Module LangGraph Triage Workflow.
- Module Reporting và Benchmark.

### 4.2. Công nghệ sử dụng

**Bảng 7. Công nghệ sử dụng**

| Thành phần | Công nghệ / lựa chọn |
|---|---|
| Ngôn ngữ phát triển | Python 3.12+ |
| AST parsing | Tree-sitter |
| Điều phối workflow | LangGraph |
| Mô hình ngôn ngữ lớn | Gemini hoặc mô hình tương đương |
| Structured output | Schema-based validation |
| Rule format | YAML |
| CLI | Rich |
| Báo cáo chuẩn | SARIF v2.1.0 |
| Thực nghiệm và kiểm thử | pytest, benchmark scripts |
| CI/CD | GitHub Actions |

### 4.3. Đầu ra dự kiến của công cụ thực nghiệm

Đề tài hướng đến các đầu ra kỹ thuật sau:

- Một prototype Aegis-SAST có CLI hoàn chỉnh.
- Một thư viện Knowledge Cards cho 5 nhóm CWE ưu tiên.
- Một workflow LangGraph cho AI triage.
- Một hệ thống xuất báo cáo JSON, Markdown và SARIF.
- Một bộ benchmark và script đánh giá đối chứng.

## CHƯƠNG 5: THỰC NGHIỆM VÀ ĐÁNH GIÁ

### 5.1. Thiết lập thực nghiệm

Thực nghiệm sẽ mô tả rõ:

- môi trường phần cứng và phần mềm;
- phiên bản parser, rule và mô hình LLM sử dụng;
- cấu hình workflow triage;
- cách thu thập runtime và token usage.

### 5.2. Bộ dữ liệu thực nghiệm

**Bảng 8. Bộ dữ liệu dự kiến cho benchmark**

| Bộ dữ liệu | Ngôn ngữ | Vai trò |
|---|---|---|
| Synthetic Dataset tự tạo | Python | Ground truth chính cho benchmark sâu |
| Juliet Test Suite | Java | Baseline chuẩn cho đối chứng mở rộng |
| Dự án mẫu nội bộ | Python, JS, Java, PHP | Kiểm thử chức năng và demo |
| OWASP Benchmark | Java | Bổ sung nếu đủ thời gian |

Đối với **Synthetic Dataset cho Python**, đề tài dự kiến xây dựng 50-100 mẫu có nhãn rõ ràng theo 5 nhóm lỗi ưu tiên. Quy trình gắn nhãn được thực hiện như sau:

1. Mỗi mẫu được mô tả rõ source, sink, sanitizer và nhãn kỳ vọng.
2. Hai thành viên gắn nhãn độc lập.
3. Các trường hợp bất đồng được rà soát lại thủ công.
4. Bộ nhãn cuối cùng được dùng làm ground truth cho benchmark chính.

### 5.3. Chỉ số đánh giá

Đề tài sử dụng các chỉ số sau:

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1-Score** = 2 x Precision x Recall / (Precision + Recall)
- **False-Positive Reduction Rate**
- **Runtime**
- **Token Usage**

Ngoài ra, có thể bổ sung đánh giá định tính cho explanation theo các tiêu chí:

- có nêu được source/sink hay không;
- có dùng đúng evidence hay không;
- có remediation suggestion phù hợp hay không.

### 5.4. Các kịch bản thực nghiệm

#### 5.4.1. E1: Static-only vs Static + AI Triage

Mục tiêu là đo trực tiếp tác động của lớp AI triage lên false positive.

#### 5.4.2. E2: Không Knowledge vs Có Knowledge

Mục tiêu là đo ảnh hưởng của Knowledge Cards lên explanation, triage status và tính ổn định của đầu ra.

#### 5.4.3. E3: Single-prompt vs LangGraph workflow

Mục tiêu là kiểm tra workflow có trạng thái và có phản biện có tạo đầu ra ổn định hơn cách gọi LLM tuyến tính hay không.

#### 5.4.4. E4: AST/Taint vs AST/Taint + DFG-lite/CFG-lite

Mục tiêu là chứng minh phần evidence sâu có tác động trực tiếp đến Precision và chất lượng path reasoning trên Python.

#### 5.4.5. So sánh với baseline

Đề tài thực hiện so sánh Aegis-SAST với Semgrep trên cùng tập dữ liệu để lượng hóa ưu điểm và giới hạn của hướng hybrid triage.

---

# PHẦN BA: KẾT QUẢ KỲ VỌNG, ĐÓNG GÓP VÀ HƯỚNG PHÁT TRIỂN

## 1. Kết quả kỳ vọng

Đề tài kỳ vọng tạo ra một prototype Aegis-SAST có các đặc điểm:

- có scanner đa ngôn ngữ dựa trên AST;
- có phân tích sâu cho Python với call graph, DFG-lite và CFG-lite;
- có workflow LangGraph cho AI triage;
- có knowledge layer để hỗ trợ explanation;
- có đầu ra SARIF và benchmark đối chứng.

## 2. Đóng góp kỹ thuật

- Chuẩn hóa finding theo hướng evidence-aware.
- Bổ sung DFG-lite và CFG-lite cho Python trong bài toán SAST thực nghiệm.
- Xây dựng workflow LangGraph cho triage có phản biện.
- Tổ chức đầu ra báo cáo và benchmark phù hợp cho nghiên cứu.

## 3. Đóng góp nghiên cứu

- Đo lường tác động của AI triage lên false positive.
- Đo lường tác động của Knowledge Loading lên explanation và sự ổn định.
- Đo lường tác động của evidence sâu (DFG-lite/CFG-lite) lên Precision.
- Đo lường sự khác biệt giữa workflow LangGraph và single-prompt verification.

## 4. Hướng phát triển

- Mở rộng cross-file analysis sang ngôn ngữ khác ngoài Python.
- Nghiên cứu remediation có kiểm soát và regression testing tự động.
- Mở rộng benchmark và tích hợp CI/CD sâu hơn.

## 5. Rủi ro và hướng giảm thiểu

**Bảng 9. Rủi ro và hướng giảm thiểu**

| Rủi ro | Hướng giảm thiểu |
|---|---|
| Phạm vi quá rộng | Khóa ngôn ngữ sâu ở Python và giới hạn 5 nhóm lỗi ưu tiên |
| Token API cao | Dùng conditional routing, caching và giới hạn số finding qua Skeptic |
| Workflow agent quá phức tạp | Giữ số node ở mức cần thiết, không mở rộng quá sớm |
| Dataset thiếu ground truth | Xây synthetic dataset có gắn nhãn chéo bởi 2 thành viên |
| Môi trường cài đặt không ổn định | Chuẩn hóa môi trường CPython và tách phụ thuộc core/AI |

## 6. Giới hạn đạo đức

Hệ thống chỉ thực hiện phân tích tĩnh trên mã nguồn được cung cấp, không thực thi mã, không khai thác lỗ hổng trên hệ thống thật và không thu thập dữ liệu cá nhân. Mục tiêu duy nhất là hỗ trợ phát hiện và giảm rủi ro bảo mật trong quá trình phát triển phần mềm.

## 7. Tài liệu tham khảo

1. OWASP Foundation. *OWASP Top 10 Application Security Risks*.
2. MITRE. *Common Weakness Enumeration (CWE)*.
3. OASIS. *Static Analysis Results Interchange Format (SARIF) v2.1.0*.
4. LangGraph Documentation.
5. NIST. *Juliet Test Suite*.
6. OWASP Benchmark Project.
7. Semgrep Documentation.
8. CodeQL Documentation.
9. Các nghiên cứu liên quan đến LLM-based vulnerability triage và automated vulnerability repair.

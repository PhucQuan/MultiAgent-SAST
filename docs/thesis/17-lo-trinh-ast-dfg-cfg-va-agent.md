# LỘ TRÌNH NÂNG CẤP AEGIS-SAST TỪ AST LÊN DFG-LITE, CFG-LITE VÀ AGENT

## 1. Mục đích của tài liệu

Tài liệu này dùng để chốt một câu hỏi kỹ thuật quan trọng của đề tài: nếu muốn đưa Aegis-SAST từ mức scanner AST-based lên mức khóa luận lớn và có giá trị nghiên cứu, thì có cần DFG và CFG hay không, và cần triển khai theo thứ tự nào để không vỡ scope.

Tài liệu cũng dùng để đồng bộ cách trình bày giữa ba lớp nội dung:

- hiện trạng thực tế của repo;
- kiến trúc mục tiêu của đề tài;
- lộ trình nâng cấp trong 3 tháng.

---

## 2. Kết luận ngắn gọn

**Có, cần DFG và CFG.** Tuy nhiên, không nên triển khai theo kiểu full graph engine cho mọi ngôn ngữ cùng lúc.

Hướng phù hợp nhất cho Aegis-SAST là:

1. Giữ AST làm lớp nền.
2. Bổ sung `DFG-lite` cho Python để làm dataflow evidence rõ hơn.
3. Bổ sung `CFG-lite` cho Python để làm path reasoning tốt hơn.
4. Dùng workflow LangGraph để triage sau khi evidence đã đủ mạnh.
5. Dùng benchmark và SARIF để chứng minh giá trị khoa học và giá trị sản phẩm.

---

## 3. Hiện trạng kỹ thuật của repo sau đợt nâng cấp gần đây

Đối chiếu với code hiện tại, Aegis-SAST đã có các thành phần đáng kể:

- AST parsing đa ngôn ngữ bằng Tree-sitter.
- Plugin scanner cho Python, JavaScript, Java và PHP.
- Rule engine dựa trên YAML.
- Taint-style source -> sink tracking.
- Cross-file analysis cho Python.
- Explicit Python flow graph v1 cho CFG/DFG ở mức thực dụng.
- Workflow triage nền tảng theo các bước intake -> normalize -> knowledge -> auditor -> skeptic -> judge -> reporter.
- Exporter JSON, Markdown và SARIF có mang theo workflow metadata.
- Bộ test và manual smoke cho các phần lõi đã được bổ sung.

Tuy nhiên, repo vẫn chưa ở mức một graph-based SAST engine hoàn chỉnh. Các khoảng trống lớn còn lại là:

- DFG/CFG hiện mới ở bản explicit graph v1 cho Python, chưa phải inter-procedural graph engine hoàn chỉnh;
- benchmark đối chứng chưa hoàn chỉnh;
- Python vẫn là ngôn ngữ duy nhất đủ tiềm năng để đi sâu về evidence;
- các ngôn ngữ còn lại chủ yếu vẫn ở mức intra-file/pattern-level.

Vì vậy, cách mô tả đúng nhất ở thời điểm hiện tại là:

> Aegis-SAST là một scanner AST-based đa ngôn ngữ đã bắt đầu có explicit Python CFG/DFG graph, có Python cross-file analysis, workflow triage nền tảng và report exporter khá đầy đủ, nhưng chưa phải một SAST engine học thuật hoàn chỉnh ở mức inter-procedural dataflow/control-flow sâu.

---

## 4. Vì sao AST một mình là chưa đủ

AST trả lời được câu hỏi “mã nguồn được viết như thế nào theo cấu trúc cú pháp”, nhưng chưa trả lời tốt các câu hỏi:

- dữ liệu có thật sự truyền từ source đến sink hay không;
- sanitizer có nằm trên đúng đường đi đến sink hay không;
- nhánh nào là reachable, nhánh nào là dead path;
- return sớm hoặc guard clause có loại bỏ được khả năng kích hoạt sink hay không.

Nếu chỉ dừng ở AST và pattern matching, hệ thống có thể phát hiện được nhiều trường hợp rõ ràng, nhưng sẽ sớm chạm trần ở bài toán giảm false positive. Đây chính là lý do đề tài cần bước sang DFG-lite và CFG-lite.

---

## 5. Vai trò của DFG-lite trong đề tài

### 5.1. DFG trả lời điều gì

DFG trả lời câu hỏi: “dữ liệu đi từ biến nào sang biến nào”.

### 5.2. Giá trị thực dụng của DFG-lite cho Aegis-SAST

Đề tài không cần một đồ thị dữ liệu hoàn chỉnh theo nghĩa học thuật cho mọi ngôn ngữ. Mục tiêu hợp lý hơn là một `DFG-lite` cho Python, tập trung vào:

- assignment từ biến sang biến;
- argument -> parameter;
- return value -> biến nhận;
- tóm tắt path evidence để dùng trong triage.

### 5.3. Tác động mong đợi

`DFG-lite` giúp:

- làm rõ dataflow trace;
- giảm false positive ở các finding bị AST bắt quá rộng;
- cung cấp evidence tốt hơn cho Auditor và Judge trong workflow triage.

---

## 6. Vai trò của CFG-lite trong đề tài

### 6.1. CFG trả lời điều gì

CFG trả lời câu hỏi: “chương trình có thể đi theo những nhánh điều khiển nào”.

### 6.2. Giá trị thực dụng của CFG-lite cho Aegis-SAST

Trong đề tài này, `CFG-lite` cho Python nên tập trung vào đúng những phần tác động mạnh đến false positive:

- branch-aware path;
- guard clause và return sớm;
- sanitizer reachability;
- loại bỏ những path không hợp lệ rõ ràng.

### 6.3. Tác động mong đợi

`CFG-lite` giúp:

- biết sanitizer xảy ra trước hay sau sink;
- biết nhánh nào mới thực sự dẫn đến sink;
- cải thiện path sensitivity;
- nâng chất lượng explanation và triage status.

---

## 7. Quan hệ giữa Call Graph, DFG-lite, CFG-lite và Agent

Ba lớp reasoning này không thay thế nhau:

- **Call Graph** giúp đi xuyên hàm và xuyên tệp.
- **DFG-lite** giúp theo dõi truyền dữ liệu.
- **CFG-lite** giúp xác định đường đi điều khiển có hợp lệ hay không.
- **Agent workflow** giúp phản biện, diễn giải và ra quyết định triage sau khi đã có evidence.

Nói ngắn gọn:

> Agent không nên xuất hiện quá sớm khi evidence còn yếu. Agent chỉ thực sự có giá trị khi finding đã có AST + dataflow + control-flow ở mức đủ dùng.

---

## 8. Thứ tự nâng cấp phù hợp nhất

### Giai đoạn 1: Schema và Evidence

Phải làm trước:

- chuẩn hóa `NormalizedFinding`;
- chuẩn hóa `EvidenceBundle`;
- tách rõ source, sink, sanitizer, path summary;
- bổ sung triage status và workflow metadata.

Nếu chưa có schema và evidence tốt thì benchmark và agent đều yếu.

### Giai đoạn 2: DFG-lite cho Python

Phải làm tiếp:

- assignment tracking;
- argument -> parameter;
- return -> variable;
- dataflow summary rõ hơn.

Mục tiêu không phải là vẽ đồ thị đẹp, mà là tạo bằng chứng dữ liệu tốt hơn cho finding.

### Giai đoạn 3: CFG-lite cho Python

Chỉ bổ sung những gì tác động trực tiếp đến false positive:

- branch-aware reasoning;
- sanitizer reachability;
- dead-path filtering;
- guard clause và return sớm.

### Giai đoạn 4: Workflow LangGraph cho triage

Khi evidence đã đủ mạnh, workflow agent mới thật sự có ý nghĩa:

- Planner
- KnowledgeLoader
- Auditor
- SkepticValidator
- Judge
- Reporter

### Giai đoạn 5: SARIF và benchmark

Khi scanner và triage đã đủ ổn định:

- xuất SARIF;
- chạy baseline với Semgrep;
- nếu kịp, bổ sung một phạm vi hẹp với CodeQL;
- thực hiện ablation study.

---

## 9. Chiến lược theo từng ngôn ngữ

### 9.1. Python

Python là ngôn ngữ đi sâu nhất của đề tài. Đây là nơi nên đầu tư:

- AST
- taint propagation
- call graph
- DFG-lite
- CFG-lite
- đầy đủ evidence cho triage
- benchmark chính

### 9.2. JavaScript

Giữ ở mức:

- AST parsing
- rule-based detection
- evidence ở mức pattern-level
- triage ở mức cơ bản

### 9.3. Java

Giữ ở mức:

- AST/rule-based scanning
- dùng cho benchmark mở rộng
- không đặt mục tiêu graph reasoning sâu trong 3 tháng

### 9.4. PHP

Giữ ở mức:

- AST parsing
- rule matching
- normalized finding
- triage mức cơ bản

Kết luận quan trọng là: **đa ngôn ngữ ở mức kiến trúc, nhưng chiều sâu phân tích chỉ tập trung mạnh ở Python**.

---

## 10. Mapping vào phân công Quân và Tuệ

### 10.1. Phần việc chính của Quân

Quân phù hợp phụ trách:

- scanner core;
- normalized finding và evidence bundle;
- Python DFG-lite;
- Python CFG-lite;
- call graph refinement;
- SARIF;
- benchmark harness;
- baseline comparison.

### 10.2. Phần việc chính của Tuệ

Tuệ phù hợp phụ trách:

- LangGraph orchestration;
- knowledge cards;
- knowledge loader;
- triage prompts và structured outputs;
- skeptical validation loop;
- ablation study liên quan đến knowledge và workflow.

---

## 11. Cách trình bày đề tài với giảng viên

Khi trình bày, nên nói theo logic sau:

1. Aegis-SAST hiện đã có scanner AST-based đa ngôn ngữ, cross-file cho Python và workflow triage seed.
2. Hạn chế lớn nhất hiện nay là evidence chưa đủ sâu để giảm false positive một cách thuyết phục.
3. Đóng góp kỹ thuật của đề tài là nâng hệ thống theo hướng:
   - Evidence-aware SAST
   - DFG-lite + CFG-lite cho Python
   - LangGraph AI triage
   - SARIF + benchmark đối chứng
4. Đóng góp nghiên cứu nằm ở chỗ lượng hóa hiệu quả của từng lớp bằng ablation study.

Nếu trình bày như vậy, đề tài vừa có chiều sâu kỹ thuật, vừa có giá trị nghiên cứu, lại không bị overclaim so với repo thực tế.

---

## 12. Kết luận

Aegis-SAST không nên dừng ở AST-only nếu mục tiêu là khóa luận lớn hoặc NCKH. Tuy nhiên, hướng đi đúng không phải là viết full graph engine cho mọi ngôn ngữ, mà là:

- giữ AST làm nền;
- đầu tư DFG-lite và CFG-lite cho Python;
- giữ Call Graph làm trục xuyên hàm/xuyên tệp;
- dùng LangGraph cho triage sau khi evidence đủ mạnh;
- dùng benchmark và SARIF để chứng minh giá trị hệ thống.

Do đó, câu trả lời thực tế cho câu hỏi “ngoài AST có cần CFG và DFG không?” là:

> Có. Nhưng cần triển khai theo thứ tự, tập trung vào Python trước và chỉ làm ở mức `lite` đủ để cải thiện false positive, explanation và benchmark.

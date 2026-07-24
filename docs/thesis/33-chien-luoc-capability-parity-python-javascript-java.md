# Chiến lược capability parity cho Python, JavaScript và Java

## 1. Mục tiêu của tài liệu này

Tài liệu này chốt lại một thay đổi quan trọng về định hướng phát triển Aegis-SAST trong giai đoạn khóa luận và nghiên cứu khoa học:

- không dừng ở mô hình `Python sâu, JavaScript/Java chỉ để minh họa`;
- chuyển sang mô hình `capability parity`, tức là các ngôn ngữ chính phải đi qua cùng một thang năng lực kỹ thuật;
- agent AI phải làm việc trên cùng một contract finding/evidence, không được thiết kế riêng cho Python.

Trong phạm vi hiện tại, ba ngôn ngữ chính được chốt là:

1. Python
2. JavaScript
3. Java

PHP được giữ ở mức tương thích kiến trúc và không phải trọng tâm nâng cấp chính trong đợt này.

---

## 2. "Như nhau" ở đây phải hiểu như thế nào

Nếu nói "mọi ngôn ngữ như nhau" theo nghĩa:

- dùng cùng parser,
- dùng cùng graph engine,
- dùng cùng framework model,
- có cùng độ phủ thư viện,

thì điều đó không thực tế trong 4-6 tháng.

Cách hiểu đúng và khả thi hơn là:

- **như nhau về chuẩn đầu ra**;
- **như nhau về thang năng lực**;
- **như nhau về workflow agent**;
- **như nhau về cách benchmark và đánh giá**.

Nói cách khác, mỗi ngôn ngữ có thể khác nhau ở chi tiết cài đặt, nhưng phải cùng đạt được các lớp năng lực cốt lõi sau.

---

## 3. Thang năng lực chung cho 3 ngôn ngữ

### Lớp 1. AST và rule matching

Mỗi plugin phải:

- parse được source code ổn định;
- nhận diện source, sink, sanitizer;
- phát sinh finding ban đầu với `rule_id`, `language`, `severity`, `message`.

### Lớp 2. Evidence thống nhất

Mỗi finding phải được chuẩn hóa về:

- `NormalizedFinding`;
- `EvidenceBundle`;
- `source`;
- `sink`;
- `sanitizers`;
- `path_summary`;
- `supporting_steps`;
- `triage_status`.

### Lớp 3. DFG-lite

Mỗi ngôn ngữ phải có tối thiểu:

- assignment flow;
- argument -> parameter flow;
- return -> receiving variable flow;
- path steps đủ rõ để AI hiểu được dòng dữ liệu đi như thế nào.

### Lớp 4. CFG-lite

Mỗi ngôn ngữ phải có tối thiểu:

- branch-aware path;
- early return / guard clause handling;
- sanitizer reachability;
- loại bỏ các path không còn reachable rõ ràng.

### Lớp 5. Agent triage

Tất cả finding từ Python, JavaScript và Java phải đi qua cùng workflow:

1. `Planner`
2. `KnowledgeLoader`
3. `Auditor`
4. `SkepticValidator`
5. `Judge`
6. `Reporter`

### Lớp 6. Benchmark và baseline

Mỗi ngôn ngữ chính đều phải có:

- sample set có nhãn;
- smoke test;
- benchmark mini;
- baseline đối chứng ít nhất với Semgrep nếu có thể map được.

---

## 4. Ma trận hiện trạng và đích đến

| Ngôn ngữ | Hiện trạng | Đích đến trong khóa luận |
|---|---|---|
| Python | Mạnh nhất, đã có graph core, function summary, benchmark mini | Giữ lợi thế hiện tại nhưng phải quy về cùng contract với JS/Java và làm mẫu chuẩn cho parity |
| JavaScript | Mới ở mức intra-file và heuristics cơ bản | Nâng lên đủ `EvidenceBundle`, `DFG-lite`, `CFG-lite`, agent triage và benchmark mini |
| Java | Mới ở mức intra-file và heuristics cơ bản | Nâng lên đủ `EvidenceBundle`, `DFG-lite`, `CFG-lite`, agent triage và benchmark mini |
| PHP | Có plugin nền tảng | Giữ tương thích, chưa bắt buộc đi hết mọi lớp năng lực trong giai đoạn này |

Điểm quan trọng là:

- **Python không còn là đích duy nhất**;
- **JavaScript và Java không còn chỉ là phần phụ để trình diễn**;
- **agent không được thiết kế theo kiểu chỉ đọc evidence Python**.

---

## 5. Contract kỹ thuật bắt buộc giữa core và agent

Để AI làm việc đa ngôn ngữ thật sự, Quân và Tuệ phải chốt một contract chung.

### 5.1. Phần Quân phải cung cấp

Mỗi finding của Python, JavaScript, Java cần có tối thiểu:

- `language`
- `rule_id`
- `category`
- `cwe_id`
- `severity`
- `confidence`
- `source`
- `sink`
- `sanitizers`
- `path_summary`
- `supporting_steps`
- `framework_hints`
- `file`, `line`, `column`

### 5.2. Phần Tuệ phải tiêu thụ

Workflow AI không được phụ thuộc vào tên plugin cụ thể, mà chỉ đọc:

- `NormalizedFinding`
- `EvidenceBundle`
- knowledge cards theo `language + CWE + vuln_type`
- triage rubric dùng chung

### 5.3. Hệ quả kiến trúc

Nếu contract này ổn định thì:

- có thể đổi scanner backend mà không phải viết lại toàn bộ agent;
- có thể benchmark công bằng giữa các ngôn ngữ;
- có thể thêm Semgrep adapter rồi đưa finding vào cùng workflow triage.

---

## 6. Các phần agent phải build để hỗ trợ parity đa ngôn ngữ

### 6.1. Planner

- đọc `language`, `framework_hints`, `severity`, `vuln_type`;
- chọn route xử lý phù hợp;
- không hard-code riêng cho Python.

### 6.2. KnowledgeLoader

- nạp card theo `language + CWE`;
- nạp sanitizer rubric theo ngôn ngữ;
- nạp false-positive pattern riêng cho Python, JavaScript, Java.

### 6.3. Auditor

- đọc evidence và tóm tắt luận điểm buộc tội;
- chỉ ra source, sink, path, sanitizer;
- không được kết luận chỉ vì rule match.

### 6.4. SkepticValidator

- tìm phản ví dụ hoặc điều kiện làm finding yếu đi;
- kiểm tra guard clause;
- kiểm tra sanitizer nằm trên path;
- kiểm tra evidence có bị đứt đoạn hay không.

### 6.5. Judge

- gom kết quả từ Auditor và Skeptic;
- gán `confirmed`, `likely`, `needs-review`, `suppressed`;
- xuất confidence và lý do quyết định.

### 6.6. Reporter

- chuẩn hóa explanation;
- ghi route workflow;
- giữ JSON, Markdown, SARIF cùng một logic triage.

---

## 7. Phân công theo capability parity

## 7.1. Quân phụ trách

- chuẩn hóa `NormalizedFinding` và `EvidenceBundle`;
- phát triển DFG-lite cho Python, JavaScript, Java;
- phát triển CFG-lite cho Python, JavaScript, Java;
- xây sample set và benchmark mini cho cả ba ngôn ngữ;
- map Semgrep findings vào cùng schema;
- duy trì JSON, Markdown, SARIF;
- tích hợp CLI, smoke tests, dataset và baseline.

## 7.2. Tuệ phụ trách

- thiết kế LangGraph workflow language-agnostic;
- xây knowledge cards theo `language + CWE + vuln_type`;
- xây prompt và structured output cho từng node;
- tích hợp Local LLM / RAG nếu kịp;
- đánh giá static-only vs static + AI trên cả ba ngôn ngữ;
- đánh giá single-prompt vs workflow;
- đánh giá no-knowledge vs knowledge-assisted.

---

## 8. Thứ tự triển khai nên làm

### Giai đoạn 1. Chuẩn hóa schema và evidence

Phải xong trước:

- `NormalizedFinding`
- `EvidenceBundle`
- metadata benchmark
- schema output thống nhất cho Python, JavaScript, Java

### Giai đoạn 2. DFG-lite cho cả 3 ngôn ngữ

Phải có tối thiểu:

- assignment flow
- argument flow
- return flow
- path summary

### Giai đoạn 3. CFG-lite cho cả 3 ngôn ngữ

Ưu tiên:

- `if/else`
- early return
- guard clause
- sanitizer reachability

### Giai đoạn 4. LangGraph workflow đa ngôn ngữ

Lúc này agent mới thực sự có giá trị vì:

- evidence đã đủ mạnh;
- Python, JavaScript, Java có cùng contract;
- knowledge layer có thể chọn card đúng theo ngôn ngữ.

### Giai đoạn 5. Benchmark và baseline

Bắt buộc phải có:

- benchmark mini theo từng ngôn ngữ;
- benchmark gộp đa ngôn ngữ;
- baseline Semgrep;
- ablation `core-only` vs `core + AI`.

---

## 9. Cách trình bày với giảng viên và hội đồng

Nếu theo chiến lược này, cách nói chuẩn là:

- hiện tại hệ thống chưa đồng đều giữa các ngôn ngữ;
- mục tiêu nghiên cứu của giai đoạn tiếp theo là thu hẹp khoảng cách đó;
- đề tài chọn Python, JavaScript, Java làm ba ngôn ngữ chính để đạt capability parity;
- PHP được giữ ở mức tương thích để tránh vỡ scope;
- đóng góp kỹ thuật không nằm ở việc "hỗ trợ rất nhiều ngôn ngữ", mà nằm ở việc xây được một khung phân tích và triage thống nhất cho nhiều ngôn ngữ.

Đây là cách nói vừa tham vọng, vừa kỹ thuật, vừa an toàn khi bảo vệ.

---

## 10. Kết luận

Nếu muốn Aegis-SAST lên mức khóa luận mạnh và có cửa đi tiếp sang nghiên cứu khoa học, thì mục tiêu đúng không phải là:

- Python quá sâu còn ngôn ngữ khác chỉ để minh họa;

mà là:

- Python, JavaScript và Java cùng đi qua một chuẩn năng lực phân tích;
- AI workflow làm việc thống nhất trên cả ba;
- benchmark và baseline chứng minh được giá trị trên cả ba.

Đó mới là hướng "đa ngôn ngữ thật" và cũng là hướng phù hợp nhất với mong muốn làm dự án lớn, khó và có chiều sâu nghiên cứu.

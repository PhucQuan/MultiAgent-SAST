# Báo cáo tiến độ Aegis-SAST và định hướng phát triển tiếp theo

## 1. Mục đích của tài liệu

Tài liệu này được viết để phục vụ trực tiếp cho buổi báo cáo tiến độ với giảng viên hướng dẫn. Nội dung tập trung vào bốn câu hỏi chính mà giảng viên thường quan tâm:

1. Nhóm đã làm được những gì ở thời điểm hiện tại.
2. Hệ thống đang hoạt động ra sao về mặt kiến trúc và thực nghiệm.
3. Các kết quả benchmark hiện tại nói lên điều gì.
4. Hướng phát triển tiếp theo của đề tài là gì, và cần ưu tiên phần nào trước.

Tài liệu được viết theo văn phong báo cáo, có thể dùng trực tiếp để gửi giảng viên đọc hoặc làm khung nói khi thuyết trình.

## 2. Tóm tắt ngắn gọn hiện trạng dự án

Tại thời điểm hiện tại, Aegis-SAST đã vượt qua mức một bản demo ý tưởng đơn thuần và đã hình thành được một hệ thống SAST có lõi phân tích riêng, có benchmark, có baseline đối chứng và có lớp hiển thị sản phẩm phục vụ demo.

Định hướng kỹ thuật hiện tại của hệ thống là một mô hình **hybrid SAST**, trong đó:

- lớp phát hiện chính vẫn là **deterministic static analysis** dựa trên AST, rule và data-flow analysis;
- lớp AI được đặt ở **triage layer**, không thay thế detector chính;
- lớp sản phẩm gồm report exporter và dashboard local để hỗ trợ đọc kết quả, lọc finding và reviewer workflow;
- phần đánh giá học thuật được thực hiện bằng benchmark OWASP và baseline Semgrep để so sánh công bằng.

Nói cách khác, đề tài hiện không được định vị là “LLM thay hoàn toàn static analysis”, mà là “xây một scanner core có thể benchmark được, sau đó đưa AI và multi-agent vào đúng lớp triage để giảm false positive và tăng khả năng sử dụng thực tế”.

## 3. Những gì nhóm đã hoàn thành

### 3.1. Hoàn thành lớp scanner core

Nhóm đã xây được một detector core hoạt động thực sự, không phụ thuộc vào Semgrep ở runtime mặc định. Lõi hiện tại có các thành phần chính sau:

- parser theo hướng AST với kiến trúc plugin đa ngôn ngữ;
- rule engine để nạp và áp dụng tập luật;
- khả năng trích xuất source, sink, sanitizer và evidence liên quan;
- data-flow và taint-oriented reasoning, trong đó lane Python hiện là lane mạnh nhất.

Các ngôn ngữ đã có plugin riêng gồm:

- Python
- Java
- JavaScript
- PHP

Tuy nhiên, mức trưởng thành giữa các lane hiện chưa đồng đều; Python đang là lane sâu nhất và đáng dùng nhất để làm trọng tâm báo cáo học thuật.

### 3.2. Tách orchestration ra khỏi CLI

Một bước kỹ thuật quan trọng đã hoàn thành là tách orchestration ra khỏi `cli.py`, đưa luồng điều phối scan sang service riêng. Điều này giúp:

- CLI chỉ còn vai trò nhận tham số và hiển thị kết quả;
- pipeline có thể tái sử dụng cho dashboard hoặc API về sau;
- kiến trúc sạch hơn và dễ mở rộng hơn khi tiếp tục phát triển.

Đây là một thay đổi quan trọng vì nó cho thấy hệ thống đã bắt đầu tách lớp đúng hướng, thay vì dồn toàn bộ logic vào một entrypoint dòng lệnh.

### 3.3. Chuẩn hóa finding và workflow triage

Nhóm đã có nền tảng finding normalization và workflow triage với các vai trò:

- `Auditor`
- `Skeptic`
- `Judge`

Các thành phần này hiện giúp hệ thống:

- giữ finding ở một schema nhất quán;
- gắn metadata như severity, type, evidence, triage status;
- chuẩn bị nền cho hướng multi-agent trong triage layer.

Quan trọng hơn, hệ thống hiện đã có cách tổ chức phù hợp với hướng LangGraph-ready workflow, tức là có thể ánh xạ các node đánh giá sang graph orchestration về sau. Tuy nhiên, ở giai đoạn hiện tại, điều đúng nhất cần nói là:

> Hệ thống đã có workflow multi-agent ở mức kiến trúc và code structure, nhưng chưa nên claim là đã hoàn thiện một LangGraph orchestration end-to-end cho toàn bộ pipeline.

Nếu cần giải thích theo cách dễ hiểu hơn với giảng viên, có thể diễn đạt như sau:

- `Auditor` đóng vai trò gần với một bên **buộc tội**, tức là đọc evidence và cố chứng minh finding là lỗi thật;
- `Skeptic` đóng vai trò gần với một bên **phản biện**, tức là đi tìm sanitizer, guard clause, dữ liệu nội bộ hoặc các dấu hiệu cho thấy finding có thể là false positive;
- `Judge` là tầng **chốt quyết định**, tổng hợp hai phía và đưa ra `status`, `confidence`, `reason_codes`, explanation.

Điểm quan trọng của cách tổ chức này là nó đưa Aegis-SAST từ chỗ “scan xong rồi in ra” sang chỗ có một **cơ chế phản biện có phân vai**. Điều này giúp đề tài có màu sắc multi-agent rõ hơn, nhưng vẫn giữ được ranh giới an toàn: multi-agent được dùng ở lớp triage, không thay thế detector deterministic.

### 3.4. Tích hợp AI ở lớp triage

Nhóm đã tích hợp AI runner và client cho Gemini, đồng thời bổ sung OpenAI-compatible adapter để mở đường cho việc dùng local model hoặc runtime tương thích về sau.

Điều này có nghĩa là:

- AI đã có vị trí rõ ràng trong kiến trúc;
- AI được dùng theo hướng review và triage finding;
- deterministic core vẫn là lớp phát hiện chính.

Hiện tại, chưa nên nói rằng AI đã tạo ra cải thiện benchmark ổn định, vì trong các lần chạy gần đây AI bị ảnh hưởng bởi quota/runtime và thường rơi về deterministic fallback.

### 3.5. Hoàn thành lớp report và dashboard

Hệ thống hiện đã xuất được:

- JSON
- Markdown
- SARIF

Ngoài ra, nhóm đã xây dựng dashboard local để:

- mở report đã scan;
- xem danh sách finding;
- lọc theo severity, status, family, language;
- xem chi tiết finding;
- theo dõi local scan trong dashboard;
- chuẩn bị nền cho reviewer memory.

Dashboard hiện là lớp sản phẩm hỗ trợ demo và reviewer workflow, không phải detector UI gắn trực tiếp vào engine scan. Cách tách lớp này là phù hợp và nên được nhấn mạnh khi báo cáo.

### 3.6. Hoàn thành benchmark harness và baseline so sánh

Nhóm đã hoàn thành hai thành phần rất quan trọng về mặt học thuật:

- một script chấm điểm báo cáo theo ground truth OWASP Benchmark;
- một baseline runner để chạy Semgrep trên cùng tập benchmark và chấm bằng cùng một harness.

Điều này giúp đề tài có khả năng đánh giá khách quan hơn, thay vì chỉ dừng ở việc “tool chạy ra bao nhiêu finding”.

## 4. Diễn giải kết quả benchmark hiện tại

### 4.1. Phạm vi benchmark đang dùng để báo cáo

Hiện tại, phạm vi claim mạnh nhất của đề tài nên tập trung vào lane Python với bốn family chính:

- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`
- `SQL_INJECTION`

Lý do chọn bốn family này là vì đây là nhóm đã có:

- detector hoạt động tương đối tốt;
- benchmark rõ ràng trên OWASP Benchmark Python;
- baseline so sánh với Semgrep;
- kết quả đủ mạnh để trình bày trong thesis V1.

### 4.2. Giải thích đúng các dòng trong bảng benchmark

Khi chạy benchmark trên `D:\BenchmarkPython\testcode`, bảng điểm hiện tại của Aegis cho các thông số chính:

- `Files scanned = 1230`
- `Report findings = 190`
- `Expected cases = 258`

Ba con số này có ý nghĩa khác nhau:

- `Files scanned` là số file mã nguồn đã được hệ thống quét.
- `Report findings` là số cảnh báo thô mà detector tạo ra.
- `Expected cases` là số benchmark case thuộc các family đã chọn trong file ground truth.

Điểm quan trọng cần giải thích rõ là:

> Benchmark không chấm theo số finding thô, mà chấm theo mức độ khớp với các benchmark case trong ground truth. Vì vậy, số `190 findings` không cần bằng tổng `TP + FP + FN`.

Lý do là vì nhiều finding thô có thể cùng trỏ về một benchmark case, hoặc một finding có thể bị loại khỏi scoring nếu không ánh xạ được vào case ID phù hợp.

### 4.3. Kết quả tổng hợp của Aegis native trên 4 family

Kết quả hiện tại của Aegis native là:

| Chỉ số | Giá trị |
|---|---:|
| TP | 85 |
| FP | 56 |
| FN | 16 |
| Precision | 0.6028 |
| Recall | 0.8416 |
| F1 | 0.7025 |

Đây là kết quả tốt theo hướng sau:

- hệ thống bắt được nhiều case thật;
- recall đạt mức cao;
- F1 tổng thể tốt hơn baseline Semgrep trong cùng điều kiện benchmark.

Tuy nhiên, precision hiện chưa thật sự cao, cho thấy hệ thống vẫn còn nhiễu ở một số family.

### 4.4. Ý nghĩa của ba dòng `All findings`, `Visible after triage`, `High confidence`

Trong bảng hiện tại, cả ba dòng:

- `All findings`
- `Visible after triage`
- `High confidence`

đều cho kết quả giống nhau hoàn toàn.

Điều này có nghĩa là:

- workflow triage đã có mặt trong kiến trúc;
- nhưng ở giai đoạn benchmark hiện tại, lớp triage chưa tạo ra sự khác biệt định lượng rõ rệt giữa các mức hiển thị;
- hệ thống chưa thật sự lọc được finding thành các nhóm “toàn bộ”, “giữ lại để reviewer xem”, và “mức tự tin cao”.

Đây là một hạn chế cần nói trung thực khi báo cáo. Tuy nhiên, chính hạn chế này cũng làm rõ hướng phát triển tiếp theo của đề tài: biến triage từ “lớp có kiến trúc” thành “lớp có tác động đo được”.

### 4.5. Diễn giải theo từng family

#### COMMAND_INJECTION

| TP | FP | FN | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|
| 13 | 4 | 0 | 0.7647 | 1.0000 | 0.8667 |

Đây là family mạnh của hệ thống. Aegis bắt đủ toàn bộ case thật trong benchmark hiện tại của family này. Precision chưa tuyệt đối vì vẫn còn 4 false positive, nhưng nhìn chung đây là một kết quả rất tốt và có thể dùng để chứng minh detector core có giá trị thực tế.

#### PATH_TRAVERSAL

| TP | FP | FN | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|
| 52 | 46 | 13 | 0.5306 | 0.8000 | 0.6380 |

Đây là điểm yếu lớn nhất hiện tại. Hệ thống bắt được khá nhiều case thật, nghĩa là detector có độ phủ tốt, nhưng false positive còn cao. Vì vậy, family này là ưu tiên số một cần tối ưu ở giai đoạn tới.

Khi báo cáo, nên nói thẳng:

> Điểm đau lớn nhất của Aegis native ở thời điểm hiện tại là Path Traversal: detector có độ phủ khá tốt nhưng còn nhiễu cao, nên cần tập trung giảm false positive trước khi mở rộng claim mạnh hơn.

#### INSECURE_DESERIALIZATION

| TP | FP | FN | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|
| 15 | 6 | 3 | 0.7143 | 0.8333 | 0.7692 |

Kết quả của family này tương đối tốt, cân bằng hơn giữa recall và precision. Đây là family có thể tiếp tục giữ trong thesis V1.

#### SQL_INJECTION

| TP | FP | FN | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|
| 5 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

Đây là family mạnh nhất ở benchmark hiện tại. Detector native bắt đủ và không tạo false positive trong tập 4 family đã chọn.

## 5. So sánh trực tiếp với Semgrep baseline

Khi chạy Semgrep raw trên cùng OWASP Benchmark Python, cùng family và cùng harness chấm điểm, kết quả baseline hiện tại là:

| Hệ thống | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Semgrep raw | 27 | 14 | 74 | 0.6585 | 0.2673 | 0.3803 |
| Aegis native | 85 | 56 | 16 | 0.6028 | 0.8416 | 0.7025 |

Kết luận từ bảng này cần được đọc đúng như sau:

- Semgrep raw có precision nhỉnh hơn một chút.
- Tuy nhiên, Semgrep bỏ sót rất nhiều case thật, nên recall thấp.
- Aegis native phát hiện được nhiều case thật hơn rất rõ, nên F1 tổng thể cao hơn đáng kể.

Nói gọn hơn:

> Trên cùng benchmark và cùng cách chấm điểm, Aegis native hiện đang có ưu thế rõ rệt về recall và F1 so với Semgrep baseline, đổi lại mức nhiễu vẫn còn cao hơn ở một số family, đặc biệt là Path Traversal.

Đây là một điểm rất đáng giá về mặt học thuật, vì nó chứng minh rằng detector native của Aegis không chỉ “chạy được”, mà còn tạo ra kết quả cạnh tranh và thậm chí vượt baseline trong phạm vi nghiên cứu đã chọn.

## 6. Nhóm đã làm được gì để có kết quả này

Nếu giảng viên hỏi cụ thể “từ đầu đến giờ các em đã thực sự làm được gì”, có thể trả lời theo các ý dưới đây:

1. Đã xây dựng scanner core dựa trên AST, rule và data-flow analysis, có plugin cho nhiều ngôn ngữ.
2. Đã làm mạnh lane Python để có thể benchmark thực chất trên OWASP Benchmark.
3. Đã tách orchestration ra khỏi CLI để hệ thống dễ mở rộng hơn.
4. Đã chuẩn hóa finding và xây dựng workflow triage với các vai trò Auditor, Skeptic, Judge.
5. Đã tích hợp AI vào kiến trúc triage theo hướng multi-agent, dù chưa claim hiệu quả benchmark ổn định.
6. Đã xây dựng report exporter và dashboard local để trình diễn và review finding.
7. Đã hoàn thiện benchmark harness theo ground truth và chạy baseline Semgrep để đối chiếu công bằng.

Nếu cần nói thành một đoạn hoàn chỉnh:

> Đến thời điểm hiện tại, nhóm em đã hoàn thiện được lõi scanner của Aegis-SAST theo hướng deterministic static analysis, có plugin đa ngôn ngữ, có rule engine và data-flow analysis. Nhóm em cũng đã chuẩn hóa finding, tách orchestration ra khỏi CLI, xây dựng workflow triage theo hướng multi-agent, xuất report JSON/Markdown/SARIF và làm dashboard local để đọc kết quả. Về mặt thực nghiệm, nhóm em đã benchmark được trên OWASP Benchmark Python và có baseline Semgrep để so sánh công bằng.

## 7. Những gì chưa nên claim quá sớm

Để báo cáo trung thực và an toàn, cần tránh nói quá mức ở các điểm sau:

1. Không nên nói AI đã cải thiện benchmark ổn định.
2. Không nên nói triage hiện đã lọc finding hiệu quả thành nhiều lớp định lượng khác nhau, vì ba mode điểm hiện còn trùng nhau.
3. Không nên nói LangGraph orchestration đã hoàn thiện end-to-end cho toàn bộ hệ thống.
4. Không nên nói Java hiện đã là lane mạnh tương đương Python.
5. Không nên nói Aegis đã thay thế hoàn toàn detector công nghiệp như Semgrep.

Thay vào đó, cách nói phù hợp hơn là:

> Hệ thống hiện đã có nền tảng AI-assisted triage và multi-agent workflow về mặt kiến trúc, nhưng deterministic core vẫn là nguồn tạo ra kết quả benchmark chính. Phần AI hiện đang ở giai đoạn hoàn thiện để tạo ra hiệu quả lọc finding ổn định hơn.

## 8. Hướng phát triển tiếp theo

### 8.1. Ưu tiên ngắn hạn

Trong ngắn hạn, đề tài nên tập trung vào bốn hướng ưu tiên sau:

1. Giảm false positive cho `PATH_TRAVERSAL`.
2. Làm cho triage thực sự phân tách được `all findings`, `visible findings` và `high-confidence findings`.
3. Tăng giá trị thực tế của dashboard bằng reviewer memory, note, mute/suppress có kiểm soát.
4. Ổn định demo và benchmark pipeline để việc trình bày không phụ thuộc vào may rủi môi trường.

Nếu diễn đạt theo ngôn ngữ multi-agent, thì mục tiêu ngắn hạn chính là hoàn thiện **feedback-loop collaborative agent architecture**, cụ thể:

- làm cho `Auditor` sinh ra lập luận tốt hơn từ evidence bundle;
- làm cho `Skeptic` bác bỏ false positive tốt hơn, nhất là ở các family traversal/path-related;
- làm cho `Judge` thực sự tạo ra khác biệt giữa `all findings`, `visible findings` và `high-confidence findings`;
- đưa reviewer note, suppression pattern và reviewed findings từ dashboard quay trở lại thành **triage memory** cho những lần scan sau.

### 8.2. Ưu tiên trung hạn

Sau khi ổn định Python lane, hướng đi hợp lý tiếp theo là:

- tích hợp thêm detector source theo hướng công nghiệp, đặc biệt là Semgrep adapter;
- giữ Aegis native core như lane nghiên cứu;
- đặt Aegis triage ở lớp trên để tạo thành mô hình hybrid:
  - `Aegis native`
  - `Semgrep raw`
  - `Semgrep + Aegis triage`

Đây là hướng rất phù hợp cho thesis vì vừa giữ được giá trị nghiên cứu, vừa tiến gần hơn đến hướng product hóa.

### 8.3. Ưu tiên dài hạn

Về dài hạn, hệ thống có thể mở rộng theo các hướng:

- diff-aware PR scan;
- reviewer memory lâu dài;
- remediation draft;
- re-scan validation;
- mở rộng sang thêm family như `XSS`, `SSRF`, `XXE`, `LDAP_INJECTION`, `XPATH_INJECTION`, nhưng chỉ khi có benchmark đủ sạch để claim.

## 9. Kịch bản phát biểu ngắn với giảng viên

Đoạn dưới đây có thể dùng gần như nguyên văn khi báo cáo:

> Hiện tại nhóm em đã xây dựng được một hệ thống Aegis-SAST theo hướng hybrid. Lõi phát hiện vẫn là deterministic static analysis dựa trên AST, rule và data-flow analysis, không phụ thuộc hoàn toàn vào LLM. Trên nền đó, nhóm em đã làm được scanner core, chuẩn hóa finding, workflow triage theo hướng multi-agent, report exporter, dashboard local và benchmark harness.  
>  
> Về mặt thực nghiệm, trên OWASP Benchmark Python với bốn family chính gồm Command Injection, Path Traversal, Insecure Deserialization và SQL Injection, Aegis hiện đạt TP bằng 85, FP bằng 56, FN bằng 16, tương ứng recall 0.8416 và F1 0.7025. So với Semgrep baseline chạy trên cùng dữ liệu và cùng cách chấm điểm, Aegis hiện có recall và F1 cao hơn rõ rệt. Tuy nhiên, false positive ở Path Traversal vẫn là điểm yếu lớn nhất.  
>  
> Hướng tiếp theo của nhóm em là giảm false positive cho Path Traversal, làm cho triage thực sự tạo ra khác biệt giữa all findings, visible findings và high-confidence findings, đồng thời phát triển reviewer memory trong dashboard. Sau đó nhóm em sẽ đi theo hướng hybrid hóa thêm với Semgrep như một detector source công nghiệp, còn Aegis tiếp tục phụ trách lớp triage và reviewer workflow.

## 10. Kết luận

Tại thời điểm hiện tại, Aegis-SAST đã có đủ những thành phần quan trọng để được xem là một đề tài có nền tảng kỹ thuật và học thuật rõ ràng:

- có scanner core hoạt động thực sự;
- có kiến trúc tách lớp hợp lý;
- có benchmark bằng ground truth;
- có baseline để so sánh;
- có hướng AI và multi-agent đặt đúng vào triage layer;
- có dashboard để phục vụ demo và product workflow.

Điểm mạnh nổi bật nhất hiện nay là lane Python với bốn family mục tiêu đang cho kết quả benchmark tốt hơn baseline Semgrep về recall và F1 tổng thể. Điểm cần cải thiện rõ nhất là false positive ở Path Traversal và khả năng để triage tạo ra tác động định lượng rõ ràng lên kết quả cuối cùng.

Nếu cần chốt ngắn gọn trong một câu:

> Aegis-SAST hiện đã đi qua giai đoạn demo ý tưởng và đã trở thành một scanner core có thể benchmark được; bước tiếp theo của đề tài là biến lớp triage và AI thành phần thật sự giúp giảm false positive và tăng giá trị sử dụng thực tế của hệ thống.

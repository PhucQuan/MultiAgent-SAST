

## 2. Phần mở đầu

Em chào cô. Hôm nay em xin báo cáo tiến độ hiện tại của đề tài Aegis-SAST, là một hệ thống phân tích mã nguồn tĩnh theo hướng kết hợp giữa lõi quét truyền thống và lớp hỗ trợ AI ở phía trên.

Nếu nói thật ngắn gọn, thì hướng đi của tụi em không phải là làm một công cụ để AI thay hoàn toàn các bộ quét SAST có sẵn, mà là xây một hệ thống có **lõi phân tích tĩnh riêng**, sau đó đặt **AI vào đúng lớp triage và review finding**, để giảm báo động giả, tăng khả năng giải thích, và giúp hệ thống có giá trị sử dụng thực tế hơn.

Lý do tụi em đi theo hướng này là vì khi tìm hiểu các công cụ SAST cũng như các bài báo và các sản phẩm đang triển khai ngoài thực tế, tụi em thấy một vấn đề lặp đi lặp lại là:

- nếu chỉ dùng bộ quét tĩnh truyền thống, thì thường bị nhiều false positive;
- nếu kỳ vọng AI làm hết từ đầu đến cuối, thì rất khó kiểm soát, khó benchmark và khó giữ độ ổn định;
- còn nếu kết hợp hai lớp, tức là detector truyền thống làm phần quét thô, sau đó AI hay workflow review làm phần lọc tinh, thì cách đó hợp lý hơn cho cả nghiên cứu lẫn product hóa.

Vì vậy, đề tài của tụi em hiện đang bám vào đúng hướng đó.

---

## 3. Bài toán mà đề tài đang giải quyết

Bài toán gốc của tụi em là bài toán SAST, tức là kiểm tra mã nguồn để tìm ra các mẫu lỗ hổng bảo mật mà không cần chạy chương trình.

Nhưng nếu nói đúng hơn, bài toán của đề tài không chỉ là “quét ra được lỗ hổng hay không”, mà là ba lớp bài toán nối tiếp nhau:

1. Làm sao phát hiện được các vị trí nghi ngờ trong mã nguồn.
2. Làm sao chuẩn hóa và đánh giá lại các finding đó để biết finding nào đáng tin, finding nào chỉ là nhiễu.
3. Làm sao trình bày kết quả đó theo cách dễ xem, dễ giải thích và có thể tiếp tục mở rộng thành workflow thực tế.

Nghĩa là tụi em không xem SAST chỉ là chuyện có một lệnh scan ra danh sách lỗi, mà xem nó như một pipeline gồm:

- quét,
- chuẩn hóa,
- review,
- báo cáo,
- và đánh giá lại bằng benchmark.

Đó cũng là lý do tại sao từ đầu tới giờ tụi em không chỉ làm phần detector, mà còn làm cả phần triage, report, dashboard và benchmark harness.

---

## 4. Hướng tiếp cận tổng thể của Aegis-SAST

Hiện tại, Aegis-SAST được xây theo hướng hybrid, tức là kết hợp hai phần:

### 4.1. Phần lõi quét

Phần lõi quét hiện vẫn là **phân tích tĩnh có tính quyết định**, nghĩa là:

- dựa trên AST;
- có rule engine;
- có khái niệm source, sink, sanitizer;
- có data-flow hoặc taint-oriented reasoning ở mức phù hợp.

Phần này là lớp tạo ra finding ban đầu.

### 4.2. Phần triage và AI

Sau khi detector quét xong, finding không được xem là kết luận cuối cùng ngay lập tức. Thay vào đó, finding sẽ đi qua lớp triage để:

- chuẩn hóa về một schema thống nhất;
- đánh giá mức độ thuyết phục;
- gắn trạng thái như confirmed, likely, needs review, suppressed;
- sinh explanation;
- chuẩn bị cho reviewer workflow hoặc dashboard.

Trong lớp này, tụi em đặt AI vào đúng vai trò hỗ trợ review chứ không thay detector chính.

### 4.3. Vì sao không dùng AI làm detector chính ngay từ đầu

Chỗ này em xin nói rất rõ vì đây cũng là một điểm dễ bị hỏi.

Nếu dùng AI làm detector chính từ đầu, sẽ có ba vấn đề lớn:

1. Khó benchmark ổn định vì kết quả AI dễ thay đổi theo model, prompt và quota.
2. Khó giải thích vì finding có thể không gắn với source, sink và bằng chứng dữ liệu rõ ràng.
3. Khó kiểm soát phạm vi claim của luận văn, vì lúc đó sẽ rất khó trả lời câu hỏi “vì sao hệ thống kết luận như vậy”.

Do đó, tụi em giữ phần lõi quét là deterministic, rồi mới đặt AI vào lớp review ở phía trên. Cách làm này vừa an toàn hơn, vừa dễ đánh giá hơn.

---

## 5. Kiến trúc hiện tại của hệ thống

Hiện tại, tụi em có thể mô tả hệ thống thành các lớp chính như sau:

### 5.1. Lớp tiếp nhận đầu vào

Lớp này chịu trách nhiệm nhận thư mục mã nguồn hoặc repo cần quét, sau đó xác định:

- ngôn ngữ chính là gì,
- framework nào có khả năng đang được dùng,
- và nên chọn profile quét nào.

Điểm này quan trọng vì nó giúp hệ thống không quét một cách mù quáng, mà có bước “repo intake” trước khi quét.

### 5.2. Lớp detector core

Đây là phần lõi kỹ thuật mà tụi em đã tự xây.

Hiện tại detector core có:

- kiến trúc plugin đa ngôn ngữ;
- rule engine;
- AST parsing;
- logic source/sink;
- reasoning theo data-flow ở một số lane.

Các plugin hiện có cho:

- Python
- Java
- JavaScript
- PHP

Trong bốn lane này thì **Python là lane mạnh nhất** ở thời điểm hiện tại.

### 5.3. Lớp chuẩn hóa finding

Sau khi detector quét xong, toàn bộ finding được đưa về một dạng thống nhất để hệ thống phía sau xử lý dễ hơn.

Trong finding đã chuẩn hóa, tụi em cố gắng giữ các thông tin quan trọng như:

- loại lỗ hổng,
- severity,
- file và dòng,
- source,
- sink,
- bằng chứng,
- metadata phục vụ triage.

### 5.4. Lớp workflow triage

Đây là lớp tụi em đang phát triển theo hướng multi-agent.

Hiện tại trong code có các vai trò chính:

- `Auditor`
- `Skeptic`
- `Judge`

Hiểu đơn giản:

- `Auditor` là người đọc finding ban đầu và đánh giá sơ bộ;
- `Skeptic` là người phản biện, cố tìm lý do vì sao finding đó có thể là false positive;
- `Judge` là người chốt lại trạng thái cuối cùng.

Cách tổ chức này giúp hệ thống đi gần hơn tới tư duy “review có nhiều bước”, thay vì scan xong là in thẳng ra kết quả.

### 5.5. Lớp AI hỗ trợ triage

Hiện tại tụi em đã tích hợp AI vào kiến trúc ở lớp triage. Nghĩa là hệ thống đã có:

- AI runner;
- client cho Gemini;
- adapter theo chuẩn OpenAI-compatible để sau này có thể chạy local bằng Ollama hay LM Studio;
- bridge theo hướng LangGraph-ready.

Điều quan trọng là tụi em **không claim AI đang làm detector chính**, mà nói rõ rằng AI hiện đang ở lớp triage để review finding sau khi detector quét xong.

### 5.5.1. Nếu diễn giải theo ngôn ngữ multi-agent cho dễ hiểu

Nếu cô hỏi cụ thể “multi-agent ở đây là gì”, thì em sẽ không nói kiểu quá lý thuyết, mà giải thích đơn giản như sau:

- tác tử thứ nhất là bên **đọc finding theo hướng buộc tội**, tức là cố chứng minh đây là lỗi thật;
- tác tử thứ hai là bên **phản biện**, tức là cố tìm lý do vì sao finding đó có thể chỉ là false positive;
- tác tử thứ ba là bên **chốt quyết định**, tức là tổng hợp hai phía rồi đưa ra kết luận cuối cùng.

Trong code hiện tại, ba vai trò đó đang được ánh xạ thành:

- `Auditor`: gần với vai trò **Prosecutor**, đọc bằng chứng source, sink, data-flow và cố giải thích vì sao finding này đáng nghi;
- `Skeptic`: gần với vai trò **Defense**, tìm các tín hiệu giảm nhẹ như sanitizer, guard clause, dữ liệu nội bộ, framework protection hoặc mẫu false positive đã biết;
- `Judge`: là tầng tổng hợp cuối cùng, chốt `status`, `confidence`, `reason_codes` và explanation.

Nếu nói theo cách của bài toán nghiên cứu, thì đây không còn là kiểu “gọi một model rồi hỏi có lỗi hay không”, mà là một **cơ chế phản biện có phân vai**. Điểm hay của cách này là nó làm cho quyết định triage có cơ sở hơn, giảm nguy cơ model bị đồng thuận mù quáng với finding ban đầu.

### 5.5.2. Vòng phản hồi trong multi-agent nằm ở đâu

Một điểm nữa em nghĩ nên nói rõ vì khá sát với hướng nghiên cứu hiện nay, đó là **multi-agent không nên dừng ở tranh luận một lần rồi thôi**, mà nên có vòng phản hồi.

Trong Aegis, chỗ này hiện đang đi theo hướng:

- finding đi từ detector sang workflow triage;
- workflow sinh ra quyết định và explanation;
- report được mở trên dashboard để reviewer xem;
- reviewer có thể để note, đánh dấu false positive, needs review hoặc suppress;
- các tín hiệu đó sẽ trở thành **review memory** hoặc **triage memory** cho những lần sau.

Nói ngắn gọn, hướng mà tụi em đang muốn làm không phải chỉ là “nhiều agent nói chuyện với nhau”, mà là **kiến trúc đa tác tử có vòng phản hồi** giữa detector, triage, dashboard và reviewer memory.

### 5.5.3. Nói thế nào để đúng với code hiện tại

Chỗ này em sẽ nói cẩn thận để không bị overclaim:

> Ở thời điểm hiện tại, Aegis-SAST đã có decomposition theo hướng multi-agent tương đối rõ, gồm Auditor, Skeptic và Judge, đồng thời đã có workflow state và route metadata để chuẩn bị cho hướng LangGraph. Tuy nhiên, hệ thống chưa nên claim là đã hoàn thiện một cơ chế tranh biện nhiều vòng hoàn chỉnh hay một feedback loop tự học đầy đủ ở mức production. Đúng hơn thì đây là nền kiến trúc multi-agent đã hình thành và đang được hoàn thiện dần.

### 5.6. Lớp xuất report và dashboard

Hệ thống hiện xuất được:

- JSON
- Markdown
- SARIF

Ngoài ra tụi em còn làm dashboard local để:

- xem report;
- lọc finding theo severity, status, language, family;
- xem chi tiết finding;
- chạy local scan;
- xem tiến trình scan;
- chuẩn bị nền cho reviewer feedback về sau.

Lớp dashboard này là điểm có giá trị trình diễn rất tốt vì cô có thể nhìn thấy hệ thống không chỉ scan được mà còn có cách tiêu thụ kết quả tương đối rõ ràng.

---

## 6. Từ đầu tới giờ tụi em đã làm được những gì

Nếu cô hỏi theo kiểu rất thực tế là “vậy từ đầu tới giờ các em đã làm được gì rồi”, thì em sẽ trả lời theo từng nhóm công việc như sau.

### 6.1. Hoàn thành scanner core

Đây là phần quan trọng nhất.

Tụi em đã xây được một lõi quét riêng của Aegis-SAST thay vì chỉ lấy Semgrep làm detector mặc định. Lõi này hiện đã:

- quét được code thật;
- sinh finding có cấu trúc;
- benchmark được trên dataset chuẩn;
- và là phần tạo ra kết quả tốt nhất hiện tại trên lane Python.

Điểm này rất quan trọng vì nó chứng minh hệ thống không còn là ý tưởng mô phỏng.

### 6.2. Hoàn thành phần tổ chức kiến trúc

Ban đầu nếu toàn bộ logic dồn vào CLI thì sau này sẽ rất khó mở rộng. Vì vậy tụi em đã tách orchestration ra thành service riêng, nghĩa là:

- CLI chỉ là nơi nhận lệnh;
- còn phần chạy pipeline nằm ở lớp dịch vụ riêng.

Nhờ vậy, cùng một pipeline bây giờ có thể dùng cho:

- CLI
- dashboard
- và về sau có thể là API hoặc CI integration

### 6.3. Hoàn thành triage workflow

Tụi em đã có workflow state, trace và các node đánh giá. Điều đó cho phép hệ thống:

- theo dõi từng bước xử lý finding;
- gắn metadata cho từng quyết định;
- tạo nền cho hướng multi-agent rõ ràng hơn.

### 6.4. Hoàn thành report exporter

Hệ thống đã xuất được report ở các định dạng thực tế như JSON, Markdown và SARIF. Điều này giúp kết quả quét không bị khóa cứng trong terminal.

### 6.5. Hoàn thành dashboard local

Tụi em đã có dashboard để mở report, lọc finding, xem chi tiết, chạy local scan và theo dõi tiến trình scan. Đây là phần rất có lợi khi demo, vì cô có thể quan sát hệ thống dưới góc nhìn người sử dụng chứ không chỉ dưới góc nhìn kỹ thuật.

### 6.6. Hoàn thành benchmark harness

Đây là phần có ý nghĩa học thuật lớn nhất sau scanner core.

Tụi em đã viết được script để chấm kết quả quét theo ground truth của OWASP Benchmark. Nghĩa là hệ thống không chỉ “scan ra nhiều hay ít finding”, mà được chấm bằng:

- TP
- FP
- FN
- precision
- recall
- F1

Đây là chỗ rất quan trọng, vì nó làm cho kết quả của đề tài có tính kiểm chứng hơn.

### 6.7. Hoàn thành baseline Semgrep để đối chiếu

Ngoài lõi Aegis, tụi em còn làm runner cho Semgrep baseline để chạy trên cùng benchmark, cùng family, cùng cách chấm điểm. Nhờ đó, khi so sánh Aegis với Semgrep, tụi em không so kiểu cảm tính mà so trong cùng điều kiện.

### 6.8. Hoàn thành nền AI và local LLM adapter

Tụi em cũng đã:

- hỗ trợ cấu hình Gemini tốt hơn;
- thêm adapter OpenAI-compatible;
- chuẩn bị nền cho local LLM;
- và thêm bridge để đi theo hướng LangGraph.

Em nhấn mạnh lại là phần này hiện mới là nền kiến trúc và tích hợp kỹ thuật, chứ chưa phải chỗ tụi em dùng để claim kết quả benchmark.

---

## 7. Kết quả benchmark hiện tại

Đây là phần quan trọng nhất của buổi báo cáo, vì đây là nơi mình chứng minh bằng số liệu.

### 7.1. Phạm vi benchmark chính đang dùng

Hiện tại, phạm vi mà tụi em dùng để báo cáo mạnh nhất là lane Python với bốn family:

- Command Injection
- Path Traversal
- Insecure Deserialization
- SQL Injection

Đây là bốn family mà detector của tụi em đang có bằng chứng tốt nhất, benchmark rõ nhất và đủ sạch để dùng làm claim cho thesis V1.

### 7.2. Giải thích bảng benchmark cho dễ hiểu

Khi chạy trên `BenchmarkPython/testcode`, hệ thống hiện cho các con số như sau:

- quét `1230` file;
- sinh ra `190` finding thô;
- đối chiếu với `258` benchmark case thuộc phạm vi bốn family đang chấm.

Ở đây em xin giải thích rõ một chỗ rất dễ hiểu lầm:

`190 finding` không có nghĩa là hệ thống bắt đúng 190 lỗi. Vì benchmark không chấm theo số finding thô, mà chấm theo **benchmark case** có trong file ground truth. Một benchmark case có thể sinh ra nhiều finding thô, nhưng khi chấm thì vẫn chỉ tính trên mức độ phát hiện đúng hay sai của case đó.

### 7.3. Kết quả tổng hợp của Aegis native

Kết quả hiện tại của Aegis native trên bốn family là:

- `TP = 85`
- `FP = 56`
- `FN = 16`
- `Precision = 0.6028`
- `Recall = 0.8416`
- `F1 = 0.7025`

Nếu đọc những con số này theo nghĩa dễ hiểu thì:

- hệ thống bắt được khá nhiều case thật;
- bỏ sót tương đối ít;
- nhưng vẫn còn một lượng nhiễu nhất định, tức là false positive chưa thấp.

Điểm mạnh rõ nhất ở đây là **recall cao**, nghĩa là detector có độ phủ tốt trên phạm vi mà tụi em đang nghiên cứu.

### 7.4. Đọc theo từng family

#### Command Injection

Ở family này, hệ thống đạt:

- `TP = 13`
- `FP = 4`
- `FN = 0`
- recall `1.0`

Điều này có nghĩa là với benchmark hiện tại, family Command Injection là family mạnh của Aegis. Hệ thống bắt đủ toàn bộ case thật, và chỉ còn một ít false positive.

#### SQL Injection

Ở family này, hệ thống đạt:

- `TP = 5`
- `FP = 0`
- `FN = 0`

Tức là trong tập benchmark hiện tại, SQL Injection là family tốt nhất của tụi em. Detector bắt đúng và không tạo nhiễu ở phạm vi đã chấm.

#### Insecure Deserialization

Family này cũng đang khá ổn:

- `TP = 15`
- `FP = 6`
- `FN = 3`

Tức là vừa có độ phủ khá tốt, vừa chưa nhiễu quá lớn.

#### Path Traversal

Đây là điểm yếu lớn nhất hiện tại:

- `TP = 52`
- `FP = 46`
- `FN = 13`

Khi nhìn vào đây, em không né tránh mà sẽ nói rất thẳng là:

> Path Traversal hiện là điểm đau nhất của hệ thống. Aegis bắt được nhiều case thật, nhưng mức false positive còn cao, nên đây là phần cần ưu tiên tối ưu trong giai đoạn tiếp theo.

---

## 8. So sánh với Semgrep baseline

Đây là phần rất quan trọng vì cô có thể hỏi ngay là: “Vậy lõi của các em so với Semgrep thì sao?”

Khi chạy Semgrep raw trên cùng benchmark, cùng family và cùng harness chấm điểm, kết quả hiện tại là:

- `TP = 27`
- `FP = 14`
- `FN = 74`
- `Precision = 0.6585`
- `Recall = 0.2673`
- `F1 = 0.3803`

Còn Aegis native là:

- `TP = 85`
- `FP = 56`
- `FN = 16`
- `Precision = 0.6028`
- `Recall = 0.8416`
- `F1 = 0.7025`

Nếu đọc kết quả này cho dễ hiểu thì:

- Semgrep sạch hơn một chút, vì precision của nó cao hơn một ít.
- Nhưng Semgrep bỏ sót rất nhiều case thật trong phạm vi bốn family này.
- Aegis hiện bắt được nhiều true case hơn rất rõ, nên recall và F1 cao hơn đáng kể.

### 8.1. Vậy có phải lõi của mình hơn Semgrep không?

Chỗ này em nghĩ nên nói rất cẩn thận, không nên nói quá mạnh kiểu “lõi của em tốt hơn Semgrep toàn diện”, vì như vậy dễ bị hỏi ngược.

Cách nói hợp lý hơn là:

> Trong phạm vi benchmark đã chọn, cụ thể là OWASP Benchmark Python với bốn family mục tiêu, lõi native của Aegis hiện cho recall và F1 tốt hơn Semgrep baseline. Điều đó có nghĩa là ở phạm vi nghiên cứu này, detector của tụi em đang bắt được nhiều case thật hơn.

Tuy nhiên, em cũng sẽ nói thêm ngay:

> Semgrep vẫn mạnh hơn ở độ trưởng thành tổng thể, hệ sinh thái rule và mức sẵn sàng công nghiệp. Vì vậy, tụi em không xem Aegis là để phủ nhận Semgrep, mà xem Aegis là một detector lane nghiên cứu riêng, đồng thời về sau có thể tích hợp Semgrep như một detector source công nghiệp trong mô hình hybrid.

### 8.2. Vậy lõi của mình đang hơn Semgrep ở điểm nào

Trong phạm vi hiện tại, tụi em thấy lõi Aegis có lợi thế ở mấy điểm sau:

1. Được điều chỉnh sát hơn theo phạm vi family mà tụi em đang nghiên cứu.
2. Ở lane Python, tụi em kiểm soát tốt hơn phần source, sink và bằng chứng dữ liệu liên quan tới finding.
3. Finding của Aegis đi ra theo schema đã chuẩn hóa và gắn chặt với triage workflow, nên dễ nối lên dashboard, report và AI review hơn.
4. Về mặt luận văn, lõi riêng giúp tụi em kiểm soát được kiến trúc, contract dữ liệu và hướng mở rộng nghiên cứu.

### 8.3. Điểm nào Semgrep vẫn tốt hơn

Em cũng sẽ nói trung thực luôn là Semgrep hiện vẫn tốt hơn tụi em ở:

- độ trưởng thành của rule ecosystem;
- độ phổ biến và tính công nghiệp;
- độ sạch ở một số tình huống;
- và độ sẵn sàng nếu nhìn từ góc độ product out-of-the-box.

Vì vậy, hướng đi lâu dài của tụi em không phải là “phải thắng Semgrep bằng mọi giá”, mà là:

- giữ lõi native làm lane nghiên cứu;
- tích hợp Semgrep làm detector source;
- để lớp triage, dashboard và AI của Aegis xử lý ở tầng trên.

---

## 9. Phần AI và multi-agent hiện tại đang ở đâu

Chỗ này em sẽ nói rõ để tránh hiểu lầm.

Tụi em đã có:

- AI runner;
- client Gemini;
- adapter OpenAI-compatible;
- bridge theo hướng LangGraph;
- workflow theo vai trò Auditor, Skeptic, Judge.

Điều đó có nghĩa là về kiến trúc, hệ thống đã đi theo hướng multi-agent triage tương đối rõ.

Nếu cần nói cụ thể hơn để cô dễ hình dung, em sẽ nói:

> Multi-agent trong Aegis hiện tại có thể hiểu là một workflow phản biện gồm ba vai trò. Một bên cố chứng minh finding là lỗi thật, một bên cố bác bỏ finding bằng ngữ cảnh bảo vệ hoặc false-positive pattern, và một bên tổng hợp lại để chốt kết quả. Điểm mà tụi em đang hướng tới không phải là cho nhiều agent chạy tự do, mà là tổ chức chúng thành một cơ chế tranh biện có kiểm soát, có lưu vết và có thể nối với reviewer feedback về sau.

Nhưng tụi em **chưa nên claim quá sớm** là:

- AI đã giúp benchmark tăng rõ ràng;
- hay LangGraph orchestration đã hoàn chỉnh end-to-end cho toàn hệ thống.

Lý do là vì trong các lần benchmark gần đây, AI thường bị rơi vào fallback do quota hoặc môi trường runtime, nên chưa tạo được khác biệt định lượng ổn định.

Cách nói em nghĩ an toàn nhất là:

> AI trong Aegis hiện đã được đặt đúng vào lớp triage về mặt kiến trúc. Tuy nhiên, kết quả benchmark chính hiện nay vẫn đến từ deterministic core. Phần AI đang ở giai đoạn hoàn thiện để sau này thực sự tác động được vào chất lượng review finding.

---

## 10. Những điểm còn yếu và hạn chế hiện tại

Em nghĩ báo cáo tốt không phải là chỉ nói điểm mạnh, mà còn phải nói rõ điểm yếu.

Hiện tại, những hạn chế chính của đề tài là:

### 10.1. False positive ở Path Traversal còn cao

Đây là hạn chế lớn nhất hiện nay và cũng là việc ưu tiên xử lý trước tiên.

### 10.2. Triage chưa tạo khác biệt định lượng rõ

Trong bảng điểm hiện tại, ba mode:

- all findings
- visible after triage
- high confidence

đều cho ra cùng kết quả. Điều đó cho thấy lớp triage đã có mặt trong kiến trúc, nhưng chưa thực sự tạo tác động đo được lên score cuối cùng.

### 10.3. Mức trưởng thành giữa các ngôn ngữ chưa đồng đều

Python hiện là lane mạnh nhất. Java đã có benchmark nhưng còn yếu hơn khá nhiều nếu so với Python. JavaScript và PHP mới ở mức nền kiến trúc và detector cơ bản.

### 10.4. AI chưa phải là điểm mạnh về số liệu ở thời điểm này

AI hiện là phần đúng hướng về mặt kiến trúc, nhưng chưa nên lấy làm phần claim chính về hiệu quả benchmark.

---

## 11. Hướng phát triển tiếp theo

Nếu cô hỏi “vậy tiếp theo các em làm gì”, thì em sẽ trả lời theo ba mức ưu tiên.

### 11.1. Ưu tiên ngắn hạn

Trong ngắn hạn, tụi em sẽ tập trung vào bốn việc:

1. Giảm false positive cho Path Traversal.
2. Làm cho triage thật sự phân biệt được giữa:
   - all findings
   - visible findings
   - high-confidence findings
3. Bổ sung reviewer memory trong dashboard, ví dụ:
   - note của reviewer
   - false positive pattern
   - mute/suppress có kiểm soát
4. Ổn định local AI để triage có thể chạy thực tế hơn.

Nếu nói theo ngôn ngữ multi-agent, thì mục tiêu ngắn hạn là làm cho ba việc này xảy ra thật sự:

- `Auditor` phải đưa ra được bằng chứng chặt hơn thay vì chỉ lặp lại finding gốc;
- `Skeptic` phải bác bỏ được nhiều false positive hơn, nhất là ở Path Traversal;
- `Judge` phải tạo ra khác biệt thực sự giữa `all findings`, `visible findings` và `high-confidence findings`.

### 11.2. Ưu tiên trung hạn

Sau đó, tụi em muốn đi theo hướng hybrid rõ ràng hơn:

- `Aegis native`
- `Semgrep raw`
- `Semgrep + Aegis triage`

Tức là Semgrep sẽ không phải đối thủ để bỏ qua, mà là một detector source công nghiệp để Aegis tận dụng.

### 11.3. Ưu tiên dài hạn

Về dài hạn, hệ thống có thể mở rộng thêm:

- diff-aware PR scan;
- remediation draft;
- re-scan validation;
- thêm family như XSS, SSRF, XXE, LDAP Injection, XPath Injection.

Nhưng nguyên tắc là tụi em chỉ claim mạnh family nào đã có benchmark đủ sạch và đủ rõ.

---

## 12. Phần demo nếu cô muốn xem ngay

Nếu cô muốn xem demo, em sẽ nói như sau:

Hiện tại có hai kiểu demo.

### 12.1. Demo bằng benchmark CLI

Đây là cách thuyết phục nhất về mặt học thuật, vì không phải ví dụ tự viết.

Tụi em sẽ chạy scan trên OWASP Benchmark Python, sau đó chấm lại bằng file ground truth để ra:

- TP
- FP
- FN
- precision
- recall
- F1

Điểm mạnh của cách demo này là:

- dữ liệu không phải do tụi em tự nghĩ ra;
- có expected results chuẩn;
- và có thể so trực tiếp với Semgrep baseline.

### 12.2. Demo bằng dashboard

Nếu cô muốn nhìn theo góc độ người dùng, tụi em có thể mở dashboard local để:

- import report benchmark đã scan;
- xem finding;
- lọc theo family hoặc severity;
- bấm vào từng finding để xem chi tiết và explanation.

Dashboard giúp cô thấy được hệ thống không chỉ quét ra kết quả mà còn có lớp tiêu thụ kết quả tương đối rõ ràng.

---

## 13. Đoạn kết luận để chốt buổi báo cáo

Nếu tới cuối buổi em cần chốt lại thật gọn nhưng vẫn đủ ý, em sẽ nói:

> Tóm lại, đến thời điểm hiện tại, đề tài Aegis-SAST đã đi qua giai đoạn ý tưởng ban đầu và đã hình thành được một hệ thống SAST có lõi quét riêng, có benchmark, có baseline đối chứng, có dashboard và có định hướng AI/multi-agent tương đối rõ.  
>  
> Kết quả tốt nhất hiện tại của hệ thống nằm ở lane Python với bốn family chính, trong đó Aegis native đang cho recall và F1 cao hơn Semgrep baseline trong cùng điều kiện benchmark. Điều này cho thấy detector của tụi em không chỉ chạy được mà còn có giá trị thực nghiệm.  
>  
> Tuy nhiên, hệ thống vẫn còn hai việc rất quan trọng phải làm tiếp là giảm false positive, đặc biệt ở Path Traversal, và làm cho lớp triage cùng AI thực sự tạo ra sự khác biệt định lượng rõ ràng hơn. Đây cũng chính là hướng mà nhóm em sẽ ưu tiên trong giai đoạn tiếp theo.

---

## 14. Một số câu trả lời ngắn nếu cô hỏi thêm

### Nếu cô hỏi: “Vì sao không dùng luôn Semgrep làm lõi?”

Em sẽ trả lời:

> Tụi em có dùng Semgrep làm baseline so sánh và cũng xem Semgrep là một detector source rất tốt về mặt công nghiệp. Tuy nhiên, nếu dùng hoàn toàn Semgrep làm lõi ngay từ đầu thì đề tài sẽ khó có chỗ để nghiên cứu kiến trúc detector, data-flow và evidence bundle của riêng mình. Vì vậy tụi em giữ Aegis native core như lane nghiên cứu, đồng thời về sau sẽ tích hợp Semgrep theo hướng hybrid.

### Nếu cô hỏi: “Vậy lõi của các em hơn Semgrep ở đâu?”

Em sẽ trả lời:

> Em không nói là hơn Semgrep toàn diện. Nhưng trong phạm vi benchmark hiện tại, tức là OWASP Benchmark Python với bốn family mục tiêu, Aegis native cho recall và F1 tốt hơn. Nghĩa là ở bài toán mà tụi em đang tập trung, detector của tụi em hiện bắt được nhiều case thật hơn.

### Nếu cô hỏi: “AI đang đóng vai trò gì?”

Em sẽ trả lời:

> AI hiện không phải detector chính mà đang được đặt ở lớp triage. Vai trò của AI là đọc lại finding, hỗ trợ đánh giá mức độ thuyết phục, sinh explanation và chuẩn bị nền cho reviewer workflow. Đây là cách đặt AI an toàn và thực tế hơn ở thời điểm hiện tại.

### Nếu cô hỏi: “Vậy multi-agent cụ thể là gì?”

Em sẽ trả lời:

> Multi-agent ở đây không có nghĩa là nhiều bot chạy độc lập cho đẹp, mà là cơ chế phân vai để tranh biện một finding. Một vai trò sẽ cố chứng minh finding là lỗi thật, một vai trò sẽ cố phản biện xem có phải false positive không, và một vai trò cuối cùng sẽ tổng hợp rồi chốt quyết định. Trong Aegis, ba vai trò đó hiện được tổ chức thành Auditor, Skeptic và Judge. Điểm tiếp theo tụi em muốn làm là nối thêm reviewer memory để cuộc đánh giá đó có vòng phản hồi, chứ không bị stateless qua từng lần scan.

### Nếu cô hỏi: “Điểm yếu lớn nhất hiện giờ là gì?”

Em sẽ trả lời:

> Điểm yếu lớn nhất hiện tại là false positive ở Path Traversal còn cao, và lớp triage chưa làm tách rõ được all findings với high-confidence findings trong benchmark.

---

## 15. Kết thúc

Đây là toàn bộ bài nói mà em có thể dùng để báo cáo với cô trong khoảng gần 30 phút. Khi trình bày thật, không cần đọc quá nhanh. Chỉ cần giữ nhịp như sau:

- phần mở đầu và bài toán: nói chậm, dễ hiểu;
- phần kiến trúc: nói rõ nhưng không quá sâu vào code;
- phần kết quả benchmark: nói kỹ hơn vì đây là phần có giá trị nhất;
- phần hạn chế và hướng tiếp theo: nói trung thực, có ưu tiên rõ ràng.

Nếu cần, có thể đánh dấu trước các đoạn em muốn nhấn mạnh nhất bằng bút hoặc highlight để lúc trình bày không bị mất nhịp.

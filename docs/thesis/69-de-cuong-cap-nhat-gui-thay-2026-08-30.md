# Đề cương cập nhật gửi thầy

## Tên đề tài chính thức

**Nghiên cứu kiến trúc Multi-Agent Hybrid kết hợp AST truyền thống và Mô hình ngôn ngữ lớn (LLM) nhằm tối ưu hóa độ chính xác trong kiểm thử bảo mật mã nguồn**

Aegis-SAST là hệ thống thực nghiệm mà nhóm đang dùng để hiện thực, kiểm chứng và benchmark cho hướng đề tài này. Vì vậy, khi viết gửi thầy, cần bám theo tên đề tài chính thức ở trên; còn tên Aegis-SAST nên được dùng để chỉ nền tảng triển khai và thử nghiệm của nhóm.

## 1. Mục đích cập nhật

Trong thời gian vừa qua, nhóm em tập trung hoàn thiện phần lõi của hệ thống Aegis-SAST và kiểm chứng lại kết quả bằng benchmark. Vì vậy, bản đề cương cập nhật này được viết để trình bày rõ những phần nhóm đã giải quyết được, phương pháp đã dùng, những khó khăn đang gặp phải, cũng như hướng xử lý và các công việc sẽ làm tiếp trong thời gian tới.

Mục tiêu của bản này là để thầy nắm được trạng thái thật của đề tài ở thời điểm hiện tại, tránh mô tả quá rộng so với phần nhóm đã làm được.

## 2. Hướng đề tài hiện tại

Nếu bám đúng theo tên đề tài chính thức, trọng tâm của đề tài không chỉ là làm một bộ quét mã nguồn, mà là nghiên cứu một kiến trúc Multi-Agent Hybrid cho kiểm thử bảo mật mã nguồn. Trong kiến trúc đó, AST và phân tích tĩnh truyền thống giữ vai trò tạo bằng chứng kỹ thuật, còn LLM và các vai trò tác tử giữ vai trò đánh giá lại kết quả, phản biện, giải thích và hỗ trợ quyết định.

Aegis-SAST hiện được phát triển theo đúng hướng kết hợp đó. Trong đó, phần phát hiện chính vẫn là bộ quét phân tích tĩnh dựa trên AST, rule và theo dõi luồng dữ liệu. AI không thay thế bộ quét chính, mà được đặt ở lớp hỗ trợ đánh giá lại kết quả, giải thích cảnh báo và chuẩn bị cho bước rà soát sau này.

Nhóm chọn hướng này vì nếu dùng AI làm bộ quét chính ngay từ đầu thì rất khó kiểm chứng, khó benchmark và khó giữ kết quả ổn định giữa các lần chạy. Ngược lại, nếu giữ phần phát hiện trên nền phân tích tĩnh, sau đó mới thêm lớp đánh giá lại ở phía trên, thì kết quả vừa dễ giải thích hơn vừa phù hợp hơn với mục tiêu nghiên cứu.

## 3. Những vấn đề nhóm đã giải quyết được

### 3.1. Xây dựng được lõi bộ quét có thể chạy và benchmark

Nhóm đã xây được bộ quét riêng thay vì chỉ bọc ngoài một công cụ có sẵn. Hệ thống hiện có kiến trúc plugin cho nhiều ngôn ngữ, dùng tree-sitter để lấy AST, có rule engine, có bước chuẩn hóa kết quả và có thể xuất báo cáo ra các dạng như JSON, Markdown và SARIF.

Về mặt kiến trúc, quy trình xử lý hiện đã tách thành các bước khá rõ: tiếp nhận repo, phát hiện, chuẩn hóa kết quả, đánh giá lại và xuất báo cáo. Đây là phần quan trọng vì nó cho thấy đề tài không còn ở mức ý tưởng, mà đã có một hệ thống chạy được và kiểm thử được.

### 3.2. Làm mạnh phần Python và có kết quả thực nghiệm rõ

Đến thời điểm hiện tại, Python là phần làm tốt nhất của hệ thống. Nhóm đã triển khai được theo dõi source, sink, sanitizer và xử lý luồng dữ liệu tốt hơn các ngôn ngữ còn lại. Đây cũng là phần đang được dùng làm trọng tâm để benchmark và báo cáo với thầy.

### 3.3. Giảm cảnh báo sai cho Path Traversal ở Python

Một trong những vấn đề lớn trước đây là Path Traversal cho ra khá nhiều cảnh báo sai. Nhóm đã xử lý lại phần lọc theo ngữ cảnh ở Python, nhất là các trường hợp giá trị đầu vào đã bị ghi đè bằng hằng an toàn, đi qua nhánh điều kiện cố định, hoặc lấy ra từ cấu trúc dữ liệu an toàn.

Sau đợt chỉnh này, chất lượng kết quả ở Python cải thiện rõ hơn so với trước. Đây là một phần tiến triển quan trọng vì Path Traversal từng là điểm gây nhiễu nhiều nhất trong quá trình benchmark.

### 3.4. Tách được các mức kết quả trên báo cáo

Trước đây báo cáo có xu hướng dồn nhiều cảnh báo vào cùng một mức đánh giá, nên người xem khó biết cảnh báo nào nên ưu tiên xem trước. Nhóm đã bổ sung bước đánh giá lại sau phát hiện để chia kết quả thành các mức như `confirmed`, `likely`, `needs-review` và `suppressed`.

Việc này giúp báo cáo có ý nghĩa hơn với người đọc và tạo nền cho bước rà soát sau này. Quan trọng hơn, nhóm không chỉ dừng ở việc gắn nhãn, mà đã bắt đầu dùng các luật lọc theo ngữ cảnh để làm cho việc phân mức phản ánh chất lượng cảnh báo tốt hơn.

### 3.5. Có bộ chấm điểm và mốc so sánh để đối chiếu

Nhóm đã chuẩn bị được bộ chấm benchmark để chấm kết quả trên OWASP Benchmark, đồng thời có mốc so sánh với Semgrep trong cùng điều kiện chấm điểm. Đây là phần rất quan trọng vì đề tài không chỉ dừng ở việc “quét ra được kết quả”, mà đã có số liệu để đánh giá tương đối khách quan.

Điểm mới trong giai đoạn này là nhóm không còn để rule baseline ở mức tài liệu hay artifact tách rời. Các rule đã review từ Semgrep đã được đưa vào luồng chạy thật dưới dạng profile kiểm soát được, để có thể dùng lại thống nhất khi scan tay, so sánh kết quả và chạy benchmark.

### 3.6. Có dùng rule và hướng đúng là xuất phát từ rule baseline có uy tín

Hệ thống hiện có `rule engine` riêng và đang chạy bằng các bộ rule YAML theo từng ngôn ngữ như Python, Java, JavaScript và PHP. Tuy vậy, nếu chỉ dựa vào rule tự viết rồi xem đó là đúng ngay thì chưa đủ thuyết phục về mặt nghiên cứu.

Vì vậy, hướng mà nhóm theo đuổi là lấy rule baseline có uy tín từ bên ngoài, trước mắt là Semgrep, làm điểm xuất phát; sau đó chọn đúng phạm vi cần dùng, chuẩn hóa về schema chung, review lại source, sink và metadata, rồi mới chuyển sang dạng mà detector của Aegis đọc được.

Đến thời điểm này, nhóm đã đóng gói được profile `semgrep-python-core4` cho bốn nhóm lỗi chính và profile `semgrep-python-ssrf` cho nhánh mở rộng SSRF. Cách tích hợp hiện nay là thêm lớp rule overlay đã review lên trên bộ rule mặc định của Aegis, chứ không thay toàn bộ detector bằng Semgrep. Nhờ vậy, nhóm vẫn giữ được quyền kiểm soát detector hiện tại nhưng điểm xuất phát của phần rule có cơ sở hơn.

Nói ngắn gọn, Semgrep trong đề tài này không chỉ là công cụ để đem ra so sánh điểm số, mà còn là nguồn baseline để nhóm tham chiếu, chọn lọc và đưa vào runtime sau khi đã kiểm tra lại.

## 4. Phương pháp nhóm đã dùng để giải quyết

### 4.1. Dùng AST làm nền để đọc cấu trúc mã nguồn

Nhóm dùng tree-sitter để lấy cây cú pháp AST của mã nguồn. Cách này giúp hệ thống đọc mã theo cấu trúc cú pháp thay vì dò chuỗi đơn thuần. Từ AST, nhóm trích ra các lời gọi hàm, biểu thức gán, điều kiện rẽ nhánh và các điểm có khả năng là source hoặc sink.

### 4.2. Kết hợp rule với phân tích luồng dữ liệu

Sau khi có AST, nhóm dùng rule để nhận diện mẫu lỗ hổng và dùng theo dõi luồng dữ liệu để xem dữ liệu đi từ đâu đến đâu. Với Python, phần này được làm sâu hơn, nên có thể bám được luồng dữ liệu qua nhiều bước và trong một số trường hợp có thể theo sang nhiều file liên quan.

Điểm cần nhấn mạnh thêm là rule không nên được xây theo kiểu hoàn toàn tách rời chuẩn tham chiếu bên ngoài. Hướng mà nhóm đang bám là lấy subset rule từ nguồn có uy tín như Semgrep, sau đó chuẩn hóa, review và điều chỉnh cho khớp với cách biểu diễn source, sink, sanitizer và evidence của Aegis. Cách làm này giúp giảm rủi ro chủ quan khi xây rule hoàn toàn bằng tay, đồng thời vẫn giữ được khả năng kiểm soát detector của hệ thống.

### 4.3. Thêm bước đánh giá lại sau phát hiện

Nhóm không xem cảnh báo sinh ra từ bộ phát hiện là kết luận cuối cùng. Sau bước phát hiện, hệ thống có thêm bước đánh giá lại để tìm xem cảnh báo nào thật sự đáng giữ, cảnh báo nào cần người xem lại, cảnh báo nào có thể hạ xuống vì trong code đã có dấu hiệu an toàn rõ ràng.

Đây là cách nhóm dùng để giảm cảnh báo sai mà không làm bộ phát hiện trở nên quá cứng hoặc quá phức tạp.

### 4.4. Dùng benchmark để kiểm chứng thay vì đánh giá cảm tính

Mỗi thay đổi lớn đều được đối chiếu lại bằng benchmark. Nhóm dùng ground truth từ OWASP Benchmark để tính TP, FP, FN, precision, recall và F1. Nhờ vậy, khi một hướng xử lý giúp giảm cảnh báo sai nhưng lại làm mất quá nhiều trường hợp đúng thì nhóm nhìn ra ngay, thay vì chỉ dựa vào cảm giác.

### 4.5. Tổ chức lớp đánh giá lại theo hướng multi-agent

Ngoài phần detector, nhóm còn tổ chức lớp đánh giá lại kết quả theo hướng nhiều vai trò phối hợp với nhau. Cụ thể, hệ thống hiện có ba vai trò chính là `Auditor`, `Skeptic` và `Judge`.

Có thể hiểu ngắn gọn như sau:

1. `Auditor` đọc finding và bằng chứng hiện có để xem cảnh báo mạnh tới đâu.
2. `Skeptic` tìm các dấu hiệu cho thấy cảnh báo có thể là cảnh báo sai hoặc cần hạ mức tin cậy.
3. `Judge` tổng hợp hai phía để chốt trạng thái cuối cùng cho finding.

Cách tổ chức này giúp hệ thống đi từ chỗ chỉ phát hiện ra cảnh báo sang chỗ có thêm một tầng phản biện và đánh giá lại trước khi đưa ra kết quả cuối cùng. Đây chính là phần mang màu sắc multi-agent của đề tài.

Ở mức hiện tại, lớp triage cũng không làm việc theo kiểu ném toàn bộ mã nguồn hay toàn bộ cây AST thô vào AI. Nhóm đã bắt đầu chuẩn hóa finding, source, sink, một phần bằng chứng luồng dữ liệu và metadata workflow thành các payload gọn hơn để lớp triage và AI đọc lại. Tuy vậy, việc biến thông tin AST thành ngữ cảnh vừa đủ ngắn để tiết kiệm token nhưng vẫn giữ được logic của luồng dữ liệu giữa nhiều hàm và nhiều file vẫn còn là một bài toán mở của đề tài.

Tuy vậy, để trình bày trung thực, cần nói rõ rằng multi-agent hiện được đặt ở lớp triage, tức lớp đánh giá lại kết quả sau phát hiện. Phần tạo ra kết quả benchmark chính hiện vẫn là detector phân tích tĩnh. Nói cách khác, multi-agent đã có nền kiến trúc và đã có hành vi thật ở mức workflow, nhưng chưa nên mô tả như một hệ LangGraph hoàn chỉnh điều khiển toàn bộ pipeline.

## 5. Kết quả hiện tại

Ở phần Python với bốn nhóm lỗi chính là `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `INSECURE_DESERIALIZATION` và `SQL_INJECTION`, kết quả hiện tại cho thấy hệ thống đã có nền tảng khá ổn để tiếp tục phát triển.

| Phạm vi đánh giá | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Tập kết quả đầy đủ | 85 | 10 | 16 | 0.8947 | 0.8416 | 0.8673 |
| Tập kết quả ưu tiên hiển thị cho người rà soát | 85 | 0 | 16 | 1.0000 | 0.8416 | 0.9140 |

Nhìn vào kết quả trên có thể thấy hướng thêm lớp đánh giá lại sau phát hiện đang có tác dụng thực tế, ít nhất là trên phạm vi Python và bốn nhóm lỗi đang tập trung. So với mốc so sánh Semgrep trên cùng bộ chấm, kết quả hiện tại của Aegis tốt hơn về recall và F1 trong phạm vi bốn nhóm lỗi này.

Khi mở rộng lên sáu nhóm lỗi, hệ thống vẫn giữ được độ bao phủ tương đối tốt nhưng bắt đầu lộ rõ khó khăn về cảnh báo sai ở một số nhóm như `OPEN_REDIRECT` và `CODE_INJECTION`. Điều này cho thấy hướng đi hiện tại là đúng, nhưng việc mở rộng độ phủ cần làm có kiểm soát chứ không thể tăng quá nhanh.

Ngoài phạm vi bốn nhóm lỗi chính, nhóm cũng đã tách riêng một nhánh reviewed cho SSRF từ nguồn Semgrep chính thức và đưa vào benchmark mở rộng. Ở ví dụ SSRF dùng để kiểm tra nhanh, kết quả giữa bộ mặc định và profile reviewed hiện giữ cùng độ phủ 3 trên 3. Điều này chưa phải là một kết luận lớn về chất lượng detector, nhưng cho thấy quy trình chuẩn hóa rule baseline đã đi vào runtime ổn định mà không làm lệch kết quả đang có.

## 6. Khó khăn nhóm đang gặp phải

Để tránh hiểu nhầm, phần khó khăn ở đây có hai lớp. Lớp thứ nhất là những khó khăn đã xuất hiện ngay trong code đang chạy. Lớp thứ hai là những khó khăn gần như chắc chắn sẽ xuất hiện nếu mở rộng Aegis-SAST đúng theo tên đề tài là Multi-Agent Hybrid kết hợp AST và LLM. Vì vậy, không nên hiểu rằng hiện tại hệ thống đã có một dàn agent LLM đọc toàn bộ repo rồi tranh luận nhiều vòng.

Khó khăn lớn nhất hiện nay vẫn là bài toán cân bằng giữa độ bao phủ và độ chính xác. Nếu bộ phát hiện được nới để bắt được nhiều trường hợp hơn thì số cảnh báo sai cũng tăng theo. Ngược lại, nếu lọc quá mạnh thì kết quả sạch hơn nhưng dễ bỏ sót case thật. Đây là điểm khó cốt lõi của phần detector và cũng là lý do nhóm vẫn giữ bộ quét phân tích tĩnh làm nền thay vì đẩy toàn bộ quyết định sang AI.

Khó khăn thứ hai là độ sâu phân tích giữa các ngôn ngữ hiện chưa đồng đều. Python đang là lane đi sâu hơn với cross-file reasoning, function index, flow graph và metadata giàu hơn. Trong khi đó, Java, JavaScript và PHP hiện vẫn chủ yếu dừng ở mức intra-file và heuristic. Điều này làm cho cùng một cách triage hay cùng một kiểu báo cáo chưa chắc đã có chất lượng như nhau giữa các lane.

Khó khăn thứ ba là phần cầu nối giữa kết quả phân tích tĩnh với lớp AI vẫn chưa phải điểm đã hoàn tất. Trong runtime hiện tại, detector chạy trước, tạo finding và evidence bundle trước, sau đó AI nếu được bật sẽ đọc lại `triage_input` của từng finding chứ không đọc toàn bộ cây AST của repo. Cách làm này giúp giữ chi phí thấp hơn và đúng với ý tưởng “scan ra nghi vấn trước, rồi mới review lại”. Tuy vậy, nếu muốn đẩy AI đi sâu hơn ở lớp triage thì nhóm vẫn phải giải được bài toán nâng gói evidence hiện có thành một dạng ngữ cảnh giàu hơn nhưng vẫn gọn token.

Khó khăn thứ tư là `repo intake` và `scan profile` hiện mới dừng ở mức nhận diện ngôn ngữ, framework hint, số file hỗ trợ và loại trừ thô các thư mục không cần thiết. Đây là nền tốt để quản lý phạm vi scan, nhưng chưa phải cơ chế tự động cắt ra đúng những file, hàm hay lát cắt code liên quan trực tiếp tới từng finding để đưa lên AI. Nói cách khác, phần “chọn đúng ngữ cảnh nhỏ nhưng đủ dùng cho AI” vẫn là việc cần làm tiếp.

Khó khăn thứ năm là sự khác nhau rất lớn giữa các ngôn ngữ, đặc biệt là giữa Java và Python. Java có class, interface, annotation và khung web khá rõ ràng nên thuận lợi hơn cho việc biểu diễn ngữ cảnh theo cấu trúc. Python linh hoạt hơn nhiều, nhất là ở các helper gọi gián tiếp, suy luận kiểu theo ngữ cảnh và hành vi runtime. Vì vậy, nếu dùng chung một cách đóng gói ngữ cảnh cho mọi ngôn ngữ thì chất lượng triage sẽ khó ổn định.

Khó khăn thứ sáu là chi phí token, độ trễ và hạ tầng API. Trong pipeline chính, AI hiện mới là lớp overlay sau deterministic triage, nhưng ngay cả mô hình này cũng đã phụ thuộc vào runtime/API ổn định. Nếu sau này mở rộng sang nhiều lượt phản biện hơn giữa các vai trò dùng LLM thì chi phí token và độ trễ sẽ tăng mạnh. Trong khi đó, phần AI hiện vẫn còn phụ thuộc vào API miễn phí hoặc host chưa đủ ổn định cho các phép đo dài hơi.

Khó khăn thứ bảy là bài toán phối hợp giữa các vai trò khi mở rộng multi-agent theo đúng nghĩa mạnh hơn. Ở thời điểm hiện tại, `Auditor`, `Skeptic` và `Judge` trong repo chủ yếu vẫn là các node deterministic có hợp đồng rõ ràng. Nhưng nếu về sau chuyển nhiều phần hơn sang LLM thì sẽ phát sinh ngay bài toán đồng thuận quá sớm, tranh luận vòng lặp, hoặc thiếu điều kiện dừng rõ ràng giữa các vai trò.

Khó khăn thứ tám là nguy cơ suy diễn sai của AI. Trong bài toán bảo mật mã nguồn, nếu AI tự tưởng tượng ra source, sanitizer hay lỗ hổng không có thật thì độ tin cậy của cả hệ thống sẽ giảm rất mạnh. Vì vậy, AI trong đề tài này không thể hoạt động theo kiểu “tin là đúng”, mà phải bị ràng buộc bởi finding, evidence summary, source, sink, sanitizer và metadata mà detector đã tạo ra.

Khó khăn thứ chín là bài toán quan sát và gỡ lỗi hệ thống nhiều lớp. Hệ thống hiện đã có workflow trace, route summary, auditor/skeptic/judge metadata và report summary khá rõ. Tuy vậy, khi muốn đo tác động thật của AI hoặc của từng bước triage trên các case khó, nhóm vẫn cần log và trace dày hơn để lần ngược xem sai lệch đến từ detector, từ evidence pack, từ source context hay từ quyết định của lớp review.

Ngoài ra, nếu về sau mở rộng lớp agent theo hướng cho gọi công cụ hoặc chạy kiểm tra cục bộ, nhóm còn phải tính đến rủi ro bảo mật của chính hệ thống agent, ví dụ như prompt injection gián tiếp từ mã nguồn được quét hoặc việc gọi công cụ trong môi trường không đủ cô lập. Ở giai đoạn hiện tại đây chưa phải bài toán trung tâm của bản demo, nhưng là một rủi ro cần được nhìn trước.

## 7. Hướng giải quyết sắp tới

Trong giai đoạn gần nhất, nhóm sẽ tiếp tục giữ bộ phát hiện chính làm nền, sau đó cải thiện dần lớp đánh giá lại kết quả. Trọng tâm trước mắt vẫn là giảm cảnh báo sai ở những nhóm còn yếu, đặc biệt là `OPEN_REDIRECT`, `CODE_INJECTION` và các tình huống khó của `PATH_TRAVERSAL`.

Riêng với hướng multi-agent, nhóm sẽ làm rõ hơn luồng phối hợp giữa `Auditor`, `Skeptic` và `Judge` để đây không chỉ là cách đặt tên vai trò, mà trở thành một quy trình đánh giá lại có thể lặp lại và so sánh được giữa các lần chạy. Mỗi vai trò cần có đầu vào, đầu ra, loại bằng chứng được dùng và điều kiện dừng rõ ràng. Ở giai đoạn này, việc củng cố deterministic workflow cho chắc còn quan trọng hơn việc đẩy quá sớm sang nhiều agent LLM.

Song song với đó, nhóm sẽ hoàn thiện hơn phần phân loại cảnh báo trên báo cáo để các mức như `confirmed`, `likely`, `needs-review`, `suppressed` phản ánh đúng giá trị sử dụng thực tế, chứ không chỉ có ý nghĩa về mặt hiển thị. Mục tiêu là khi người xem mở báo cáo thì biết rõ nên ưu tiên xem gì trước và vì sao một finding lại đang ở đúng trạng thái đó.

Về kiến trúc, một hướng xử lý quan trọng là nâng lớp trung gian hiện có giữa detector và AI. Hiện tại hệ thống đã có `NormalizedFinding`, `EvidenceBundle`, `triage_input` và source/sink context window. Bước tiếp theo là làm cho lớp này giàu thông tin hơn theo hướng `code summary context`, ví dụ như tóm tắt call graph cục bộ, helper liên quan, source, sink, sanitizer và path summary rõ hơn, nhưng vẫn chỉ xoay quanh finding đã bị detector đánh dấu thay vì đưa cả repo lên AI.

Việc lọc trước cho AI cũng sẽ đi theo đúng tinh thần đó. `Repo intake` hiện nay hỗ trợ tốt cho việc loại trừ thô và nhận diện scan profile, còn bước chọn lát cắt ngữ cảnh cho AI sẽ cần bám sát finding, source/sink, path summary và các helper liên quan. Nói ngắn gọn, hướng đi đúng không phải là “đưa AI đọc toàn repo”, mà là “chỉ đưa AI đọc phần liên quan trực tiếp tới finding sau khi detector đã tìm ra nghi vấn”.

Với các ngôn ngữ khác nhau, nhóm cũng sẽ đi theo hướng tách rõ cách chuẩn bị ngữ cảnh thay vì ép mọi lane đi chung một mẫu. Java sẽ cần ngữ cảnh theo kiểu class, annotation, framework web và JDBC/ORM rõ ràng hơn; còn Python sẽ cần tận dụng tốt hơn function summary, helper summaries, source context và các case động như Flask, Django, `pickle`, `subprocess`. Đây là hướng tách lane về evidence và triage, chứ chưa phải tuyên bố rằng hiện tại hệ thống đã có các specialist agent hoàn chỉnh cho từng ngôn ngữ.

Đối với AI, hướng của nhóm là triển khai theo cách có kiểm soát ở lớp triage trên các finding mà detector đã tạo ra. Trước mắt, nhóm ưu tiên runtime local hoặc giao diện gọi tương thích OpenAI để dễ chủ động về chi phí, độ ổn định và việc so sánh kết quả giữa các lần chạy. Đồng thời, nhóm cũng cần tìm API hoặc host ổn định hơn thay cho việc phụ thuộc quá nhiều vào API miễn phí, để các phép đo về token, latency và chất lượng triage có giá trị hơn.

Sau khi phần AI triage chạy ổn định hơn, nhóm sẽ đo lại tác động của nó theo các tiêu chí dễ báo cáo như chất lượng phân loại cảnh báo, mức giảm false positive trên tập kết quả hiển thị, số finding bị đổi trạng thái sau AI overlay, số trường hợp fallback, thời gian người rà soát cần bỏ ra để đọc report, và chi phí token hoặc độ trễ của từng kiểu workflow. Cách làm này phù hợp hơn với tên đề tài vì thể hiện rõ vai trò của LLM trong kiến trúc hybrid, nhưng vẫn giữ được nền tảng là AST và phân tích tĩnh truyền thống.

Cuối cùng, nhóm sẽ bổ sung tốt hơn phần log, trace và metadata của từng bước trong workflow để khi một case bị xử lý sai vẫn có thể lần ngược lại xem lỗi đến từ detector, từ evidence pack, từ source context hay từ quyết định của từng node review. Nếu sau này mở rộng thêm khả năng cho agent gọi công cụ hoặc chạy kiểm tra cục bộ, nhóm cũng sẽ đi kèm với sandbox chặt hơn để tránh rủi ro khi quét mã nguồn không tin cậy.

Về phần rule, nhóm sẽ tiếp tục đi theo một quy trình tương đối chặt: lấy baseline từ nguồn có uy tín, chọn subset phù hợp, review thủ công, đóng gói thành profile ổn định, rồi mới benchmark lại. Sau `semgrep-python-core4` và `semgrep-python-ssrf`, các nhóm lỗi còn yếu hơn sẽ tiếp tục được đưa dần về cùng cách làm này.

## 8. Các hướng làm tiếp trong thời gian tới

Trong thời gian tới, nhóm dự kiến tập trung vào các công việc chính sau:

1. Tiếp tục tối ưu các luật lọc và rule để giảm cảnh báo sai ở các nhóm lỗi còn yếu.
2. Nâng `triage_input` và `evidence bundle` hiện có lên dạng `code summary context` giàu hơn, nhưng vẫn chỉ xoay quanh finding đã bị detector đánh dấu.
3. Kết hợp exclusion profile hiện tại với bước cắt ngữ cảnh quanh source, sink và path summary để chỉ đưa phần liên quan trực tiếp tới finding lên AI, thay vì đưa cả repo lên lớp triage.
4. Mở rộng thêm các profile rule reviewed theo quy trình baseline -> review -> runtime -> benchmark cho những nhóm lỗi còn đang yếu.
5. Củng cố phần Java, JavaScript và PHP để thu hẹp khoảng cách với Python, đồng thời tách rõ hơn cách chuẩn bị ngữ cảnh giữa Java lane và Python lane.
6. Hoàn thiện workflow `Auditor -> Skeptic -> Judge` theo hướng deterministic, có trace và điều kiện dừng rõ hơn; sau đó mới cân nhắc mở rộng thêm vai trò LLM khi thật sự cần.
7. Triển khai thử AI triage theo hướng có kiểm soát, ưu tiên runtime local hoặc giao diện tương thích OpenAI, đồng thời tìm host hoặc API ổn định hơn để giảm phụ thuộc vào gói miễn phí.
8. Đo tác động của AI triage không chỉ trên chất lượng rà soát kết quả mà còn trên token cost, latency, số lần fallback và độ ổn định giữa các lần chạy.
9. Hoàn thiện hơn bước chuẩn hóa kết quả, log, trace và xuất báo cáo để dễ dùng cho đánh giá, debug và demo.
10. Bổ sung tốt hơn phần rà soát trên dashboard, để việc xem và phản hồi cảnh báo có thể dùng lại cho các lần scan sau.
11. Duy trì benchmark định kỳ sau mỗi đợt chỉnh lớn để bảo đảm mọi thay đổi đều được kiểm chứng bằng số liệu.
12. Chuẩn bị hướng tích hợp tốt hơn với báo cáo chuẩn như SARIF và tiến tới khả năng dùng trong CI ở giai đoạn sau.
13. Nếu mở rộng thêm lớp agent có gọi công cụ hoặc kiểm tra cục bộ, đi kèm với sandbox và giới hạn thực thi đủ chặt để tránh rủi ro từ mã nguồn không tin cậy.

## 9. Kết luận

Tóm lại, nếu nhìn theo tên đề tài chính thức thì phần mà nhóm đã giải quyết được rõ nhất đến thời điểm hiện tại là từng bước hiện thực hóa kiến trúc Multi-Agent Hybrid trên một nền tảng chạy thật là Aegis-SAST. Trong đó, nhóm đã xây được lõi bộ quét có thể chạy thật, benchmark thật và cải thiện được chất lượng kết quả ở phần Python; đồng thời bắt đầu tổ chức được lớp đánh giá lại theo hướng nhiều vai trò phối hợp.

Đóng góp thực tế của giai đoạn này không nằm ở việc dùng AI thay toàn bộ quá trình quét, mà nằm ở chỗ nhóm đã xây được nền phân tích tĩnh đủ chắc, sau đó tổ chức thêm lớp đánh giá lại để giảm cảnh báo sai và làm cho kết quả có giá trị sử dụng hơn. Ngoài ra, nhóm cũng đã bắt đầu đưa rule baseline đã review từ Semgrep vào luồng chạy thật của hệ thống, thay vì chỉ dùng để tham khảo hoặc so sánh ở bên ngoài.

Nếu thầy đồng ý với hướng này, nhóm em sẽ tiếp tục bám theo lộ trình: giữ chắc phần lõi đã làm được, giảm dần cảnh báo sai ở các nhóm còn yếu, mở rộng có kiểm soát sang các ngôn ngữ còn lại, và hoàn thiện hơn phần đánh giá lại kết quả để đề tài vừa có giá trị kỹ thuật, vừa có giá trị thực nghiệm rõ ràng.

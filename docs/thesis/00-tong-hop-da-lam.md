# Tổng hợp những gì Aegis-SAST đã làm được

## 1. Mục đích của tài liệu

Tài liệu này đóng vai trò như một bản tóm tắt điều hành cho toàn bộ dự án **Aegis-SAST** ở thời điểm hiện tại. Mục tiêu của tài liệu không phải là trình bày toàn bộ chi tiết kỹ thuật, mà là giúp người đọc nhanh chóng nắm được bốn nội dung quan trọng nhất:

1. Hệ thống hiện đang làm được những gì.
2. Những phần nào đã có giá trị kỹ thuật và giá trị học thuật rõ ràng.
3. Kết quả benchmark nào có thể dùng để báo cáo với giảng viên.
4. Những giới hạn nào cần nói trung thực để tránh lệch claim khi bảo vệ.

Tài liệu này nên được đọc trước khi chuẩn bị báo cáo tiến độ, viết phần mở đầu khóa luận, hoặc xây dựng kịch bản demo ngắn.

## 2. Aegis-SAST hiện đang là gì

Ở trạng thái hiện tại, Aegis-SAST là một hệ thống **SAST hybrid** theo hướng:

- dùng **deterministic static analysis** làm lớp phát hiện chính;
- dùng **triage có cấu trúc** để chuẩn hóa và đánh giá finding;
- dùng **AI** ở lớp trên nhằm hỗ trợ triage, explanation và reviewer workflow, thay vì thay thế toàn bộ detector;
- dùng **dashboard** như một lớp sản phẩm để đọc, lọc và review kết quả đã được xuất ra từ pipeline.

Điểm quan trọng cần nhấn mạnh là Aegis-SAST **không phải** một lớp giao diện bọc ngoài Semgrep hay một demo LLM thuần prompt. Hệ thống đã có detector riêng của repo, có plugin theo ngôn ngữ, có rule engine, có data-flow/taint analysis, có report exporter, có benchmark scorer, và đã cho ra được số liệu thực nghiệm trên OWASP Benchmark.

## 3. Những thành phần đã hoàn thành trong codebase

### 3.1. Lớp thực thi và điều phối

- `aegis_sast/cli.py`: điểm vào chính cho quét mã nguồn bằng dòng lệnh.
- `aegis_sast/orchestration/service.py`: tách orchestration ra khỏi CLI, giúp pipeline có thể tái sử dụng cho dashboard hoặc các entrypoint khác.
- `aegis_sast/orchestration/repo_intake.py`: nhận diện ngôn ngữ, scan profile, framework hints và kế hoạch phân tích.

### 3.2. Detection core

- `aegis_sast/analysis/vulnerability_detector.py`: lõi quét lỗ hổng.
- `aegis_sast/analysis/rule_engine.py`: nạp và quản lý rule YAML.
- `aegis_sast/plugins/python_plugin.py`, `java_plugin.py`, `javascript_plugin.py`, `php_plugin.py`: kiến trúc plugin đa ngôn ngữ.
- Tree-sitter đã được dùng để phân tích cú pháp theo AST.
- Python hiện là lane mạnh nhất, đã có cross-file reasoning và graph-oriented analysis tốt hơn các ngôn ngữ còn lại.

### 3.3. Chuẩn hóa finding và workflow triage

- `aegis_sast/core/models.py`: schema finding, severity, vulnerability families.
- `aegis_sast/triage/engine.py`: lớp triage deterministic.
- `aegis_sast/orchestration/workflow.py`: workflow state cho luồng auditor, skeptic, judge.
- `aegis_sast/orchestration/nodes.py`: hiện thực các vai trò review chính.

### 3.4. AI layer và hướng multi-agent

- `aegis_sast/triage/ai_runner.py`: nối AI vào lớp triage.
- `aegis_sast/ai/gemini_client.py`: client Gemini hiện có.
- `aegis_sast/llm/openai_compatible_client.py`: adapter OpenAI-compatible mới, dùng được cho Ollama hoặc LM Studio khi local runtime sẵn sàng.
- `aegis_sast/orchestration/langgraph_bridge.py`: bridge tối thiểu để bọc workflow hiện tại dưới dạng graph thực thi theo hướng LangGraph.

Điều này có nghĩa là dự án **đã có nền tảng multi-agent rõ ràng về mặt kiến trúc**, nhưng chưa nên claim là đã hoàn thiện một hệ LangGraph end-to-end đầy đủ ở mọi khâu.

### 3.5. Reporting, dashboard và benchmark

- `aegis_sast/reporting/json_exporter.py`: xuất JSON.
- `aegis_sast/reporting/markdown_exporter.py`: xuất Markdown.
- `aegis_sast/integrations/sarif_formatter.py`: xuất SARIF.
- `apps/findings-dashboard`: dashboard local để đọc report, lọc finding và hỗ trợ reviewer workflow.
- `scripts/score_owasp_benchmark.py`: chấm TP/FP/FN theo ground truth.
- `scripts/run_semgrep_owasp_python.py`: chạy baseline Semgrep để so sánh công bằng.

## 4. Điểm mạnh kỹ thuật nổi bật của dự án

### 4.1. Hệ thống đã vượt mức “demo quét file đơn giản”

Aegis-SAST hiện không còn ở mức một công cụ thử nghiệm nhỏ. Dự án đã có đủ các lớp cần thiết của một hệ thống SAST có thể nghiên cứu nghiêm túc:

- detector core;
- finding normalization;
- workflow triage;
- exporter;
- dashboard;
- benchmark harness;
- baseline comparison.

### 4.2. Kiến trúc đủ tốt để tiếp tục mở rộng

Một điểm mạnh quan trọng là orchestration đã được tách ra khỏi CLI. Điều này giúp hệ thống không bị khóa cứng vào giao diện terminal, đồng thời tạo nền tảng cho các hướng mở rộng sau:

- dashboard local;
- API nội bộ;
- CI integration;
- PR scan hoặc diff-aware scan;
- reviewer memory trong product layer.

### 4.3. Có giá trị học thuật rõ ràng

Dự án không chỉ có giá trị trình diễn sản phẩm, mà còn có các trục đánh giá học thuật tương đối rõ:

- precision, recall, F1;
- false positive reduction;
- vai trò của triage layer;
- so sánh với baseline Semgrep;
- khác biệt giữa lane Python và lane Java;
- khả năng tổ chức detector core và AI workflow thành các lớp độc lập.

## 5. Kết quả benchmark đáng sử dụng khi báo cáo

### 5.1. Python lane với 4 family chính

Đây là lane mạnh nhất và nên được dùng làm trọng tâm báo cáo ở thời điểm hiện tại.

Phạm vi 4 family chính:

- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`
- `SQL_INJECTION`

Kết quả tổng hợp:

| Hệ thống | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Aegis core | 85 | 56 | 16 | 0.6028 | 0.8416 | 0.7025 |
| Semgrep baseline | 27 | 14 | 74 | 0.6585 | 0.2673 | 0.3803 |

Ý nghĩa của kết quả này là:

- Aegis đang **vượt rõ Semgrep baseline về recall và F1 tổng thể** trong phạm vi bốn family mục tiêu;
- detector hiện tại của repo không chỉ chạy được, mà đã cho kết quả thực nghiệm có sức thuyết phục;
- điểm đau chính vẫn là **false positive của PATH_TRAVERSAL**.

### 5.2. Python lane khi mở rộng lên 6 family

Ngoài bốn family chính, hệ thống đã được mở rộng benchmark thêm:

- `CODE_INJECTION`
- `OPEN_REDIRECT`

Kết quả tổng hợp:

| Hệ thống | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Aegis core | 107 | 83 | 27 | 0.5632 | 0.7985 | 0.6605 |
| Semgrep baseline | 48 | 48 | 86 | 0.5000 | 0.3582 | 0.4174 |

Kết quả này cho thấy Aegis vẫn giữ được ưu thế về recall và F1 khi mở rộng độ phủ, nhưng đồng thời cũng làm lộ rõ một quy luật thực tế: khi tăng số family, việc kiểm soát false positive trở nên khó hơn.

### 5.3. Java lane

Java đã có benchmark thực nghiệm, nhưng chưa phải lane nên dùng làm claim chính ở buổi báo cáo.

| Hệ thống | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Aegis core | 211 | 154 | 320 | 0.5781 | 0.3974 | 0.4710 |
| Semgrep baseline | 490 | 385 | 41 | 0.5600 | 0.9228 | 0.6970 |

Kết luận phù hợp nhất là:

- Java lane **đã có triển khai và đã benchmark được**;
- nhưng ở thời điểm hiện tại, lane này **chưa cạnh tranh tốt bằng Python**;
- do đó, Python nên là lane trung tâm của Thesis V1, còn Java nên được trình bày như lane breadth đã có nền tảng nhưng cần đầu tư thêm.

## 6. Vai trò của AI, multi-agent và LangGraph trong báo cáo

Đây là phần rất quan trọng vì dễ bị hỏi ngược nếu trình bày không cẩn thận.

### 6.1. Điều có thể claim

Có thể nói rằng Aegis-SAST hiện đã có:

- workflow state rõ ràng;
- các vai trò `auditor`, `skeptic`, `judge`;
- AI triage runner có schema đầu ra thống nhất;
- LangGraph bridge tối thiểu;
- local LLM adapter theo chuẩn OpenAI-compatible cho hướng Ollama hoặc LM Studio.

Điều này đủ để khẳng định hệ thống đang đi theo hướng **multi-agent SAST cho lớp triage**, chứ không còn là một detector thuần rule.

### 6.2. Điều không nên claim quá sớm

Không nên nói rằng:

- LangGraph orchestration đã hoàn chỉnh end-to-end cho toàn bộ pipeline;
- AI đã tạo ra cải thiện benchmark ổn định;
- LLM đang thay thế detector core;
- local LLM đã trở thành runtime mặc định của hệ thống.

Ở thời điểm hiện tại, cách diễn đạt an toàn và trung thực nhất là:

> Aegis-SAST đã tích hợp AI và workflow đa tác tử ở lớp triage về mặt kiến trúc; deterministic detector vẫn là lớp phát hiện chính, còn AI hiện đóng vai trò hỗ trợ đánh giá finding, explanation và chuẩn bị nền tảng cho reviewer workflow.

## 7. Những hạn chế cần nói thật trong buổi báo cáo

Các hạn chế sau đây nên được trình bày rõ ràng:

1. Python là lane mạnh nhất; các lane khác chưa đồng đều về độ sâu phân tích.
2. Cross-file reasoning hiện mạnh chủ yếu ở Python.
3. False positive của `PATH_TRAVERSAL` vẫn còn cao.
4. AI đã tích hợp về mặt kiến trúc, nhưng chưa chứng minh được improvement benchmark ổn định do phụ thuộc runtime/quota.
5. Dashboard là lớp đọc report và hỗ trợ review, không phải detector UI gắn trực tiếp với engine.
6. Local LLM adapter đã được nối vào codebase, nhưng máy hiện tại chưa cài Ollama hoặc LM Studio runtime để dùng ngay trong demo.

Việc nêu rõ các giới hạn này không làm yếu đề tài. Ngược lại, nó cho thấy người thực hiện hiểu rõ hệ thống và có thái độ nghiên cứu nghiêm túc.

## 8. Gợi ý cách trình bày ngắn với giảng viên

Nếu cần một đoạn giới thiệu ngắn trong khoảng một phút, có thể dùng cách diễn đạt sau:

> Aegis-SAST là một hệ thống SAST hybrid, trong đó detector chính được xây dựng trên AST, rule và data-flow analysis thay vì phụ thuộc hoàn toàn vào LLM. Hệ thống hiện đã có scanner core đa ngôn ngữ, workflow triage có cấu trúc, report exporter, dashboard local và benchmark trên OWASP Benchmark. Trên lane Python với bốn family mục tiêu, Aegis hiện cho recall và F1 tốt hơn Semgrep baseline trong cùng điều kiện chấm điểm. Thành phần AI đã được tích hợp ở lớp triage theo hướng multi-agent, nhưng hiện tại deterministic core vẫn là nguồn tạo ra kết quả benchmark chính, còn AI đang ở giai đoạn hoàn thiện để cải thiện chất lượng review finding một cách ổn định hơn.

Đây là cách trình bày ngắn gọn, đúng trọng tâm và không vượt quá khả năng thực của hệ thống.

## 9. Gợi ý thứ tự demo an toàn cho buổi báo cáo

Để hạn chế rủi ro khi demo, nên đi theo thứ tự sau:

1. Demo CLI trên ví dụ nhỏ để cho thấy hệ thống quét được và xuất report được.
2. Demo report JSON hoặc Markdown để giải thích finding, severity và metadata.
3. Demo dashboard bằng cách mở một report đã sinh sẵn, tránh phụ thuộc quá nhiều vào runtime scan trong lúc thuyết trình.
4. Nếu cần trình bày benchmark, dùng luôn report và score đã có sẵn trên OWASP Benchmark Python.
5. Chỉ nhắc đến AI như một lớp đã tích hợp về mặt kiến trúc; không lấy AI làm trung tâm của buổi demo nếu local runtime chưa sẵn sàng.

## 10. Việc nên làm ngay sau buổi báo cáo

Sau khi hoàn thành buổi báo cáo, các ưu tiên ngắn hạn hợp lý nhất là:

1. Giảm false positive cho `PATH_TRAVERSAL`.
2. Làm rõ hơn sự khác biệt giữa `all findings`, `visible findings` và `high-confidence findings`.
3. Hoàn thiện reviewer memory hoặc feedback loop trong dashboard.
4. Khi hạ tầng ổn định hơn, bật local LLM bằng Ollama hoặc LM Studio để AI triage chạy thật trong môi trường cục bộ.

## 11. Kết luận ngắn

Ở thời điểm hiện tại, Aegis-SAST đã có đủ bốn nền tảng quan trọng để được báo cáo như một đề tài nghiêm túc:

1. Một detector core hoạt động thực tế dựa trên AST, rule và data-flow.
2. Một kiến trúc đủ tốt để tiếp tục mở rộng thành hệ thống nhiều lớp.
3. Một benchmark harness có ground truth và baseline so sánh.
4. Một hướng AI/multi-agent được đặt đúng vào lớp triage thay vì làm lệch trọng tâm của detector.

Nói ngắn gọn, đóng góp quan trọng nhất của dự án ở giai đoạn hiện tại là: **xây dựng được một scanner core có thể benchmark được, sau đó tổ chức lớp triage và workflow theo hướng multi-agent để từng bước giảm false positive và tăng giá trị sử dụng thực tế của hệ thống**.

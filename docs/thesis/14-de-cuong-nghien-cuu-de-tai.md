# Đề cương nghiên cứu đề tài

## 1. Tên đề tài đề xuất

**Phát triển Aegis-SAST thành hệ thống Agentic Hybrid SAST đa ngôn ngữ sử dụng static analysis, knowledge loading và AI triage để phát hiện, phân loại và giải thích lỗ hổng mã nguồn**

Tên rút gọn có thể dùng khi trình bày:

- `Aegis-SAST Agent`
- `Agentic SAST with Evidence-based AI Triage`

## 2. Bối cảnh và lý do chọn đề tài

Phân tích tĩnh mã nguồn là một hướng rất quan trọng trong an toàn phần mềm vì nó cho phép phát hiện sớm lỗ hổng ngay khi chưa triển khai hệ thống. Tuy nhiên, các công cụ SAST truyền thống thường gặp ba điểm yếu lớn:

- phát hiện được nhiều dấu hiệu nghi ngờ nhưng sinh ra khá nhiều false positive,
- khó giải thích rõ vì sao một finding lại thực sự nguy hiểm,
- khó gợi ý cách xử lý theo ngữ cảnh cụ thể của mã nguồn.

Ngược lại, mô hình ngôn ngữ lớn có thế mạnh về đọc hiểu mã nguồn, giải thích luồng dữ liệu và tạo gợi ý remediation. Nhưng nếu chỉ dùng LLM độc lập mà không dựa trên bằng chứng phân tích tĩnh, kết quả rất dễ bị suy diễn, thiếu ổn định và khó benchmark một cách nghiêm túc.

Trong bối cảnh đó, hướng đi hợp lý nhất cho đề tài không phải là thay static analysis bằng AI, mà là xây dựng một kiến trúc lai:

- lớp static analysis tạo ra finding và evidence kỹ thuật,
- lớp AI agent dùng finding đó để triage, phản biện, giải thích và hỗ trợ remediation,
- toàn bộ pipeline phải có khả năng benchmark, tái lập và báo cáo được.

Điểm mạnh của đề tài này là không bắt đầu từ con số 0. Repository hiện tại đã có một scanner AST-based hoạt động thật, có plugin đa ngôn ngữ, có cross-file analysis cho Python, có AI verification seed, có JSON/Markdown report và có bộ test. Vì vậy, đề tài có nền tảng đủ tốt để nâng từ mức project portfolio lên mức đồ án tốt nghiệp và nghiên cứu khoa học.

## 3. Hiện trạng thật của repo Aegis-SAST

### 3.1. Hệ thống hiện đang có gì

Theo mã nguồn và bộ tài liệu `docs/thesis/00` đến `docs/thesis/13`, repo hiện tại đã có các thành phần sau:

| Thành phần | Hiện trạng | File / thư mục chính |
|---|---|---|
| CLI scan | Đã có entrypoint quét thư mục hoặc file | `aegis_sast/cli.py` |
| Plugin đa ngôn ngữ | Đã có Python, JavaScript, Java, PHP | `aegis_sast/plugins/` |
| Rule engine | Đã có rule YAML và cơ chế nạp rule | `aegis_sast/analysis/rule_engine.py`, `rules/*.yaml` |
| AST parsing | Đã dùng Tree-sitter thay vì regex đơn thuần | trong từng plugin |
| Taint analysis | Đã có flow source -> sink -> sanitizer | `aegis_sast/analysis/vulnerability_detector.py` và plugin |
| Cross-file analysis | Đã có chiều sâu đáng kể cho Python | `aegis_sast/analysis/call_graph.py` |
| AI verification | Đã có lớp gọi Gemini, retry, cache, structured JSON | `aegis_sast/ai/gemini_client.py` |
| Data models | Đã có `Vulnerability`, `DataFlowPath`, `AIVerification`, `ScanResult` | `aegis_sast/core/models.py` |
| Reporting | Đã có JSON exporter và Markdown exporter | `aegis_sast/reporting/` |
| Demo và test | Đã có sample project, Docker, test suite | `examples/`, `test_projects/`, `tests/` |

### 3.2. Luồng xử lý hiện tại từ đầu tới cuối

Luồng chạy của repo hiện tại có thể mô tả khá rõ bằng đúng các file đang có:

1. `aegis_sast/cli.py` nhận `target_path`, `--rules`, `--no-ai`, `--max-depth`, `--output`.
2. CLI khởi tạo config, đăng ký plugin Python/JavaScript/Java/PHP.
3. CLI tạo `RuleEngine` và `VulnerabilityDetector`.
4. `VulnerabilityDetector.analyze_directory()` xây `FunctionIndex` cho cả project để hỗ trợ cross-file Python.
5. `VulnerabilityDetector.analyze_file()` chọn plugin theo file extension, parse AST, extract source/sink/sanitizer, rồi track dataflow để sinh `Vulnerability`.
6. Nếu AI bật, `GeminiClient` sẽ chạy verify cho từng finding và gắn `AIVerification` vào object `Vulnerability`.
7. Cuối cùng CLI export JSON và Markdown report qua `JSONExporter` và `MarkdownExporter`.

Đây là một pipeline scanner thật, không còn là bản demo mô phỏng.

### 3.3. Những điểm mạnh đáng giá nhất của repo

| Điểm mạnh | Ý nghĩa với đồ án |
|---|---|
| Có scanner core thật | Có thể chứng minh năng lực kỹ thuật của nhóm, không bị rơi vào kiểu “chỉ bọc LLM” |
| Có kiến trúc plugin | Dễ giải thích hướng mở rộng đa ngôn ngữ |
| Có AST + taint analysis | Có chiều sâu hơn các project học tập chỉ dùng regex |
| Có cross-file cho Python | Đây là điểm nhấn kỹ thuật mạnh nhất để làm benchmark và demo |
| Có AI verification seed | Có nền để nâng lên AI triage thay vì xây lại từ đầu |
| Có report exporter | Dễ nâng tiếp sang SARIF, CI và benchmark pipeline |

### 3.4. Những giới hạn hiện tại cần nói thật trong báo cáo

Repo hiện tại vẫn còn mang tính scanner hơn là agent. Những điểm còn thiếu hoặc còn lệch so với mục tiêu đồ án lớn gồm:

| Hạn chế | Mô tả cụ thể |
|---|---|
| Chưa có agent orchestration | Chưa có state machine, chưa có workflow router -> triage -> validator -> reporter |
| AI mới ở mức annotate | `GeminiClient` hiện tạo `AIVerification`, chưa phải triage subsystem hoàn chỉnh |
| Chưa có normalized finding schema mạnh | `Vulnerability` hiện tốt cho scanner, nhưng chưa đủ giàu metadata cho triage, SARIF, benchmark |
| Cross-file mới mạnh ở Python | Chưa thể claim tương đương ở mọi ngôn ngữ |
| Chưa có SARIF / CI-first | Mới có JSON và Markdown output |
| Chưa có benchmark harness chính thức | Chưa có pipeline so sánh với Semgrep hoặc CodeQL |
| Có điểm lệch giữa claim và implementation | `--rules` chưa truyền chặt end-to-end, config có nhắc `html` nhưng exporter thực tế mới có JSON/Markdown |

### 3.5. Kết luận về điểm xuất phát của đề tài

Aegis-SAST hiện đang ở mức **portfolio-scale scanner có chiều sâu kỹ thuật tốt**, chưa phải **agentic SAST platform**. Vì vậy, đề tài này không nên mô tả là “xây SAST từ đầu”, mà nên mô tả đúng hơn là:

- kế thừa scanner hiện có,
- chuẩn hóa lại finding và evidence,
- xây lớp knowledge loading,
- thêm orchestration bằng LangGraph,
- biến AI verification thành AI triage,
- rồi benchmark để chứng minh đóng góp.

## 4. Phát biểu bài toán nghiên cứu

Từ hiện trạng trên, bài toán trung tâm của đề tài có thể phát biểu như sau:

**Làm thế nào để phát triển một scanner SAST AST-based hiện có thành một hệ thống agentic hybrid SAST, trong đó finding được sinh ra từ static analysis có bằng chứng rõ ràng, còn AI agent thực hiện triage, phản biện, giải thích và hỗ trợ remediation, nhằm giảm false positive và nâng chất lượng đầu ra cho benchmark, báo cáo và tích hợp thực tế?**

Bài toán này có bốn vế con:

1. Làm sao chuẩn hóa finding để cả detector, AI triage, reporting và benchmark cùng dùng một ngôn ngữ chung?
2. Làm sao “load được lỗ hổng”, tức là nạp được tri thức về CWE, OWASP, source, sink, sanitizer, false-positive pattern và fix pattern vào pipeline?
3. Làm sao thêm agent orchestration thật, thay vì chỉ gọi LLM một lần theo kiểu prompt tuyến tính?
4. Làm sao chứng minh phần AI agent tạo ra giá trị đo được chứ không chỉ tăng độ đẹp khi demo?

## 5. Mục tiêu của đề tài

### 5.1. Mục tiêu tổng quát

Phát triển Aegis-SAST thành một **hệ thống Agentic Hybrid SAST** có khả năng:

- quét mã nguồn bằng static analysis,
- chuẩn hóa finding và evidence,
- nạp tri thức lỗ hổng có cấu trúc,
- triage finding bằng AI agent,
- sinh explanation và remediation note có căn cứ,
- xuất báo cáo phù hợp cho nghiên cứu và tích hợp sản phẩm.

### 5.2. Mục tiêu kỹ thuật

| Nhóm mục tiêu | Nội dung cụ thể |
|---|---|
| Scanner core | Củng cố detector đa ngôn ngữ, rule propagation, severity rationale và sample dataset |
| Data contract | Thiết kế normalized finding schema, triage schema, evidence schema |
| Knowledge layer | Xây bộ knowledge cards cho các nhóm lỗ hổng ưu tiên |
| Agent layer | Xây LangGraph workflow điều phối finding -> knowledge -> triage -> report |
| Reporting | Bổ sung triage-rich JSON/Markdown và SARIF prototype |
| Benchmark | Xây harness so sánh với baseline và đo FP reduction |

### 5.3. Mục tiêu nghiên cứu

- Đo xem AI triage có giúp giảm false positive so với core scanner hay không.
- Đo xem knowledge loading có cải thiện explanation và remediation hay không.
- Đo xem workflow có trạng thái bằng LangGraph có ổn định hơn prompt tuyến tính hay không.
- Chứng minh giá trị của cross-file evidence trong các case Python phức tạp.

## 6. Phạm vi nghiên cứu

### 6.1. Phạm vi nên làm

| Trục | Phạm vi chọn |
|---|---|
| Ngôn ngữ trọng tâm | Python là ngôn ngữ phân tích sâu và benchmark chính; JavaScript, Java, PHP là ngôn ngữ mở rộng để chứng minh tính đa ngôn ngữ |
| Nhóm lỗ hổng ưu tiên | SQL Injection, Command Injection, Path Traversal, XSS hoặc SSRF |
| Baseline chính | Semgrep |
| Baseline mở rộng | CodeQL ở phạm vi hẹp, nếu đủ thời gian |
| Dữ liệu | `examples/`, `test_projects/`, bộ sample curated của nhóm |

### 6.2. Phạm vi không nên claim quá mức

- Không claim đây là enterprise SAST thay thế công cụ thương mại.
- Không claim cross-file sâu cho toàn bộ ngôn ngữ.
- Không claim auto-fix hoàn chỉnh cho mọi finding.
- Không mở rộng quá sớm sang dashboard lớn hoặc multi-tenant platform.
- Không đưa C++ vào phiên bản nghiên cứu chính khi chưa có plugin, rules và test tương ứng.

## 7. “Load được lỗ hổng” trong đề tài này nghĩa là gì

Đây là yêu cầu rất quan trọng của đề tài. “Load được lỗ hổng” không nên hiểu là chỉ đọc một danh sách CWE rồi chèn vào prompt, mà nên hiểu đầy đủ là:

- nạp được tri thức lỗ hổng có cấu trúc,
- liên kết tri thức đó với finding cụ thể,
- dùng tri thức này để phản biện false positive và sinh remediation hợp lý.

### 7.1. Nội dung tri thức cần nạp

Mỗi knowledge card nên chứa ít nhất:

| Trường | Ý nghĩa |
|---|---|
| `vuln_type` | Loại lỗ hổng nội bộ của Aegis-SAST |
| `cwe_id` | Mapping sang taxonomy chuẩn |
| `owasp_category` | Mapping sang OWASP Top 10 khi phù hợp |
| `description` | Mô tả ngắn gọn về bản chất lỗ hổng |
| `common_sources` | Các source thường gặp |
| `common_sinks` | Các sink thường gặp |
| `valid_sanitizers` | Sanitizer nào thực sự có tác dụng |
| `false_positive_patterns` | Mẫu dễ báo động giả |
| `severity_rationale` | Vì sao mức độ nghiêm trọng thường ở mức nào |
| `secure_fix_patterns` | Hướng sửa an toàn |
| `language_notes` | Khác biệt giữa Python, JavaScript, Java, PHP |

### 7.2. Cách nạp tri thức vào hệ thống

Trong repo này, nên đi theo hướng **curated local knowledge base** trước khi nghĩ tới vector database lớn. Hướng phù hợp với scope đồ án là:

- lưu knowledge card ở dạng YAML hoặc JSON trong repo,
- load theo `vuln_type` và `language`,
- nếu cần thì bổ sung một lớp retrieval nhẹ theo tag và keyword,
- chưa cần mở rộng ngay sang RAG phức tạp hoặc external database.

### 7.3. Giá trị của knowledge loading

Knowledge loading tạo ra ba lợi ích rất rõ:

1. AI không còn suy luận trong trạng thái thiếu ngữ cảnh.
2. Triage có thể phản biện finding theo tiêu chí nhất quán hơn.
3. Report remediation sẽ bớt “nói chung chung”, tiến gần hơn tới hướng có thể dùng thật.

## 8. Vì sao cần build agent và nên chọn LangGraph

### 8.1. Vì sao repo hiện tại chưa phải agent đúng nghĩa

Hiện tại repo có `scanner + AI verification`, nhưng chưa có:

- router quyết định finding nào đi nhánh xử lý nào,
- state chung chứa finding, evidence, knowledge và triage status,
- validator phản biện các finding confidence thấp,
- report node tổng hợp đầu ra theo logic cuối,
- orchestration log để benchmark tính ổn định của workflow.

Nói cách khác, hiện tại hệ thống mới có **AI-enabled scanner**, chưa phải **agentic scanner**.

### 8.2. So sánh LangGraph với CrewAI và AutoGen trong bài toán này

| Framework | Điểm mạnh | Điểm yếu | Phù hợp với đề tài |
|---|---|---|---|
| LangGraph | Có state rõ ràng, edge rõ ràng, debug tốt, hợp workflow kỹ thuật | Viết cấu trúc verbose hơn | Phù hợp nhất để làm lõi của đồ án |
| CrewAI | Dễ mô tả theo role, dễ thuyết trình “đa tác nhân” | Ít kiểm soát state chặt bằng LangGraph | Có thể tham khảo cách chia role, không nên là lõi chính |
| AutoGen | Hợp bài toán đối thoại nhiều agent | Dễ tốn token, khó kiểm soát determinism | Không phải ưu tiên cho repo này |

**Kết luận lựa chọn:** với repo Aegis-SAST, nên dùng **LangGraph làm lõi orchestration**, còn phần “multi-agent roles” nên được thể hiện dưới dạng các node chuyên biệt trong graph thay vì làm nhiều agent chat với nhau một cách nặng nề.

## 9. Kiến trúc đề xuất cho phiên bản đồ án lớn

### 9.1. Nguyên tắc kiến trúc

Kiến trúc mục tiêu cần bám bốn nguyên tắc:

1. **Evidence-first:** detector sinh evidence trước, AI không được thay detector.
2. **Agent-after-detector:** AI agent chỉ hoạt động sau khi finding đã được chuẩn hóa.
3. **Benchmarkable:** mọi trạng thái quan trọng đều phải log được để so sánh.
4. **Depth-first multi-language:** giữ định hướng đa ngôn ngữ, nhưng phân tầng độ sâu hỗ trợ; Python là lớp phân tích sâu, JavaScript/Java/PHP là lớp mở rộng.

### 9.2. Kiến trúc 6 lớp của hệ thống

Kế thừa trực tiếp từ `docs/thesis/04-kien-truc-muc-tieu.md`, kiến trúc đích nên gồm 6 lớp:

| Lớp | Vai trò | Kế thừa từ repo hiện tại |
|---|---|---|
| Repo Intake | Nhận repo, nhận scan profile, phân loại ngôn ngữ | mở rộng từ `cli.py` |
| Detection Core | Parse AST, load rules, extract source/sink, track taint | kế thừa `vulnerability_detector.py` và plugin |
| Finding Normalization | Chuẩn hóa finding về schema thống nhất | mở rộng từ `models.py` |
| AI Triage | Nạp knowledge, phân tích, phản biện, gán status | nâng cấp từ `gemini_client.py` |
| Remediation and Reporting | Sinh explanation, remediation note, JSON/MD/SARIF | mở rộng `reporting/` |
| Evaluation and CI | Benchmark, regression, CI, so sánh baseline | bổ sung mới |

### 9.3. Vai trò của agent trong kiến trúc

Phần “build agent” phải được xác định rõ là **nằm giữa lớp Finding Normalization và lớp Reporting**, không nằm bên trong detector. Cụ thể:

- detector tạo finding thô nhưng có evidence,
- normalizer chuyển finding về schema chuẩn,
- agent graph đọc finding chuẩn đó,
- agent graph load tri thức liên quan,
- AI triage và validator quyết định status cuối,
- reporter mới tạo báo cáo cuối cùng.

Nói ngắn gọn:

**Scanner phát hiện. Agent hiểu, phản biện và ra quyết định trình bày.**

## 10. Thiết kế LangGraph cụ thể cho repo này

### 10.1. Các role nên có trong graph

Nếu muốn trình bày theo tư duy multi-agent, repo này nên tách thành các role sau:

| Role / Node | Chức năng |
|---|---|
| `RepoRouter` | Đọc cấu trúc scan target, xác định language, profile và phạm vi scan |
| `DetectionAdapter` | Gọi detector hiện có và nhận raw findings |
| `FindingNormalizer` | Chuẩn hóa finding, evidence, severity rationale, sanitizer info |
| `KnowledgeLoader` | Nạp knowledge cards theo `vuln_type` và `language` |
| `SecurityReviewer` | Đưa ra nhận định đầu tiên: finding đáng tin đến đâu |
| `SkepticValidator` | Phản biện finding có confidence thấp hoặc evidence mâu thuẫn |
| `TriageJudge` | Gán status cuối: `confirmed`, `likely`, `needs-review`, `suppressed` |
| `Reporter` | Tạo đầu ra JSON/Markdown/SARIF và summary |
| `RemediationPlanner` | Sinh remediation note, patch idea, checklist fix |

### 10.2. State tối thiểu của graph

LangGraph chỉ thực sự có giá trị khi state được thiết kế tốt. State đề xuất cho repo này:

| Trường state | Ý nghĩa |
|---|---|
| `scan_target` | đường dẫn hoặc repo đang được quét |
| `scan_profile` | profile quét theo ngôn ngữ / scope |
| `raw_findings` | finding gốc từ detector |
| `normalized_findings` | finding sau khi chuẩn hóa |
| `current_finding` | finding đang được xử lý tại node hiện tại |
| `language` | ngôn ngữ của finding |
| `vuln_type` | loại lỗ hổng nội bộ |
| `knowledge_cards` | tri thức đã nạp cho finding theo loại lỗ hổng và ngôn ngữ |
| `triage_decision` | quyết định sơ bộ của AI |
| `triage_status` | trạng thái cuối cùng |
| `confidence` | độ tin cậy của status |
| `evidence_bundle` | source, sink, path, sanitizer, snippet, rule id |
| `explanation` | diễn giải lý do |
| `remediation_note` | gợi ý xử lý |
| `requires_manual_review` | cờ đánh dấu cần người kiểm tra |
| `report_entries` | đầu ra tích lũy cho report |
| `benchmark_tags` | metadata để dùng cho benchmark |

### 10.3. Luồng node đề xuất

Luồng graph nên đi theo thứ tự sau:

1. `repo_intake`
2. `run_detector`
3. `normalize_findings`
4. `for_each_finding`
5. `load_knowledge`
6. `initial_review`
7. `skeptic_validation` nếu confidence thấp hoặc evidence mâu thuẫn
8. `judge_triage`
9. `build_report_entry`
10. `aggregate_and_export`

### 10.4. Logic rẽ nhánh trong graph

| Điều kiện | Nhánh xử lý |
|---|---|
| Finding có evidence mạnh, path rõ, không có sanitizer hiệu quả | đi thẳng sang `judge_triage` |
| Finding có sanitizer nhưng chưa rõ hiệu quả | bắt buộc qua `skeptic_validation` |
| Finding có confidence thấp | qua `skeptic_validation` |
| Finding khớp false-positive pattern trong knowledge card | ưu tiên `suppressed` hoặc `needs-review` |
| Finding thiếu snippet hoặc metadata | đánh dấu `needs-review` |

### 10.5. Tại sao graph này phù hợp với nghiên cứu

Graph trên cho phép đề tài đo được:

- AI triage có thay đổi status so với detector ban đầu không,
- knowledge loading có làm AI ổn định hơn không,
- validator có giảm suppression sai hay không,
- workflow LangGraph có ổn định hơn một prompt tuyến tính hay không.

## 11. Mapping trực tiếp từ mã nguồn hiện tại sang kiến trúc agent

### 11.1. Mapping các module đang có

| Module hiện tại | Vai trò hiện tại | Vai trò trong kiến trúc mới |
|---|---|---|
| `aegis_sast/cli.py` | Điểm vào scan | Entry point cho repo intake và orchestration |
| `aegis_sast/analysis/vulnerability_detector.py` | Detector chính | Detection Core |
| `aegis_sast/core/models.py` | Model scanner | Nền cho normalized finding schema |
| `aegis_sast/ai/gemini_client.py` | Verify finding bằng AI | Backend cho AI triage node |
| `aegis_sast/reporting/json_exporter.py` | Xuất JSON | Report adapter |
| `aegis_sast/reporting/markdown_exporter.py` | Xuất Markdown | Report adapter |
| `aegis_sast/analysis/call_graph.py` | Cross-file Python | Evidence booster cho finding phức tạp |

### 11.2. Các module nên bổ sung

Để có agent thật, repo nên thêm các package mới sau:

```text
aegis_agents/
  graph.py
  state.py
  contracts.py
  nodes/
    repo_intake.py
    detection_adapter.py
    finding_normalizer.py
    knowledge_loader.py
    security_reviewer.py
    skeptic_validator.py
    triage_judge.py
    reporter.py
    remediation_planner.py

aegis_knowledge/
  loaders.py
  retrieval.py
  cards/
    python/
    javascript/
    shared/

aegis_sast/reporting/
  sarif_exporter.py

benchmarks/
  datasets/
  scripts/
  results/
```

### 11.3. Các object nên được thêm vào data model

Trong `models.py` hoặc package mới cho contracts, nên bổ sung:

| Object | Mục đích |
|---|---|
| `NormalizedFinding` | Đại diện finding chuẩn dùng xuyên suốt pipeline |
| `EvidenceBundle` | Gom source, sink, path, sanitizer, rule id, snippets |
| `TriageDecision` | Kết quả AI trước khi judge |
| `TriageStatus` | Enum `confirmed`, `likely`, `needs-review`, `suppressed` |
| `KnowledgeCard` | Đại diện tri thức lỗ hổng |
| `RemediationPlan` | Đại diện cho remediation note hoặc patch hint |

## 12. Khoảng trống kỹ thuật cần giải quyết trước khi build agent

Để LangGraph không chỉ là “bọc ngoài cho đẹp”, đề tài phải xử lý các gap kỹ thuật thật sau:

### 12.1. Chuẩn hóa finding schema

Hiện tại `Vulnerability` đủ dùng cho scanner nhưng chưa đủ cho:

- triage status,
- severity rationale,
- evidence completeness,
- benchmark label,
- suppression reason,
- mapping sang SARIF.

Đây là việc phải làm đầu tiên.

### 12.2. Sửa luồng custom rules

CLI đã tạo `RuleEngine(config.custom_rules_path)`, nhưng trong `VulnerabilityDetector.analyze_file()` lại khởi tạo `RuleEngine(language=plugin.get_language_name())`. Điều này khiến `--rules` chưa được đảm bảo truyền chặt từ đầu vào đến detector. Nếu không fix điểm này sớm, benchmark và demo sẽ thiếu độ tin cậy.

### 12.3. Chuẩn hóa output format

Hiện pipeline thực tế mới có JSON và Markdown. Nếu tài liệu hoặc config đang nhắc `html`, cần chỉnh lại claim hoặc bổ sung đúng implementation.

### 12.4. Tách AI verification thành AI triage

`AIVerification` hiện mới có:

- `is_vulnerable`
- `confidence`
- `explanation`
- `recommendation`

Đề tài cần nâng lên:

- trạng thái triage rõ ràng,
- suppression reason,
- evidence assessment,
- remediation note theo template,
- benchmark metadata.

## 13. Câu hỏi nghiên cứu và giả thuyết

### 13.1. Câu hỏi nghiên cứu

| Mã | Câu hỏi |
|---|---|
| RQ1 | AI triage dựa trên evidence có giúp giảm false positive so với core scanner hay không? |
| RQ2 | Knowledge loading có giúp explanation và remediation tốt hơn so với prompt không có tri thức hay không? |
| RQ3 | LangGraph orchestration có tạo ra output ổn định hơn so với prompt tuyến tính hay không? |
| RQ4 | Cross-file evidence có giúp triage đúng hơn ở các case Python phức tạp hay không? |

### 13.2. Giả thuyết nghiên cứu

| Mã | Giả thuyết |
|---|---|
| H1 | `Aegis core + AI triage` sẽ giảm false positive tốt hơn `Aegis core` |
| H2 | `AI triage + knowledge cards` sẽ cho explanation và remediation hữu ích hơn `AI triage không có knowledge` |
| H3 | `LangGraph workflow` sẽ cho status nhất quán hơn `single-prompt verification` |
| H4 | Các finding có cross-file evidence ở Python sẽ được triage chính xác hơn các finding chỉ có local evidence |

## 14. Phương pháp nghiên cứu và kế hoạch thực nghiệm

### 14.1. Phương pháp nghiên cứu

Đề tài kết hợp ba hướng:

1. **Khảo sát và đối chiếu kiến trúc** từ các hệ tham khảo như Semgrep, CodeQL, Strix, `utkusen/sast-skills`.
2. **Thiết kế và phát triển hệ thống** trên nền mã nguồn Aegis-SAST hiện có.
3. **Thực nghiệm định lượng và định tính** để đánh giá detection, triage và reporting.

### 14.2. Dataset và nguồn dữ liệu

| Nguồn | Vai trò |
|---|---|
| `examples/` | Demo luồng scan và triage cho nhiều ngôn ngữ |
| `test_projects/` | Case có thể kiểm soát ground truth |
| Bộ mẫu nhóm tự xây | Bổ sung ca SQLi, Command Injection, Path Traversal, XSS/SSRF trên Python, JavaScript, Java, PHP |
| Semgrep output | Baseline rule-based đa ngôn ngữ |
| CodeQL output | Baseline query/dataflow ở phạm vi hẹp, ưu tiên Python hoặc Java |

### 14.3. Các thí nghiệm đề xuất

| Thí nghiệm | So sánh | Mục tiêu |
|---|---|---|
| E1 | `Aegis core` vs `Aegis core + AI triage` | đo tác động của AI triage |
| E2 | `AI triage không knowledge` vs `AI triage có knowledge` | đo tác động của knowledge loading |
| E3 | `single-prompt verification` vs `LangGraph triage workflow` | đo tác động của orchestration |
| E4 | `Aegis-SAST` vs `Semgrep` | baseline chính |
| E5 | `Aegis-SAST` vs `CodeQL` ở phạm vi hẹp | baseline tham chiếu nâng cao |
| E6 | case Python cross-file có và không dùng evidence đầy đủ | làm nổi bật chiều sâu phân tích hiện tại |
| E7 | ma trận sample JavaScript, Java, PHP | chứng minh tính đa ngôn ngữ của pipeline và finding schema |

### 14.4. Metric đánh giá

| Nhóm metric | Metric cụ thể |
|---|---|
| Detection | Precision, Recall, F1-score |
| Triage | FP reduction, status consistency, manual-review rate |
| Reporting | explanation clarity, evidence completeness, remediation usefulness |
| Vận hành | runtime, số file scan, độ ổn định của workflow |

## 15. Tách bạch 4 lớp giá trị của đề tài

Đây là phần rất quan trọng để tránh viết báo cáo bị lan man hoặc claim quá mức.

| Nhóm | Nội dung cần nói |
|---|---|
| Hiện tại đã làm được | scanner core, plugin đa ngôn ngữ, AST parsing, Python cross-file, AI verification, JSON/Markdown report |
| Khoảng trống kỹ thuật | chưa có agent thật, chưa có normalized triage schema, chưa có SARIF/CI/benchmark harness, `--rules` cần siết lại |
| Đóng góp nghiên cứu | hybrid SAST + AI triage, knowledge loading, LangGraph orchestration, benchmark có số liệu |
| Giá trị demo / sản phẩm | scan repo, sinh finding có status, giải thích, remediation note, export report và benchmark summary |

## 16. Đóng góp kỳ vọng của đề tài

### 16.1. Đóng góp kỹ thuật

- Chuẩn hóa finding schema và evidence schema cho Aegis-SAST.
- Bổ sung lớp knowledge loading có cấu trúc.
- Tích hợp LangGraph thành orchestration layer thật.
- Nâng AI verification thành AI triage subsystem.
- Bổ sung SARIF prototype và benchmark harness.

### 16.2. Đóng góp nghiên cứu

- Đề xuất mô hình lai giữa static analysis và AI triage có thể benchmark.
- Đo tác động của knowledge loading lên chất lượng triage.
- Đo tác động của workflow có state lên độ ổn định của AI.
- Minh họa vai trò của cross-file evidence trong triage bảo mật.

### 16.3. Đóng góp thực tiễn

- Tạo ra một prototype đủ mạnh để làm đồ án tốt nghiệp.
- Có thể trình diễn rõ ràng trong báo cáo, demo và phản biện.
- Là nền để phát triển tiếp thành nghiên cứu khoa học hoặc công cụ nội bộ.

## 17. Rủi ro và hướng giảm thiểu

| Rủi ro | Ảnh hưởng | Hướng giảm thiểu |
|---|---|---|
| Dàn trải quá nhiều ngôn ngữ | làm agent và benchmark bị loãng | chốt Python là trục phân tích sâu, JavaScript/Java/PHP là trục mở rộng, C++ để phase sau |
| AI triage thiếu ổn định | benchmark không đẹp | dùng structured output, rubric cố định, cache, log đầy đủ |
| Thiếu ground truth | precision/recall kém tin cậy | ưu tiên sample curated có review tay |
| LangGraph quá phức tạp | tốn thời gian tích hợp | chỉ giữ các node thật sự cần thiết |
| Claim vượt implementation | dễ bị hội đồng phản biện | luôn tách rõ “đã có”, “đang làm”, “hướng mở rộng” |

## 18. Sản phẩm đầu ra kỳ vọng

Khi hoàn thành đề tài, nhóm cần có các đầu ra sau:

| Nhóm đầu ra | Nội dung |
|---|---|
| Mã nguồn | scanner core nâng cấp, `aegis_agents/`, `aegis_knowledge/`, exporter mới |
| Dữ liệu | knowledge cards, benchmark datasets, result tables |
| Tài liệu | đề cương, báo cáo, kế hoạch benchmark, kế hoạch demo, câu hỏi phản biện |
| Trình diễn | demo scan -> triage -> remediation note -> report |

## 19. Kết luận

Đề tài này nên được trình bày như một bước phát triển có chiều sâu trên nền repo Aegis-SAST hiện có, chứ không phải một ý tưởng chung chung về “dùng AI quét lỗ hổng”. Điểm mạnh nhất của hướng này là:

- trung thực với hiện trạng kỹ thuật của repo,
- làm rõ phần build agent bằng LangGraph,
- tách rõ vai trò của static analysis và AI,
- có khả năng benchmark và nghiên cứu,
- có giá trị trình bày đủ mạnh cho đồ án tốt nghiệp.

Nếu đi đúng hướng, Aegis-SAST sẽ chuyển từ một scanner có AI verification thành một **prototype Agentic Hybrid SAST có cơ sở kỹ thuật, có đóng góp nghiên cứu và có câu chuyện bảo vệ rõ ràng**.

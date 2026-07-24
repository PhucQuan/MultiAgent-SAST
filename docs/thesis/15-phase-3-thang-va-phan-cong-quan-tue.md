# KẾ HOẠCH 3 THÁNG VÀ PHÂN CÔNG NHIỆM VỤ — MÔ HÌNH CAPABILITY PARITY

## Đề tài: Phát hiện và phân loại lỗ hổng bảo mật trong mã nguồn bằng phân tích tĩnh kết hợp đồ thị đa tác nhân AI

**Thành viên thực hiện:** Phúc Quân và Tuệ
**Thời lượng:** 12 tuần (5 phase)
**Mô hình chiến lược:** Capability Parity — 4 ngôn ngữ cùng pipeline, cùng chuẩn đầu ra, cùng benchmark

**Nguyên tắc phân công chính:**

- **Tuệ chỉ phụ trách mảng AI**: AI triage, multi-agent workflow, LangGraph, knowledge loading, prompt, explanation, remediation note và các thí nghiệm liên quan đến AI.
- **Quân phụ trách toàn bộ phần còn lại**: deterministic core, nâng cấp JS/Java/PHP lên capability parity (DFG-lite, evidence extraction, taint analysis), schema, benchmark đa ngôn ngữ, baseline, SARIF, CI, dataset, reporting và tích hợp hệ thống.

---

## 1. Capability Parity là gì và tại sao chuyển sang mô hình này

### 1.1. Vấn đề của mô hình cũ

Kế hoạch trước đây chia dự án thành "Python deep lane" (phân tích sâu) và "breadth lane" (JS/Java/PHP chỉ cần smoke test và demo tối thiểu). Mô hình này có hai điểm yếu:

1. **Hội đồng sẽ hỏi thẳng:** "Đa ngôn ngữ mà chỉ Python có cross-file và evidence, còn JS/Java/PHP chỉ là plugin trên giấy thì gọi là đa ngôn ngữ kiểu gì?"
2. **Benchmark lệch:** Nếu chỉ benchmark trên Python, kết quả Precision/Recall không đại diện cho hệ thống thật. Agent AI nhận finding từ JS/Java/PHP thiếu evidence sẽ triage sai.

### 1.2. Mô hình Capability Parity

**Capability Parity** nghĩa là: 4 ngôn ngữ (Python, JavaScript, Java, PHP) cùng đi qua 1 pipeline chung và cùng tuân theo 1 chuẩn đầu ra.

**Pipeline chung:**

1. AST parsing (Tree-sitter)
2. Evidence extraction (source, sink, snippet, context)
3. DFG-lite (data-flow tracking intra-file, tối thiểu)
4. CFG-lite (control-flow skeleton, dead-path detection cơ bản)
5. NormalizedFinding + EvidenceBundle (chuẩn đầu ra thống nhất)
6. Knowledge Loading (CWE/OWASP cards theo ngôn ngữ)
7. Agent Triage (LangGraph multi-agent)
8. Benchmark (cùng harness, cùng metric)

**Chuẩn đầu ra thống nhất:** Mọi finding từ bất kỳ ngôn ngữ nào đều phải chứa đủ: `source_location`, `sink_location`, `evidence_snippets`, `data_flow_path`, `sanitizer_info`, `confidence`, `severity`, `vuln_type`, `language`. Agent AI nhận finding từ Python hay PHP đều thấy cùng format, cùng cách xử lý.

### 1.3. Parity không có nghĩa là nội bộ giống hệt

Cần nói rõ: **parity là về chuẩn đầu ra và workflow, không phải về nội bộ triển khai**. Cụ thể:

- Python vẫn là ngôn ngữ có chiều sâu nhất: cross-file call graph, function summary, inter-procedural taint. Đây là thế mạnh đã xây từ đầu, không bỏ đi.
- JavaScript sẽ có DFG-lite intra-file, callback/promise-aware source-sink tracking. Không cần cross-file ở mức Python.
- Java sẽ có DFG-lite intra-file, class-method-aware tracking. Juliet Test Suite làm ground truth sẵn.
- PHP sẽ có DFG-lite intra-file, superglobal source detection, taint tracking cơ bản. PHP có ưu thế là pattern source-sink rõ ràng ($ _GET, $ _POST → query/exec).

Điểm chung bắt buộc: **cùng output NormalizedFinding + EvidenceBundle, cùng đi qua Agent Triage, cùng cách tính Precision/Recall/F1 trong benchmark**.

### 1.4. C++ không nằm trong phạm vi

C++ không nằm trong kế hoạch 12 tuần này. Lý do: C++ đòi hỏi xử lý pointer, memory model, preprocessor phức tạp hơn nhiều lần so với 4 ngôn ngữ hiện tại. C++ được ghi vào mục "Hướng phát triển" trong báo cáo.

---

## 2. Mục tiêu của giai đoạn 12 tuần

Giai đoạn 12 tuần này không bắt đầu từ con số 0. Đây là giai đoạn nâng cấp Aegis-SAST từ một scanner có nền tảng tốt (nhưng lệch pha giữa các ngôn ngữ) thành một prototype đa ngôn ngữ đủ mạnh cho khóa luận tốt nghiệp.

Ở thời điểm lập kế hoạch, dự án đã có:

- Plugin đa ngôn ngữ cho Python, JavaScript, Java, PHP (nhưng JS/Java/PHP mới ở mức AST + rule matching).
- Python graph core với CFG/DFG, function summary, dead-path pruning, cross-file call graph.
- AI verification seed qua Gemini.
- JSON, Markdown exporter.
- Mini benchmark ablation cho Python graph.

Mục tiêu 12 tuần được chốt thành 4 trục:

1. **Nâng 4 ngôn ngữ lên capability parity** — JS/Java/PHP phải có DFG-lite, evidence extraction, taint analysis đủ để tạo NormalizedFinding có chất lượng. Python tiếp tục giữ chiều sâu cross-file.
2. **Hoàn thiện lớp AI multi-agent có kiểm soát** — LangGraph graph, knowledge cards, conditional routing, triage node hoạt động trên finding từ cả 4 ngôn ngữ.
3. **Xây benchmark đa ngôn ngữ** — Precision/Recall/F1 trên cả Python, JS, Java, PHP. Đối chứng Semgrep.
4. **Đóng gói thành hồ sơ bảo vệ** — báo cáo, demo, số liệu, slide.

---

## 3. Nguyên tắc phân công

### 3.1. Nguyên tắc tổng quát

- Các phần việc về **scanner, DFG-lite, evidence extraction, taint analysis cho 4 ngôn ngữ, rules, benchmark, SARIF, Semgrep baseline, CI** do **Quân** chịu trách nhiệm chính. Quân đã xây toàn bộ scanner core từ đầu, hiểu rõ kiến trúc plugin và Tree-sitter.
- Các phần việc về **AI, LangGraph, prompt, triage, multi-agent reasoning, knowledge cards, explanation, remediation note** do **Tuệ** chịu trách nhiệm chính. Tách rõ phần AI thành module độc lập.

### 3.2. Ranh giới trách nhiệm

**Quân không phụ trách:**

- Prompt engineering.
- Thiết kế node AI trong LangGraph.
- LangGraph graph definition.
- Explanation generation.
- Remediation note generation.
- AI ablation experiments.

**Tuệ không phụ trách chính:**

- Detector core và vulnerability_detector.
- Plugin parsing (Python, JS, Java, PHP).
- DFG-lite / CFG-lite cho bất kỳ ngôn ngữ nào.
- Evidence extraction pipeline.
- Benchmark harness nền.
- Semgrep adapter.
- SARIF formatter.
- CI/CD pipeline.

### 3.3. Điểm giao nhau bắt buộc (Contract)

- Quân cung cấp `NormalizedFinding`, `EvidenceBundle`, benchmark metadata và output schema ổn định cho Tuệ — format giống nhau bất kể ngôn ngữ nguồn.
- Tuệ tiêu thụ contract đó để xây AI workflow, triage decision và report enrichment.
- Mọi thay đổi schema phải được thống nhất trước khi code. Không ai tự ý đổi schema mà không báo người kia.

---

## 4. Đầu ra chính của từng người

**Bảng 1. Deliverable chính theo thành viên**

| Thành viên | Deliverable chính | Phần báo cáo viết |
|---|---|---|
| Quân | Deterministic core, DFG-lite/CFG-lite cho JS/Java/PHP, evidence extraction pipeline đa ngôn ngữ, benchmark harness đa ngôn ngữ, Semgrep baseline, SARIF/CI, datasets, Mock Data, polyglot demo | Chương core scanner, kiến trúc hệ thống, capability parity, benchmark đa ngôn ngữ, SARIF |
| Tuệ | LangGraph workflow, AI triage nodes, knowledge cards (đa ngôn ngữ), prompt/schema AI, conditional routing, explanation/remediation, ablation experiments | Chương AI agent, knowledge loading, ablation study, đánh giá AI |

---

## 5. Kế hoạch 12 tuần theo 5 phase

### Phase 1. Tuần 1-2: Khóa phạm vi, khóa schema, tạo Mock Data đa ngôn ngữ

**Mục tiêu:** Chốt schema contract giữa core và AI. Tạo Mock Data đa ngôn ngữ để Tuệ bắt đầu phát triển agent song song. Đánh giá hiện trạng 4 ngôn ngữ.

**Tại sao phase này quan trọng:** Schema là contract duy nhất giữa core và AI. Nếu không khóa từ đầu, tích hợp cuối kỳ sẽ vỡ. Mock Data đa ngôn ngữ giúp Tuệ test agent trên finding từ cả 4 ngôn ngữ ngay từ đầu.

**Quân thực hiện:**

- Rà soát deterministic core hiện có: kiểm tra plugin nào chạy ổn, plugin nào cần sửa cho từng ngôn ngữ.
- Đánh giá gap analysis cho JS/Java/PHP: hiện tại mỗi ngôn ngữ đang thiếu gì so với chuẩn parity (DFG-lite, evidence extraction, taint tracking).
- Khóa lại `NormalizedFinding`, `EvidenceBundle`, `triage metadata` — đảm bảo schema chứa trường `language` và các trường evidence bắt buộc.
- Tạo 25-35 file JSON Mock Data finding giả lập đúng schema, phân bổ đều 4 ngôn ngữ.

**Tuệ thực hiện:**

- Khóa mô hình AI triage status: `confirmed`, `likely`, `needs-review`, `suppressed`.
- Khóa contract đầu ra cho từng node LangGraph: mỗi node nhận gì, trả gì.
- Chốt format Knowledge Card: các trường bắt buộc, cách load, hỗ trợ trường `language` để rubric theo ngôn ngữ.
- Chốt logic conditional routing ban đầu (xem mục 7).

**KPI phase 1:**

- Có schema finding/evidence ổn định, viết thành tài liệu, bao phủ 4 ngôn ngữ.
- Có gap analysis rõ ràng: mỗi ngôn ngữ cần nâng cấp gì.
- Có 25-35 file Mock Data JSON (7-10 Python, 6-8 JavaScript, 6-8 Java, 5-7 PHP).
- Có tài liệu scope: 12 tuần này làm gì, không làm gì, C++ nằm ở đâu.

### Phase 2. Tuần 3-5: Xây DFG-lite và evidence extraction cho JS/Java/PHP, Knowledge Layer

**Mục tiêu:** Đây là phase quyết định của mô hình capability parity. Quân xây DFG-lite, evidence extraction, và taint analysis cơ bản cho JavaScript, Java, PHP — nâng 3 ngôn ngữ này từ "chỉ có AST + rule matching" lên "có data-flow tracking và evidence thật". Song song, Tuệ xây knowledge layer trên Mock Data.

**Tại sao phase này quan trọng:** Nếu JS/Java/PHP không có evidence thật, agent AI sẽ triage trên dữ liệu rỗng và cho kết quả vô nghĩa. Phase này là nơi parity được xây dựng.

**Quân thực hiện:**

**Tuần 3 — JavaScript DFG-lite + evidence:**

- Xây DFG-lite cho JavaScript: intra-file data-flow tracking, xử lý callback/promise cơ bản, variable assignment chain.
- Xây evidence extraction cho JS: trích source (req.params, req.query, req.body), sink (eval, exec, query, innerHTML), snippet context.
- Tạo Express.js examples: SQLi, XSS DOM-based, eval injection. Ít nhất 5 test cases.
- Chuẩn hóa JS finding output về đúng NormalizedFinding schema.

**Tuần 4 — Java DFG-lite + evidence:**

- Xây DFG-lite cho Java: intra-file data-flow, class-method-aware tracking, constructor chain.
- Xây evidence extraction cho Java: trích source (HttpServletRequest, getParameter), sink (Statement.execute, ProcessBuilder, FileWriter), snippet context.
- Tạo Java examples: JDBC SQLi, Servlet XSS, command injection. Ít nhất 5 test cases.
- Chuẩn hóa Java finding output về đúng NormalizedFinding schema.

**Tuần 5 — PHP DFG-lite + evidence, tổng hợp parity:**

- Xây DFG-lite cho PHP: intra-file data-flow, superglobal source detection ($ _GET, $ _POST, $ _REQUEST, $ _COOKIE), variable tracking.
- Xây evidence extraction cho PHP: trích source (superglobals), sink (mysql_query, exec, system, include, eval), snippet context.
- Tạo PHP examples: SQLi, command injection, file inclusion. Ít nhất 5 test cases.
- Chạy parity check: quét cả 4 ngôn ngữ, xác minh output đều tuân theo cùng schema.

**Chiến lược tái sử dụng:** Quân xây 1 framework evidence extraction dùng chung (class `BaseEvidenceExtractor`) với interface thống nhất: `extract_sources()`, `extract_sinks()`, `build_data_flow()`, `build_evidence_bundle()`. Mỗi ngôn ngữ kế thừa và override phần đặc thù. Điều này giúp tiết kiệm thời gian đáng kể so với xây riêng từng ngôn ngữ từ đầu.

**Tuệ thực hiện (tuần 3-5):**

- Viết Knowledge Cards cho 5 nhóm lỗi ưu tiên: SQL Injection, Command Injection, Path Traversal, XSS, SSRF. Mỗi card gồm: mô tả, common sources/sinks theo từng ngôn ngữ (Python/JS/Java/PHP), valid sanitizers theo ngôn ngữ, false-positive patterns, secure fix patterns.
- Thiết kế sanitizer rubric đa ngôn ngữ: sanitizer nào hợp lệ cho Python, JS, Java, PHP. Ví dụ: `parameterized query` hợp lệ cho cả 4, `htmlspecialchars()` chỉ hợp lệ cho PHP.
- Xây KnowledgeLoader node: nhận `vuln_type` + `language`, trả về card phù hợp.
- Test KnowledgeLoader trên Mock Data từ cả 4 ngôn ngữ.

**KPI phase 2:**

- JavaScript có DFG-lite, evidence extraction, ít nhất 5 test cases scan chạy được.
- Java có DFG-lite, evidence extraction, ít nhất 5 test cases scan chạy được.
- PHP có DFG-lite, evidence extraction, ít nhất 5 test cases scan chạy được.
- Output từ cả 4 ngôn ngữ đều tuân theo NormalizedFinding schema.
- Knowledge layer có 5 cards đa ngôn ngữ, KnowledgeLoader chạy được.

### Phase 3. Tuần 6-7: Semgrep baseline, Python evidence mở rộng, AI agent core

**Mục tiêu:** Củng cố Python evidence (vẫn là ngôn ngữ sâu nhất), bắt đầu Semgrep baseline đa ngôn ngữ, và LangGraph agent chạy trên finding thật từ cả 4 ngôn ngữ.

**Tại sao phase này quan trọng:** Parity đã được xây ở phase 2, giờ cần kiểm chứng bằng baseline thật (Semgrep) và agent AI phải xử lý được finding từ mọi ngôn ngữ.

**Quân thực hiện:**

- Mở rộng Python evidence: evidence slicing, graph-aware metadata (call-chain depth, cross-file flag, sanitizer location) vào EvidenceBundle.
- Bổ sung metadata benchmark vào finding cho cả 4 ngôn ngữ.
- Tích hợp Semgrep adapter: chạy Semgrep trên cùng dataset, lưu output để so sánh. Chạy trên Python + Java + JavaScript (Semgrep hỗ trợ tốt 3 ngôn ngữ này).
- Mở rộng synthetic dataset: thêm case cross-file Python, false positive có sanitizer, dead-path.

**Tuệ thực hiện:**

- Cài đặt các node AI trên finding thật (không chỉ Mock Data): Planner, KnowledgeLoader, Auditor.
- Phát triển LangGraph graph: state definition, edge routing, node registration.
- Cài đặt SkepticValidator: nhận finding có confidence thấp hoặc medium, phản biện dựa trên knowledge card.
- Cài đặt Judge: gán triage status cuối cùng dựa trên kết quả Auditor và SkepticValidator.
- Test agent trên finding thật từ ít nhất 3 ngôn ngữ khác nhau.

**KPI phase 3:**

- Python có evidence bundle đầy đủ hơn.
- Semgrep baseline chạy được trên ít nhất Python + Java dataset.
- LangGraph graph chạy end-to-end trên finding thật từ 4 ngôn ngữ, output đúng schema.

### Phase 4. Tuần 8-10: Tích hợp end-to-end và thực nghiệm

**Mục tiêu:** Nối core + agent thành pipeline hoàn chỉnh cho cả 4 ngôn ngữ. Chạy benchmark đa ngôn ngữ và ablation study.

**Tại sao phase này quan trọng:** Đây là lúc hệ thống phải chạy từ đầu đến cuối trên cả 4 ngôn ngữ. Nếu tích hợp thất bại ở đây, phase 5 không có gì để viết.

**Quân thực hiện:**

- Nối deterministic core với benchmark harness: batch chạy toàn bộ dataset đa ngôn ngữ, output metrics tự động.
- Hoàn thiện SARIF exporter: output đúng SARIF v2.1.0 schema, hỗ trợ 4 ngôn ngữ.
- Chạy benchmark batch trên Ground Truth Dataset (xem mục 8) cho Python, JavaScript, Java, PHP.
- Chạy Semgrep đối chứng trên cùng dataset.
- Chuẩn bị polyglot demo project: 1 repo chứa Python + JS + Java + PHP, scan một lần ra report đa ngôn ngữ thống nhất.

**Tuệ thực hiện:**

- Hoàn thiện LangGraph end-to-end: toàn bộ graph chạy trên finding từ 4 ngôn ngữ.
- Triển khai conditional routing thật (xem mục 7).
- Chạy 3 thí nghiệm ablation (xem mục 9):
  - E1: static-only vs static + AI (trên finding đa ngôn ngữ)
  - E2: no-knowledge vs knowledge
  - E3: single-prompt vs LangGraph workflow
- Thu thập số liệu: token usage, route distribution, triage consistency theo từng ngôn ngữ.

**KPI phase 4:**

- Có alpha demo: scan → triage → report chạy end-to-end trên 4 ngôn ngữ.
- Có bảng số liệu ablation E1/E2/E3 ban đầu.
- Có bảng Precision/Recall/F1 theo từng ngôn ngữ.
- SARIF output validate được.

### Phase 5. Tuần 11-12: Benchmark tổng hợp, báo cáo, chuẩn bị bảo vệ

**Mục tiêu:** Đóng gói kết quả thành đầu ra đủ mạnh cho khóa luận.

**Quân thực hiện:**

- Chạy benchmark chính thức trên Ground Truth Dataset: tính Precision, Recall, F1 cho từng ngôn ngữ và tổng hợp.
- Tổng hợp bảng so sánh Aegis-SAST vs Semgrep theo từng ngôn ngữ.
- Chốt phần báo cáo: core scanner, kiến trúc, capability parity, benchmark đa ngôn ngữ, SARIF.
- Chuẩn bị demo kỹ thuật: quay video hoặc live demo polyglot scan.

**Tuệ thực hiện:**

- Chốt kết quả ablation E1/E2/E3: bảng số liệu, biểu đồ, nhận xét.
- Chốt phần báo cáo: AI agent, LangGraph workflow, knowledge loading, ablation study.
- Chuẩn bị slide và kịch bản trình bày phần AI.
- Chuẩn bị trả lời phản biện: "AI có bịa không?", "token tốn bao nhiêu?", "parity thật hay trên giấy?", "knowledge cards có bias không?"

**KPI phase 5:**

- Có bảng Precision/Recall/F1 đa ngôn ngữ đủ để bảo vệ.
- Có bảng ablation AI đủ để chứng minh đóng góp.
- Có báo cáo hoàn chỉnh.
- Có demo polyglot ổn định, chạy được trước hội đồng.

---

## 6. Chiến lược Mock Data đa ngôn ngữ

**Vấn đề:** Tuệ cần finding data để phát triển agent, nhưng core scanner chưa hoàn thiện parity ở phase 1. Nếu Tuệ chờ Quân xong mới bắt đầu, sẽ mất 4-5 tuần trống.

**Giải pháp:** Quân tạo 25-35 file JSON finding giả lập đúng `NormalizedFinding` schema, phân bổ đều 4 ngôn ngữ, giao cho Tuệ từ tuần 2. Tuệ dùng Mock Data này phát triển agent song song.

**Nội dung Mock Data:**

- 7-10 finding Python: SQLi cross-file (TP), command injection (TP), path traversal có sanitizer (FP), dead-path false alarm (FP), XSS (TP), SSRF (TP).
- 6-8 finding JavaScript: XSS DOM-based (TP), eval injection (TP), prototype pollution (FP), Express SQLi (TP), callback-chain injection (TP).
- 6-8 finding Java: JDBC SQLi (TP), Servlet XSS (TP), path traversal (TP), over-reported null check (FP), PreparedStatement false alarm (FP).
- 5-7 finding PHP: mysql_query SQLi (TP), exec command injection (TP), include file inclusion (TP), htmlspecialchars false alarm (FP), PDO prepared statement (FP).

**Yêu cầu Mock Data:**

- Đúng schema `NormalizedFinding` đã khóa ở tuần 1.
- Có nhãn ground truth (TP hay FP) để Tuệ test triage accuracy.
- Mỗi file JSON chứa 1 finding với đầy đủ: source, sink, evidence, data_flow_path, severity, language, vuln_type.
- Có finding từ cả 4 ngôn ngữ để Tuệ test agent xử lý đa ngôn ngữ từ đầu.

**Thời điểm chuyển giao:** Cuối tuần 2. Từ tuần 6 trở đi, Tuệ chuyển sang dùng finding thật từ core.

---

## 7. Conditional Routing

**Mục đích:** Không phải mọi finding đều cần qua toàn bộ pipeline AI. Finding rõ ràng thì đi nhanh, finding mờ thì cần kiểm tra kỹ hơn. Routing giúp tiết kiệm token và giảm latency.

**Logic routing:**

| Mức confidence | Routing | Lý do |
|---|---|---|
| High (>= 0.8) | Finding đi thẳng từ Auditor → Judge, bỏ qua SkepticValidator | Evidence mạnh, path rõ, không có sanitizer hiệu quả |
| Medium (0.5 - 0.8) | Finding bắt buộc qua SkepticValidator → Judge | Có dấu hiệu nhưng chưa chắc chắn, cần phản biện |
| Low (< 0.5) | Finding qua SkepticValidator, nếu đồng ý suppress → Judge gán `suppressed`, nếu không → `needs-review` | Confidence thấp, cần kiểm tra kỹ |

**Điều kiện bổ sung:**

- Finding khớp false-positive pattern trong knowledge card → ưu tiên route qua SkepticValidator bất kể confidence.
- Finding thiếu snippet hoặc evidence không đầy đủ → tự động gán `needs-review`, không gán `confirmed`.
- Evidence quality từ JS/Java/PHP có thể thấp hơn Python trong giai đoạn đầu → agent cần xử lý gracefully khi evidence ít.

**Tuệ chịu trách nhiệm:** cài đặt routing logic trong LangGraph graph, log mọi route decision để dùng cho ablation study.

---

## 8. Ground Truth Dataset đa ngôn ngữ

Để benchmark đa ngôn ngữ có ý nghĩa, cần ground truth có nhãn rõ ràng cho từng ngôn ngữ.

**A. Synthetic Dataset Python (Quân tự viết)**

- 50-100 mẫu Python: SQLi (intra-file và cross-file), command injection, path traversal, XSS, SSRF.
- Mỗi mẫu có nhãn ground truth: TP hoặc FP. Gồm cả case có sanitizer, dead-path, và cross-file.

**B. Juliet Test Suite — Java (NIST, public domain)**

- CWE-89 SQL Injection: khoảng 50-80 test cases có nhãn good/bad.
- CWE-79 XSS: khoảng 50-80 test cases có nhãn good/bad.
- Juliet là dataset chuẩn được nhiều paper SAST dùng, hội đồng sẽ công nhận.

**C. Synthetic Dataset JavaScript (Quân tự viết)**

- 30-50 mẫu JavaScript: Express.js SQLi, XSS DOM-based, eval injection, prototype pollution.
- Mỗi mẫu có nhãn ground truth.
- Tại sao cần tự tạo: Juliet không có JavaScript.

**D. Synthetic Dataset PHP (Quân tự viết)**

- 20-30 mẫu PHP: mysql_query SQLi, exec/system command injection, include file inclusion, XSS.
- Mỗi mẫu có nhãn ground truth.
- PHP có pattern source-sink rõ ràng, dataset dễ viết hơn.

**E. OWASP Benchmark (mở rộng nếu đủ thời gian)**

- Dùng một phần OWASP Benchmark cho Java để bổ sung ground truth.

**Quân chịu trách nhiệm:** tạo và duy trì toàn bộ dataset, gán nhãn ground truth, viết script benchmark.

---

## 9. Ablation Study

Ablation study là phần thí nghiệm quan trọng nhất của lớp AI. Mục tiêu: chứng minh từng thành phần AI tạo ra giá trị đo được. Thay đổi so với kế hoạch cũ: ablation giờ chạy trên finding đa ngôn ngữ, không chỉ Python.

**E1: Static-only vs Static + AI Triage**

- So sánh: Aegis-SAST core scanner (không AI) vs Aegis-SAST core + LangGraph AI triage.
- Giả thuyết: AI triage giúp giảm false positive rate ít nhất 15-20%.
- Metric: Precision, FP count, FP reduction rate.
- Dataset: Synthetic Python + Juliet Java + Synthetic JavaScript + Synthetic PHP.

**E2: No-Knowledge vs Knowledge-Assisted**

- So sánh: AI triage không load knowledge cards vs AI triage có load knowledge cards.
- Giả thuyết: Knowledge cards giúp AI triage nhất quán hơn và explanation hữu ích hơn.
- Metric: Triage consistency (chạy 3 lần, đếm finding thay đổi status), explanation quality (đánh giá thủ công).
- Dataset: 50 finding mix từ 4 ngôn ngữ.

**E3: Single-Prompt vs LangGraph Workflow**

- So sánh: Gọi Gemini 1 lần vs LangGraph workflow đa node.
- Giả thuyết: LangGraph workflow cho triage ổn định hơn single-prompt, đặc biệt ở finding medium confidence.
- Metric: Triage accuracy (so với ground truth), consistency, token usage.
- Dataset: 30 finding mix TP/FP từ 4 ngôn ngữ.

**Tuệ chịu trách nhiệm:** thiết kế thí nghiệm, chạy thí nghiệm, thu thập số liệu, viết phân tích.

---

## 10. Ma trận tiến độ theo tuần

**Bảng 2. Phân công chi tiết theo từng tuần**

| Tuần | Quân | Tuệ | Đầu ra chính |
|---|---|---|---|
| 1 | Rà soát core, plugin, schema. Gap analysis cho JS/Java/PHP. | Rà soát AI seed, khóa triage states, thiết kế node contracts. | Báo cáo hiện trạng + gap analysis. |
| 2 | Chốt NormalizedFinding + EvidenceBundle schema. Tạo 25-35 Mock Data JSON đa ngôn ngữ. | Chốt LangGraph state schema, knowledge card format, nhận Mock Data. | Contract ổn định. Mock Data giao xong. |
| 3 | Xây DFG-lite + evidence extraction cho JavaScript. Tạo Express.js examples (5+ tests). | Viết knowledge cards cho SQLi + XSS (đa ngôn ngữ). Code KnowledgeLoader trên Mock Data. | JS DFG-lite + 2 knowledge cards. |
| 4 | Xây DFG-lite + evidence extraction cho Java. Tạo Java examples (5+ tests). | Viết knowledge cards cho CmdI, Path Traversal, SSRF. Hoàn thiện KnowledgeLoader. | Java DFG-lite + 5 knowledge cards. |
| 5 | Xây DFG-lite + evidence extraction cho PHP. Tạo PHP examples (5+ tests). Chạy parity check 4 ngôn ngữ. | Test KnowledgeLoader trên Mock Data 4 ngôn ngữ. Bắt đầu thiết kế Planner node. | PHP DFG-lite. Parity check pass. |
| 6 | Mở rộng Python evidence (slicing, graph metadata). Bổ sung metadata benchmark. | Cài Planner + KnowledgeLoader + Auditor node. Chuyển sang finding thật. | Python evidence mở rộng. Agent core nodes. |
| 7 | Tích hợp Semgrep baseline. Chạy Semgrep trên Python + Java + JS dataset. | Cài SkepticValidator + Judge. Test routing cơ bản. Graph chạy end-to-end. | Semgrep baseline. Agent end-to-end. |
| 8 | Hoàn thiện SARIF exporter. Nối core với benchmark harness đa ngôn ngữ. | Hoàn thiện conditional routing. Tối ưu prompt. | Alpha pipeline đa ngôn ngữ. |
| 9 | Chạy benchmark trên Synthetic + Juliet cho 4 ngôn ngữ. Chuẩn bị dataset chính thức. | Chạy ablation E1 + E2 trên finding đa ngôn ngữ. | Số liệu benchmark + ablation ban đầu. |
| 10 | Chạy Semgrep đối chứng đa ngôn ngữ. Tổng hợp Precision/Recall/F1 theo ngôn ngữ. Chuẩn bị polyglot demo. | Chạy ablation E3. Thu thập token usage. Phân tích kết quả theo ngôn ngữ. | Bảng so sánh hoàn chỉnh. |
| 11 | Viết báo cáo: core, capability parity, benchmark đa ngôn ngữ, SARIF. Rà soát repo. | Viết báo cáo: AI agent, LangGraph, knowledge, ablation. | Bản báo cáo gần hoàn chỉnh. |
| 12 | Chốt số liệu, quay demo polyglot, rà soát repo lần cuối. | Chốt slide AI, script trình bày, chuẩn bị trả lời phản biện. | Hồ sơ bảo vệ hoàn chỉnh. |

---

## 11. Quy trình phối hợp giữa Quân và Tuệ

### 11.1. Dòng dữ liệu

**Quân cung cấp cho Tuệ:**

- Schema NormalizedFinding và EvidenceBundle (tuần 2, cập nhật nếu cần).
- Mock Data JSON đa ngôn ngữ (tuần 2, 25-35 file).
- Finding thật từ detector (từ tuần 6 trở đi — sau khi parity cơ bản hoàn thành).
- Benchmark metadata: ground truth labels, dataset info theo từng ngôn ngữ.

**Tuệ trả ngược về cho Quân:**

- Triage decision schema: status, confidence, route taken.
- Explanation và remediation note cho từng finding.
- Nhãn triage cuối cùng để Quân đưa vào report và benchmark.
- Token usage và route summary cho phần evaluation trong báo cáo.

### 11.2. Quy tắc thay đổi schema

- Mọi thay đổi schema phải chốt bằng tài liệu ngắn (1 trang markdown) trước khi code.
- Không đổi schema giữa chừng mà không cập nhật benchmark, report, và Mock Data.
- Nếu có breaking change: Quân cập nhật adapter phía core + Mock Data, Tuệ cập nhật contract phía AI + LangGraph state.
- Deadline thay đổi schema lớn: hết tuần 7. Từ tuần 8 trở đi, schema phải ổn định.

### 11.3. Quy tắc review chéo

- Review chéo ít nhất 1 lần mỗi tuần, tập trung vào điểm giao nhau (schema, contract, output format).
- Review theo module, không review tràn lan toàn bộ code của nhau.
- Các thay đổi ảnh hưởng benchmark hoặc AI contract phải được kiểm tra lại ở cả hai phía trước khi merge.

### 11.4. Kênh liên lạc

- Chat nhóm hàng ngày cho cập nhật nhanh.
- Meeting tuần (30 phút) vào đầu mỗi tuần để sync tiến độ.
- Blocker liên quan schema: giải quyết trong vòng 24 giờ.

---

## 12. Technology Stack

**Bảng 3. Công nghệ sử dụng**

| Thành phần | Công nghệ | Phiên bản / Ghi chú |
|---|---|---|
| Ngôn ngữ chính | Python | 3.12+ |
| AST parsing | Tree-sitter | tree-sitter-python, tree-sitter-javascript, tree-sitter-java, tree-sitter-php |
| Agent orchestration | LangGraph | Graph-based multi-agent workflow |
| LLM API | Gemini 2.0 Flash | Qua Google AI API, dùng cho triage và explanation |
| Data validation | Pydantic | Schema validation cho NormalizedFinding, EvidenceBundle, TriageDecision |
| CLI framework | click | Command-line interface cho scanner |
| Terminal output | Rich | Pretty print, progress bar, bảng kết quả |
| Report format | SARIF v2.1.0 | Chuẩn công nghiệp cho SAST output |
| Retry logic | tenacity | Retry khi gọi API Gemini bị lỗi |
| Caching | diskcache | Cache response Gemini để tiết kiệm token |
| Testing | pytest | Unit test và integration test |
| Baseline | Semgrep | Công cụ SAST mã nguồn mở làm đối chứng |

---

## 13. Rủi ro và hướng giảm thiểu

**Bảng 4. Rủi ro chính của giai đoạn 12 tuần**

| Rủi ro | Ảnh hưởng | Hướng giảm thiểu |
|---|---|---|
| Nâng 3 ngôn ngữ (JS/Java/PHP) lên parity tốn nhiều thời gian hơn dự kiến | Trễ toàn bộ kế hoạch, phase 3-4 bị dồn | Xây framework evidence extraction dùng chung (BaseEvidenceExtractor), tái sử dụng pattern giữa các ngôn ngữ. Mỗi ngôn ngữ chỉ cần override phần đặc thù. Nếu trễ quá: PHP có thể giảm scope xuống DFG-lite tối thiểu |
| DFG-lite cho JS khó hơn dự kiến do callback/async | JS evidence kém, triage JS sai | Giới hạn scope: chỉ xử lý synchronous flow và callback đơn giản (Express middleware chain). Không cố xử lý full async/await chain |
| AI bị chậm hơn core, tích hợp trễ | Tích hợp cuối kỳ bị nghẽn | Khóa contract sớm, dùng Mock Data ngay từ tuần 2, Tuệ phát triển song song |
| Python graph mở rộng quá nặng | Trễ benchmark | Chỉ đi theo hướng evidence slicing thực dụng, không cố xây full CPG |
| Semgrep baseline chưa kịp | Yếu phần đối chứng | Ưu tiên Semgrep trước CodeQL, chạy trên Python + Java + JS trước |
| Chi phí token cao khi chạy AI triage đa ngôn ngữ | Tốn tiền API | Batch grouping, conditional routing, diskcache |
| Ground truth thiếu hoặc sai nhãn cho JS/PHP | Precision/Recall không đáng tin | Ưu tiên sample curated do Quân gán nhãn thủ công, review trước benchmark |
| Scope AI và non-AI chồng lấn | Khó quản lý trách nhiệm | Giữ nguyên nguyên tắc: Tuệ làm AI, Quân làm toàn bộ phần còn lại |

---

## 14. Ethical Considerations

Đề tài này chỉ thực hiện **phân tích tĩnh mã nguồn** (static analysis). Nhóm cam kết:

- **Không thực hiện exploit hay tấn công** bất kỳ hệ thống thật nào. Toàn bộ quét scan diễn ra trên mã nguồn tĩnh, không chạy mã độc, không gửi payload.
- **Không quét mã nguồn của bên thứ ba** mà không có quyền. Dataset dùng cho benchmark là: Juliet Test Suite (public domain, NIST), OWASP Benchmark (open source), và mã nguồn tự viết.
- **Không thu thập dữ liệu cá nhân.** Scanner không truy cập database, không đọc credential, không gửi dữ liệu ra ngoài.
- **AI chỉ phân tích mã nguồn** đã được cung cấp. Prompt gửi lên Gemini API chỉ chứa code snippet và finding metadata, không chứa thông tin nhạy cảm.
- **Kết quả benchmark được báo cáo trung thực**, bao gồm cả các trường hợp hệ thống hoạt động chưa tốt. Nhóm không cherry-pick số liệu.

---

## 15. Kết luận

Kế hoạch 12 tuần này chuyển từ mô hình "Python sâu, 3 ngôn ngữ còn lại cho có" sang mô hình **Capability Parity**: 4 ngôn ngữ cùng pipeline, cùng chuẩn đầu ra, cùng benchmark.

Thay đổi lớn nhất so với kế hoạch cũ:

- **Phase 2 không chỉ là "thêm smoke test"** cho JS/Java. Quân phải xây DFG-lite, evidence extraction, taint analysis thật cho JavaScript, Java, PHP — và đây là khối lượng công việc nặng nhất trong kế hoạch.
- **Benchmark giờ bao phủ cả 4 ngôn ngữ**, không chỉ Python. Bảng Precision/Recall/F1 sẽ có cột cho từng ngôn ngữ.
- **Agent AI xử lý finding từ mọi ngôn ngữ** với cùng workflow, cùng knowledge cards đa ngôn ngữ.

Phân công giữ nguyên:

- **Quân không làm AI**, tập trung vào core scanner, nâng cấp 3 ngôn ngữ lên parity, benchmark đa ngôn ngữ, SARIF và baseline.
- **Tuệ chỉ làm AI**, tập trung vào LangGraph, triage, knowledge, prompt, explanation và ablation.

Rủi ro lớn nhất là thời gian nâng 3 ngôn ngữ. Giải pháp: xây framework evidence extraction dùng chung, tái sử dụng pattern, chấp nhận parity ở mức "đủ evidence cho agent triage chính xác" chứ không cần bằng Python về chiều sâu.

Đây là kế hoạch đòi hỏi nhiều công hơn kế hoạch cũ, nhưng kết quả sẽ mạnh hơn đáng kể khi bảo vệ: hệ thống đa ngôn ngữ thật, benchmark đa ngôn ngữ thật, không phải giải thích tại sao chỉ Python mới có graph.

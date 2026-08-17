# Phân công tuần 15/08/2026 - 21/08/2026 cho Quân - Ánh - Tuệ

## 1. Phân biệt nguồn tài liệu và yêu cầu hiện tại

Tài liệu này **không** sao chép nguyên xi kế hoạch 12 tuần trong `PhanCongNhiemVu.pdf` hay các file `.docx`.

Ba nguồn đó đang đóng vai trò:

- chốt **vai trò dài hạn** của từng thành viên;
- chốt **phạm vi thesis/research**;
- chốt **định hướng kiến trúc tổng thể**.

Yêu cầu hiện tại là:

- đọc lại codebase thật ở thời điểm hiện tại;
- đối chiếu với các tài liệu `.pdf` và `.docx`;
- từ đó **rút ra phân công công việc cho đúng trạng thái repo bây giờ**, không lặp lại những việc repo đã làm xong.

Vì vậy, bản phân công tuần này được suy ra từ ba lớp:

1. `PhanCongNhiemVu.pdf`: vai trò gốc của Quân - Ánh - Tuệ.
2. `docs/thesis/14`, `15`, `16`: mục tiêu thesis và scope nghiên cứu.
3. Codebase hiện tại + `docs/thesis/00`, `04`, `59`, `60`, `61`, `62`: hiện trạng implementation và các gap thật sự còn lại.

## 2. Hiện trạng implementation đã xác nhận từ codebase

### 2.1. Những gì repo đã có thật

Tính đến ngày 14/08/2026, repo đã có các thành phần quan trọng sau:

- `aegis_sast/orchestration/service.py`: scan pipeline service tách khỏi CLI.
- `aegis_sast/orchestration/repo_intake.py`: repo intake, scan profile, framework hints.
- `aegis_sast/core/models.py`: `NormalizedFinding`, `EvidenceBundle`, `TriageStatus`.
- `aegis_sast/triage/engine.py`: deterministic triage engine.
- `aegis_sast/orchestration/workflow.py` và `nodes.py`: workflow `Auditor` / `Skeptic` / `Judge`.
- `aegis_sast/triage/ai_runner.py`: AI triage overlay.
- `aegis_sast/knowledge/loader.py` và `aegis_sast/knowledge/library/`: knowledge cards.
- `aegis_sast/reporting/json_exporter.py`, `markdown_exporter.py`, `integrations/sarif_formatter.py`.
- `scripts/score_owasp_benchmark.py`, `run_benchmark_v1.py`, `run_semgrep_baseline.py`, `run_semgrep_owasp_python.py`.
- `apps/findings-dashboard`: dashboard local đã có import report, queue, detail pane, run local scan, local review memory.

### 2.2. Những gì đã kiểm tra chạy ổn

Đã chạy các nhóm test trọng tâm và đều pass:

- `tests/test_detector_rule_propagation.py`
- `tests/test_workflow.py`
- `tests/test_polyglot_plugin_dataflow.py`
- `tests/test_run_benchmark_v1.py`
- `tests/test_sarif_formatter.py`
- `tests/test_run_ai_triage_overlay.py`

Điều này xác nhận rằng:

- rule propagation hiện không còn là blocker số một;
- workflow triage và AI overlay đã có nền chạy được;
- benchmark script và SARIF formatter đã ở mức dùng được;
- JavaScript/Java plugin dataflow đã có test coverage cơ bản.

## 3. Engineering gaps nên ưu tiên trong tuần tới

### 3.1. Current implementation

- Đã có scanner core, triage workflow, benchmark, dashboard.
- Đã có 3 mode benchmark: `all`, `visible`, `high-confidence`.
- Đã có reviewer feedback local trong dashboard.

### 3.2. Engineering gaps

Các gap còn lại đáng làm nhất trong 1 tuần tới là:

1. `PATH_TRAVERSAL` vẫn còn false positive cao ở lane Python.
2. `all findings`, `visible findings`, `high-confidence findings` vẫn chưa tách rõ đủ trên dữ liệu thật.
3. Reviewer feedback mới dừng ở local dashboard memory, chưa quay lại thành triage memory dùng lại cho pipeline.
4. Benchmark/demo pack cần thêm một vòng artifact hóa gọn, dễ lặp, dễ báo cáo.

### 3.3. Research contribution cần chốt trong tuần này

Tuần này nên cố gắng tạo ra một đóng góp nhìn thấy được ở mức thesis:

- không chỉ có workflow multi-agent về mặt kiến trúc;
- mà còn chứng minh được triage **thực sự làm thay đổi cách nhìn finding**:
  - finding nào giữ lại;
  - finding nào suppress;
  - finding nào được xem là high-confidence.

### 3.4. Demo value cần chốt trong tuần này

Cuối tuần nên có một pack đủ để demo và báo cáo:

- một report benchmark Python mới;
- một bảng điểm `all / visible / high-confidence`;
- một ví dụ dashboard import report và xem review flow;
- một ghi chú ngắn giải thích vì sao kết quả tuần này tốt hơn tuần trước.

## 4. Mục tiêu sprint 1 tuần

### 4.1. Sprint goal

Trong tuần từ **15/08/2026 đến 21/08/2026**, nhóm nên chốt được 4 đầu ra:

1. Giảm nhiễu thực tế cho `PATH_TRAVERSAL`.
2. Làm cho triage status tạo ra khác biệt giữa `all`, `visible`, `high-confidence`.
3. Chốt một contract `review memory / triage memory` v1.
4. Tạo một benchmark/demo pack có thể lặp lại ổn định.

### 4.2. Definition of done cuối tuần

Đến tối **thứ Sáu, 21/08/2026**, sprint này được xem là đạt nếu có đủ:

- 1 report benchmark Python mới sau khi sửa;
- 1 bảng score có 3 mode và có chênh lệch đọc được;
- 1 note ngắn mô tả vì sao `PATH_TRAVERSAL` đỡ nhiễu hơn;
- 1 spec `triage memory` / `review memory` v1;
- 1 demo flow ngắn: scan -> report -> dashboard -> review.

## 5. Phân công cụ thể cho từng thành viên

## 5.1. Quân

### Vai trò tuần này

Giữ đúng vai trò từ PDF: **owner của core scanner, evidence, detector-side precision**.

### Task Q1 - Audit false positive `PATH_TRAVERSAL`

- Mục tiêu: đọc lại các false positive tiêu biểu của family `PATH_TRAVERSAL` trên lane Python.
- Việc phải ra:
  - liệt kê tối thiểu 10 case FP tiêu biểu;
  - nhóm chúng thành 3-5 pattern lặp lại;
  - chốt 2-3 heuristic nên sửa ở core/evidence.
- Deliverable:
  - 1 file markdown ngắn trong `docs/thesis/` hoặc `reports/benchmark/...`;
  - 1 checklist “fix trước / để sau”.
- Deadline: **Chủ nhật, 16/08/2026 - 18:00**

### Task Q2 - Sửa detector/evidence cho `PATH_TRAVERSAL`

- Mục tiêu: đưa ít nhất 1-2 cải tiến thật vào core để giảm nhiễu.
- Ưu tiên:
  - guard / sanitizer / base-dir pattern;
  - evidence rõ hơn cho source-sink-path;
  - tránh report các path đã normalize/allowlist quá rõ.
- File nên tập trung:
  - `aegis_sast/plugins/python_plugin.py`
  - `aegis_sast/analysis/python_deep_analysis.py`
  - `aegis_sast/analysis/vulnerability_detector.py`
  - test tương ứng trong `tests/`
- Deliverable:
  - code chạy được;
  - test mới hoặc test cập nhật;
  - 1 report before/after nhỏ để Ánh dùng chấm lại.
- Deadline: **Thứ Tư, 19/08/2026 - 23:00**

### Task Q3 - Chốt gói evidence handoff cho triage

- Mục tiêu: chốt lại các field evidence mà Tuệ và Ánh cần dùng ổn định trong tuần này.
- Bắt buộc phải rõ:
  - source
  - sink
  - path summary
  - sanitizer info
  - detection metadata
  - graph slice nếu có
- Deliverable:
  - 1 report JSON mẫu mới;
  - 1 note ngắn “field nào là canonical, field nào chỉ là optional”.
- Deadline: **Thứ Sáu, 21/08/2026 - 12:00**

## 5.2. Ánh

### Vai trò tuần này

Giữ đúng vai trò từ PDF: **owner của integration, benchmark, reporting, evaluation**.

### Task A1 - Chốt benchmark runbook tuần này

- Mục tiêu: chuẩn hóa lại đúng lệnh chạy cho claim hiện tại, không để nhóm mỗi người chạy một kiểu.
- Scope:
  - Aegis Python 4-family thesis-safe
  - Semgrep baseline tương ứng
  - score output cho `all / visible / high-confidence`
- File nên tập trung:
  - `scripts/score_owasp_benchmark.py`
  - `scripts/run_semgrep_owasp_python.py`
  - `scripts/analyze_scan_report.py`
  - 1 markdown runbook ngắn trong `docs/thesis/`
- Deliverable:
  - 1 runbook thống nhất;
  - 1 danh sách artifact path chuẩn.
- Deadline: **Thứ Hai, 17/08/2026 - 21:00**

### Task A2 - Chấm lại score sau khi Quân và Tuệ cập nhật

- Mục tiêu: tạo bảng score mới phản ánh đúng thay đổi trong tuần.
- Việc phải ra:
  - rerun score cho `all`, `visible`, `high-confidence`;
  - so sánh với run trước;
  - chỉ rõ family nào cải thiện / family nào chưa.
- Deliverable:
  - 1 bảng tổng hợp TP/FP/FN/Precision/Recall/F1 cho 3 mode;
  - 1 bảng delta trước-sau;
  - 1 note ngắn “điểm nào cải thiện được nhờ core, điểm nào nhờ triage”.
- Deadline: **Thứ Năm, 20/08/2026 - 20:00**

### Task A3 - Kiểm tra integration/demo pack

- Mục tiêu: đảm bảo artifact cuối tuần dùng được cho buổi báo cáo.
- Việc phải kiểm:
  - JSON report import được vào dashboard;
  - Markdown report đọc được;
  - SARIF export hợp lệ;
  - `Run local scan` trong dashboard không vỡ flow cơ bản;
  - benchmark artifact có tên thư mục và cấu trúc nhất quán.
- Deliverable:
  - 1 integration checklist;
  - 1 danh sách bug/blocker còn lại nếu có.
- Deadline: **Thứ Sáu, 21/08/2026 - 18:00**

## 5.3. Tuệ

### Vai trò tuần này

Giữ đúng vai trò từ PDF: **owner của AI triage, workflow logic, knowledge, explanation**.

### Task T1 - Chốt rubric để tách `confirmed / likely / needs-review / suppressed`

- Mục tiêu: viết lại cho rõ rule suy luận status, đặc biệt cho case evidence mơ hồ hoặc có sanitizer.
- Cần chốt rõ:
  - khi nào được `confirmed`;
  - khi nào chỉ là `likely`;
  - khi nào phải `needs-review`;
  - khi nào đủ điều kiện `suppressed`.
- File nên tập trung:
  - `aegis_sast/triage/engine.py`
  - `aegis_sast/orchestration/nodes.py`
  - 1 note ngắn trong `docs/thesis/`
- Deliverable:
  - 1 rubric v1 dạng bảng hoặc bullet;
  - 1 mapping từ evidence signal -> status decision.
- Deadline: **Thứ Hai, 17/08/2026 - 21:00**

### Task T2 - Làm cho 3 mode benchmark tách nhau trên dữ liệu thật

- Mục tiêu: không để `all`, `visible`, `high-confidence` gần như trùng nhau như hiện tại.
- Việc phải ra:
  - chỉnh route / skepticism / judge logic;
  - tăng số case bị suppress hợp lý;
  - tăng số case đi vào `likely` hoặc `confirmed` có lý do rõ;
  - không overfit bằng cách suppress bừa.
- Deliverable:
  - code + test cập nhật;
  - ít nhất 1 report thật cho thấy 3 mode tách nhau;
  - 1 note giải thích vì sao triage tuần này “có tác động đo được”.
- Deadline: **Thứ Năm, 20/08/2026 - 23:00**

### Task T3 - Chốt `TriageMemory / ReviewMemory` contract v1

- Mục tiêu: nối được ngôn ngữ giữa dashboard feedback hiện tại và triage workflow tương lai.
- Scope v1 chỉ cần chốt contract, chưa cần làm full persistence backend.
- Bắt buộc nên có các trường:
  - finding key
  - disposition
  - note
  - muted
  - updatedAt
  - reason codes
  - provenance của reviewer decision
- Deliverable:
  - 1 spec JSON hoặc markdown;
  - 1 ví dụ payload mẫu;
  - ghi rõ phần nào tuần sau mới implement.
- Deadline: **Thứ Sáu, 21/08/2026 - 17:00**

## 6. Mốc phối hợp trong tuần

### Mốc 1 - Kickoff scope lock

- Thời gian: **Thứ Bảy, 15/08/2026 - 09:00**
- Thời lượng: 30 phút
- Mục tiêu:
  - thống nhất sprint goal;
  - chốt artifact path;
  - chốt family focus: Python + 4 family chính.

### Mốc 2 - Freeze spec giữa tuần

- Thời gian: **Thứ Hai, 17/08/2026 - 21:30**
- Đầu vào:
  - Q1 xong
  - A1 xong
  - T1 xong
- Mục tiêu:
  - chốt detector-side FP themes;
  - chốt rubric triage;
  - chốt lệnh benchmark chính thức cho tuần này.

### Mốc 3 - Handoff kỹ thuật

- Thời gian: **Thứ Tư, 19/08/2026 - 23:30**
- Đầu vào:
  - Quân giao report JSON mẫu mới
  - Tuệ bắt đầu chạy triage trên report mới
  - Ánh chuẩn bị score rerun

### Mốc 4 - Score review

- Thời gian: **Thứ Năm, 20/08/2026 - 21:00**
- Mục tiêu:
  - nhìn bảng `all / visible / high-confidence`;
  - quyết định có cần chỉnh thêm một vòng hay không.

### Mốc 5 - Sprint close

- Thời gian: **Thứ Sáu, 21/08/2026 - 20:30**
- Mục tiêu:
  - gom đủ artifact cuối tuần;
  - chốt 1 đoạn tóm tắt để báo cáo với giảng viên.

## 7. Quy tắc handoff giữa 3 người trong tuần này

### 7.1. Quân -> Tuệ

Quân phải giao cho Tuệ:

- ít nhất 1 report JSON mới sau khi sửa detector;
- ghi rõ case nào dự kiến sẽ đổi status;
- ghi rõ heuristic nào đang thử để Tuệ không “đọc sai ý định detector”.

### 7.2. Quân -> Ánh

Quân phải giao cho Ánh:

- artifact path cụ thể;
- ghi rõ report nào là before, report nào là after;
- nếu có đổi schema nhẹ thì báo ngay trong ngày.

### 7.3. Tuệ -> Ánh

Tuệ phải giao cho Ánh:

- giải thích rule nào tạo ra `suppressed`;
- giải thích điều kiện nào tạo ra `high-confidence`;
- note rõ các case manual-review để Ánh không diễn giải nhầm bảng benchmark.

### 7.4. Ánh -> Cả nhóm

Ánh phải trả lại:

- bảng score ngắn gọn;
- family nào tăng / giảm;
- blocker cuối tuần còn tồn tại.

## 8. Việc không nên làm trong tuần này

Để tránh dàn trải, tuần này **không nên**:

1. Mở thêm scope C++.
2. Lao sang full capability parity cho mọi ngôn ngữ như trong plan 12 tuần cũ.
3. Viết lại dashboard theo hướng UI redesign lớn.
4. Claim AI improvement lớn khi chưa có score mới.
5. Đập lại toàn bộ schema nếu chưa thực sự cần.

## 9. Kết luận ngắn

Nếu bám đúng hiện trạng repo, thì tuần tới không nên làm theo kiểu “khởi động lại roadmap 12 tuần”, mà nên đánh vào 3 chỗ đang tạo ra giá trị thesis rõ nhất:

1. detector-side precision cho `PATH_TRAVERSAL`;
2. triage-side differentiation giữa `all / visible / high-confidence`;
3. benchmark/integration pack đủ sạch để báo cáo.

Phân công hợp lý nhất trong tuần 15/08/2026 - 21/08/2026 là:

- **Quân** tập trung giảm nhiễu ở core và chốt evidence handoff;
- **Ánh** tập trung benchmark, artifact, integration và kiểm chứng cuối;
- **Tuệ** tập trung làm cho triage status có tác động đo được và chốt contract memory v1.

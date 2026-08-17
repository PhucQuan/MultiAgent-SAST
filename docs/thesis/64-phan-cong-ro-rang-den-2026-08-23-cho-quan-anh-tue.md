# Phân công rõ ràng đến Chủ nhật 23/08/2026 cho Quân - Ánh - Tuệ

## 1. Phân biệt tài liệu tham chiếu và yêu cầu hiện tại

Tài liệu này được viết sau khi đọc:

- `D:\Nghiên Cứu Khoa Học\PhanCongNhiemVu.pdf`
- `docs/thesis/00-tong-hop-da-lam.md`
- `docs/thesis/04-kien-truc-muc-tieu.md`
- `docs/thesis/14-de-cuong-nghien-cuu-de-tai.docx`
- `docs/thesis/15-phase-3-thang-va-phan-cong-quan-tue.docx`
- `docs/thesis/16-de-cuong-bao-cao-de-tai-ban-giang-vien.docx`
- `docs/thesis/60-bao-cao-tien-do-va-huong-phat-trien-cho-buoi-lam-viec-voi-co.md`
- codebase hiện tại

Ba nguồn PDF/DOCX/thesis ở trên dùng để:

- giữ đúng **vai trò gốc** của từng người;
- giữ đúng **claim thesis** so với implementation thật;
- tránh giao việc lệch với kiến trúc hiện tại của repo.

Yêu cầu hiện tại **không phải** là bê nguyên roadmap 12 tuần trong PDF sang tuần này.

Yêu cầu hiện tại là:

- chốt một sprint ngắn, làm được ngay, từ bây giờ đến **Chủ nhật 23/08/2026, 23:59**;
- phân công rõ cho **Quân, Ánh, Tuệ** theo đúng repo đang có ở thời điểm hiện tại;
- đặc biệt biến phần **Tuệ** thành các đầu việc có output nhìn thấy được, đo được, demo được, không để ở mức “nghiên cứu multi-agent” chung chung.

## 2. Hiện trạng repo đã xác nhận

### 2.1. Current implementation

Repo hiện đã có thật các phần sau:

- `aegis_sast/core/models.py`: đã có `NormalizedFinding`, `EvidenceBundle`, `TriageStatus`.
- `aegis_sast/orchestration/service.py`: đã có scan pipeline service tách khỏi CLI.
- `aegis_sast/orchestration/workflow.py`: đã có workflow stateful cho scan và triage.
- `aegis_sast/orchestration/router.py`: đã có route `direct-judge` và `skeptic-review`.
- `aegis_sast/orchestration/nodes.py`: đã có `Auditor`, `SkepticValidator`, `Judge`.
- `aegis_sast/orchestration/langgraph_bridge.py`: đã có LangGraph bridge tối thiểu.
- `aegis_sast/triage/engine.py`: đã có deterministic triage + knowledge-assisted triage.
- `aegis_sast/triage/ai_runner.py`: đã có AI triage overlay.
- `aegis_sast/knowledge/library/`: đã có knowledge cards generic + Python/JavaScript/Java.
- `aegis_sast/reporting/` và `aegis_sast/integrations/sarif_formatter.py`: đã có JSON, Markdown, SARIF.
- `scripts/score_owasp_benchmark.py`, `scripts/run_benchmark_v1.py`, `scripts/run_semgrep_owasp_python.py`: đã có benchmark/scoring cơ bản.
- `apps/findings-dashboard`: đã có dashboard local và `review-store.ts` cho reviewer memory local.

### 2.2. Engineering gaps cần đánh thẳng trong sprint này

Các gap còn đáng làm nhất từ giờ đến 23/08/2026 là:

1. `PATH_TRAVERSAL` vẫn còn nhiễu cao ở lane Python.
2. Ba mode benchmark `all`, `visible`, `high-confidence` chưa tạo ra khác biệt đủ rõ trên dữ liệu thật.
3. Reviewer memory hiện mới ở dashboard local, chưa nối thành contract dùng lại cho triage.
4. Phần multi-agent/LangGraph đã có nền nhưng chưa tạo được một artifact đủ thuyết phục để ai cũng thấy “Tuệ đã làm phần AI”.

### 2.3. Research contribution nên chốt trong sprint này

Tuần này không cần mở thêm scope lớn. Cái cần chốt là:

- triage phải **thực sự thay đổi cách nhìn finding**;
- benchmark phải chỉ ra được chỗ nào core cải thiện, chỗ nào triage cải thiện;
- dashboard/review memory phải được nối về mặt contract với triage để có câu chuyện phát triển tiếp.

### 2.4. Demo value cần có vào cuối hạn

Đến cuối Chủ nhật 23/08/2026, nhóm nên có một luồng demo đủ ngắn và đủ sạch:

`scan -> export report -> score benchmark -> mở dashboard -> xem status / reason_codes / note`

## 3. Mục tiêu sprint và definition of done

### 3.1. Sprint goal

Đến hết ngày **23/08/2026**, nhóm phải chốt được 6 đầu ra:

1. Một report Python mới với evidence và triage metadata đủ sạch để dùng làm artifact chính.
2. Một bảng score mới có đủ `all`, `visible`, `high-confidence` và có khác biệt đọc được.
3. Một ghi chú before/after cho `PATH_TRAVERSAL`.
4. Một ghi chú ngắn giải thích rõ rubric triage và route logic.
5. Một spec `ReviewMemory -> TriageMemory` v1.
6. Một runbook/demo pack ngắn đủ để cả nhóm nói cùng một câu chuyện.

### 3.2. Definition of done

Sprint này chỉ được xem là xong khi:

- artifact đều nằm trong repo;
- Ánh chạy lại benchmark được bằng runbook chung;
- Tuệ có output AI/triage nhìn thấy được trên finding thật;
- Quân bàn giao report/evidence mà Ánh và Tuệ đọc không phải hỏi lại structure;
- nhóm có thể báo cáo trung thực: cái gì đã có, cái gì mới hoàn thiện trong tuần này, cái gì chưa nên claim.

## 4. Phân công cụ thể cho từng người

### 4.1. Quân

**Vai trò tuần này:** owner của **core scanner, detector precision, evidence handoff**.

#### Việc bắt buộc

1. Audit false positive `PATH_TRAVERSAL` trên report benchmark gần nhất.
   - Mục tiêu: gom tối thiểu 10 case FP thành 3-5 pattern lặp lại.
   - File nên đọc/chạm:
     - `aegis_sast/plugins/python_plugin.py`
     - `aegis_sast/analysis/python_deep_analysis.py`
     - `aegis_sast/analysis/vulnerability_detector.py`
   - Deliverable:
     - 1 note markdown ngắn ghi rõ từng pattern FP;
     - 1 danh sách “fix ngay” và “để sau”.
   - Hạn nội bộ: **Thứ Hai 17/08/2026 - 21:00**

2. Sửa detector/evidence cho 1-2 pattern FP có tác động cao nhất.
   - Mục tiêu: giảm nhiễu nhưng không làm vỡ recall đang có.
   - Deliverable:
     - code chạy được;
     - test mới hoặc test cập nhật;
     - 1 report before/after để Ánh chấm lại.
   - Hạn nội bộ: **Thứ Năm 20/08/2026 - 23:00**

3. Chốt gói evidence handoff cho Ánh và Tuệ.
   - Bắt buộc phải rõ các field:
     - `source`
     - `sink`
     - `path_summary`
     - `sanitizer`
     - `detection metadata`
     - `graph_slice` nếu có
   - Deliverable:
     - 1 JSON report canonical mới;
     - 1 note ngắn “field nào là canonical, field nào optional”.
   - Hạn nội bộ: **Thứ Sáu 21/08/2026 - 12:00**

#### Khi nào xem là Quân xong

- Có report mới để Ánh chấm lại.
- Tuệ đọc report mới không cần hỏi lại format.
- Có ít nhất một thay đổi detector/evidence giải thích được bằng before/after.

### 4.2. Ánh

**Vai trò tuần này:** owner của **benchmark, integration, reporting, evaluation**.

#### Việc bắt buộc

1. Khóa runbook benchmark dùng cho sprint này.
   - Chỉ tập trung lane **Python thesis-safe** trong sprint này, không mở thêm scope mới.
   - File nên đọc/chạm:
     - `scripts/score_owasp_benchmark.py`
     - `scripts/run_benchmark_v1.py`
     - `scripts/run_semgrep_owasp_python.py`
     - `scripts/analyze_scan_report.py`
   - Deliverable:
     - 1 runbook markdown thống nhất;
     - 1 danh sách path artifact chuẩn để cả nhóm dùng chung.
   - Hạn nội bộ: **Thứ Hai 17/08/2026 - 21:00**

2. Chấm lại benchmark sau khi Quân và Tuệ bàn giao bản mới.
   - Bắt buộc phải ra:
     - bảng `TP/FP/FN/Precision/Recall/F1` cho `all`, `visible`, `high-confidence`;
     - bảng delta trước/sau;
     - note ngắn phần nào do core cải thiện, phần nào do triage cải thiện.
   - Deliverable:
     - 1 bảng tổng hợp benchmark mới;
     - 1 note giải thích kết quả.
   - Hạn nội bộ: **Thứ Bảy 22/08/2026 - 14:00**

3. Kiểm integration/demo pack cuối sprint.
   - Bắt buộc phải kiểm:
     - JSON import được vào dashboard;
     - Markdown report đọc được;
     - SARIF export hợp lệ;
     - cấu trúc thư mục artifact rõ ràng, không rối.
   - File nên đọc/chạm:
     - `aegis_sast/integrations/sarif_formatter.py`
     - `apps/findings-dashboard/README.md`
     - `apps/findings-dashboard/src/lib/report-adapter.ts`
   - Deliverable:
     - 1 checklist xanh/đỏ;
     - 1 danh sách blocker còn lại nếu có.
   - Hạn nội bộ: **Thứ Bảy 22/08/2026 - 20:00**

#### Khi nào xem là Ánh xong

- Bất kỳ ai trong nhóm cũng có thể chạy theo runbook và ra cùng kiểu artifact.
- Có đủ một bộ score để dùng trong báo cáo.
- Có checklist nói rõ cái gì demo được, cái gì chưa demo được.

### 4.3. Tuệ

**Vai trò tuần này:** owner của **AI triage, route logic, knowledge, explanation**.

Lưu ý rất rõ: Tuệ **không cần làm lại detector core**. Việc của Tuệ là làm cho phần AI/triage **có tác động nhìn thấy được trên finding thật**.

#### Việc bắt buộc

1. Chốt rubric triage và route logic thành tài liệu + code.
   - Phải trả lời rõ 5 câu:
     - khi nào `confirmed`
     - khi nào `likely`
     - khi nào `needs-review`
     - khi nào `suppressed`
     - khi nào đi `direct-judge`, khi nào đi `skeptic-review`
   - File nên đọc/chạm:
     - `aegis_sast/triage/engine.py`
     - `aegis_sast/orchestration/router.py`
     - `aegis_sast/orchestration/nodes.py`
     - `aegis_sast/orchestration/langgraph_bridge.py`
     - `aegis_sast/triage/ai_runner.py`
   - Deliverable:
     - 1 note markdown ngắn về rubric;
     - test cập nhật cho workflow/triage nếu logic thay đổi.
   - Hạn nội bộ: **Thứ Hai 17/08/2026 - 21:00**

2. Làm cho triage tạo ra khác biệt đo được trên report thật.
   - Mục tiêu:
     - `all`, `visible`, `high-confidence` không còn gần như trùng nhau;
     - `route_summary`, `reason_codes`, `status` phải giải thích được;
     - nếu có AI overlay thì phải ghi rõ finding nào đổi status/confidence.
   - File nên đọc/chạm:
     - `aegis_sast/triage/engine.py`
     - `aegis_sast/orchestration/router.py`
     - `aegis_sast/orchestration/nodes.py`
     - `aegis_sast/triage/ai_runner.py`
     - `aegis_sast/knowledge/library/*.yaml`
     - `tests/test_workflow.py`
     - `tests/test_run_ai_triage_overlay.py`
   - Deliverable:
     - code + test;
     - 1 note “triage tuần này thay đổi gì và vì sao”.
   - Hạn nội bộ: **Thứ Sáu 21/08/2026 - 23:00**

3. Chốt contract `ReviewMemory -> TriageMemory` v1.
   - Mốc xuất phát là dashboard local memory hiện có, chưa cần full backend.
   - Bắt buộc nên có các trường:
     - `finding_key`
     - `disposition`
     - `note`
     - `muted`
     - `updatedAt`
     - `reason_codes`
     - `provenance`
   - File nên đọc/chạm:
     - `apps/findings-dashboard/src/lib/review-store.ts`
     - `aegis_sast/core/models.py`
     - `aegis_sast/orchestration/state.py`
   - Deliverable:
     - 1 spec markdown;
     - 1 sample JSON payload;
     - ghi rõ phần nào để tuần sau implement tiếp.
   - Hạn nội bộ: **Thứ Bảy 22/08/2026 - 18:00**

4. Chuẩn bị demo AI/multi-agent đúng scope.
   - Không demo kiểu “LangGraph hay lắm”.
   - Phải demo bằng finding thật:
     - route đi đâu;
     - status cuối là gì;
     - reason codes nào được gắn;
     - explanation/remediation hiện ra ở đâu.
   - Deliverable:
     - 1 flow demo 3-5 phút;
     - 1 note ngắn để Ánh và Quân đọc là hiểu cách nói.
   - Hạn nội bộ: **Chủ nhật 23/08/2026 - 12:00**

#### Khi nào xem là Tuệ xong

- Ánh benchmark lại thấy ba mode bắt đầu tách nhau.
- Quân đọc rubric/route là biết detector cần bàn giao gì.
- Cả nhóm có thể chỉ thẳng vào code và artifact để nói “đây là phần AI/triage Tuệ làm”.

## 5. Mốc phối hợp chung

1. **Kickoff scope lock**
   - Thời gian: **Thứ Bảy 15/08/2026 - 09:00**
   - Mục tiêu: chốt đúng sprint goal, không lan sang roadmap 12 tuần.

2. **Freeze spec giữa tuần**
   - Thời gian: **Thứ Hai 17/08/2026 - 21:30**
   - Đầu vào bắt buộc:
     - Quân giao note audit FP
     - Ánh giao benchmark runbook
     - Tuệ giao rubric triage/route v1

3. **Handoff kỹ thuật**
   - Thời gian: **Thứ Sáu 21/08/2026 - 12:30**
   - Đầu vào bắt buộc:
     - Quân giao report canonical
     - Tuệ bắt đầu chạy triage trên report canonical
     - Ánh chuẩn bị score rerun

4. **Score review**
   - Thời gian: **Thứ Bảy 22/08/2026 - 20:30**
   - Mục tiêu:
     - xem bảng `all / visible / high-confidence`;
     - quyết định còn cần chỉnh thêm 1 vòng hay freeze.

5. **Final freeze**
   - Thời gian: **Chủ nhật 23/08/2026 - 20:30**
   - Mục tiêu:
     - gom đủ artifact;
     - chốt demo flow;
     - thống nhất cách nói khi báo cáo.

## 6. Quy tắc handoff giữa 3 người

### 6.1. Quân -> Tuệ

Quân phải giao:

- 1 JSON report canonical;
- note field canonical/optional;
- note case nào dự kiến đổi status sau triage.

### 6.2. Quân -> Ánh

Quân phải giao:

- path cụ thể của report before/after;
- nếu có đổi schema nhẹ thì báo ngay trong ngày;
- note rất ngắn vì sao detector bớt nhiễu hơn trước.

### 6.3. Tuệ -> Ánh

Tuệ phải giao:

- giải thích rule nào sinh `suppressed`;
- điều kiện nào tạo `high-confidence`;
- route nào được coi là `direct-judge`, route nào phải qua `skeptic-review`.

### 6.4. Ánh -> Cả nhóm

Ánh phải trả lại:

- bảng score ngắn gọn;
- family nào tăng/giảm;
- blocker cuối cùng còn lại trước khi freeze.

## 7. Việc không làm trong sprint này

Để tránh dàn trải, sprint này **không làm** các việc sau:

1. Không quay lại roadmap capability parity 4 ngôn ngữ như trong PDF.
2. Không mở C++.
3. Không ôm thêm HTML exporter nếu repo chưa có exporter thật.
4. Không redesign lớn dashboard.
5. Không claim “LangGraph end-to-end hoàn chỉnh cho toàn hệ thống”.
6. Không claim “AI đã cải thiện benchmark mạnh” nếu bảng score mới chưa chứng minh được.

## 8. Artifact cuối cùng phải có vào tối 23/08/2026

1. **Quân**
   - 1 note audit `PATH_TRAVERSAL`
   - 1 report canonical mới
   - 1 note field handoff

2. **Ánh**
   - 1 benchmark runbook
   - 1 bảng score mới cho `all / visible / high-confidence`
   - 1 checklist integration/demo pack

3. **Tuệ**
   - 1 note rubric triage/route
   - 1 note “triage tuần này thay đổi gì”
   - 1 spec `ReviewMemory -> TriageMemory` v1
   - 1 note demo AI/multi-agent

4. **Cả nhóm**
   - 1 bộ artifact đủ để báo cáo: `report + score + note giải thích + demo flow`

## 9. Kết luận ngắn

Nếu bám đúng hiện trạng repo, thì từ giờ đến **23/08/2026** không nên làm theo kiểu “khởi động lại đề tài từ đầu”. Cách hợp lý nhất là:

- **Quân** đánh vào detector precision và evidence handoff;
- **Ánh** khóa benchmark/runbook/integration;
- **Tuệ** làm cho triage và multi-agent tạo ra tác động đo được trên finding thật.

Nói gọn hơn: sprint này phải làm cho cả nhóm có thể chỉ thẳng vào code, report và benchmark rồi nói rõ được:

- phần nào là scanner core;
- phần nào là integration/evaluation;
- phần nào là AI triage của Tuệ;
- và vì sao ba phần đó ghép lại thành một câu chuyện thesis mạch lạc.

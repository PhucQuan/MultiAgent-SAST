# Quân lane: giảm false positive `PATH_TRAVERSAL` (2026-08-17)

## 1. Mục tiêu

Phần việc này tập trung đúng lane detector-side của Quân:

- audit các false positive `PATH_TRAVERSAL` trên BenchmarkPython;
- vá hẹp trong Python lane;
- giữ recall hiện có, tránh làm rung các family khác;
- để lại artifact ngắn cho benchmark/reporting handoff.

## 2. Thay đổi đã làm

### 2.1. Detector refinement mới

Đã thêm file:

- `aegis_sast/analysis/python_path_traversal_filter.py`

Vai trò:

- chạy như một Python-only refinement sau khi detector tạo raw findings;
- chỉ prune `PATH_TRAVERSAL` khi có bằng chứng khá chắc rằng path thực tế đi vào sink là safe.

### 2.2. Wiring vào detector

Đã nối refinement vào:

- `aegis_sast/analysis/vulnerability_detector.py`

Luồng mới:

1. detector/plugin Python tạo finding như cũ;
2. refinement chỉ chạy cho Python `PATH_TRAVERSAL`;
3. findings còn lại mới đi vào bước finalize/dedupe/report.

### 2.3. Các motif FP đã xử lý

Refinement hiện xử lý tốt các motif lặp lại trong OWASP Benchmark Python:

- nhánh hằng chọn giá trị safe:
  - `bar = "safe" if const_true else param`
  - `match guess` với `guess` là hằng và case thực tế rơi vào nhánh safe
- container slot safe:
  - dict/list/config object có cả dữ liệu safe và tainted, nhưng sink thực tế đọc đúng slot safe
- early-return guard cho parent traversal:
  - ví dụ `if '../' in bar: return`
- sink nằm trong `try` body:
  - refinement bây giờ vẫn nhìn thấy các assignment trước sink trong cùng `try`
- module-style path sink:
  - ví dụ `os.path.exists(fileName)` phải đọc đối số `fileName`, không phải receiver `os.path`

## 3. Evidence kỹ thuật

### 3.1. Test hồi quy đã thêm/cập nhật

Đã mở rộng `tests/test_taint_analysis.py` để khóa lại các motif:

- safe constant branch
- safe ConfigParser option
- safe list slot
- safe constant `match`
- tainted ConfigParser option vẫn phải báo
- `try` body + `os.path.exists(...)` cho cả safe và tainted path

### 3.2. Test suite đã chạy

Đã chạy xanh:

- `pytest tests/test_taint_analysis.py tests/test_python_flow_graph.py tests/test_python_plugin.py tests/test_detector_rule_propagation.py tests/test_workflow.py -q`
- `pytest tests/test_run_benchmark_v1.py tests/test_scan_report_analysis.py tests/test_polyglot_plugin_dataflow.py -q`
- `python -m py_compile aegis_sast/analysis/python_path_traversal_filter.py aegis_sast/analysis/vulnerability_detector.py tests/test_taint_analysis.py`

## 4. Kết quả benchmark sau vá

### 4.1. Artifact mới

- Report:
  - `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_quan_patch\aegis_sast_report_20260817_205627.json`
- Score PATH only:
  - `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_quan_patch_score_path\owasp_score_summary.json`
- Score 4 family:
  - `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_quan_patch_score_4fam\owasp_score_summary.json`

### 4.2. So sánh trực tiếp

#### `PATH_TRAVERSAL` trước vá

- TP = 52
- FP = 46
- FN = 13
- Precision = 0.5306
- Recall = 0.8000
- F1 = 0.6380

#### `PATH_TRAVERSAL` sau vá

- TP = 52
- FP = 0
- FN = 13
- Precision = 1.0000
- Recall = 0.8000
- F1 = 0.8889

### 4.3. 4 family core trước vá

- TP = 85
- FP = 56
- FN = 16
- Precision = 0.6028
- Recall = 0.8416
- F1 = 0.7025

### 4.4. 4 family core sau vá

- TP = 85
- FP = 10
- FN = 16
- Precision = 0.8947
- Recall = 0.8416
- F1 = 0.8673

## 5. Ý nghĩa cho thesis/demo

### Current implementation

- deterministic detector vẫn là nguồn tạo finding chính;
- patch này không đụng AI triage, dashboard hay exporter;
- improvement nằm đúng ở detection-quality của Python lane.

### Engineering gap đã xử lý

- điểm đau lớn nhất của benchmark Python là `PATH_TRAVERSAL` false positive;
- patch hiện tại giảm mạnh FP mà không làm rơi recall trên run benchmark mới.

### Research contribution có thể claim

- đây là ví dụ rõ cho hướng hybrid:
  - detector lõi vẫn rule/dataflow-based
  - thêm một refinement lớp trên để giảm noise theo motif cấu trúc mã
- có thể trình bày như một detector-quality improvement thực nghiệm, thay vì claim AI làm tất cả.

### Demo value

- số benchmark đẹp hơn đáng kể;
- câu chuyện demo/báo cáo dễ nói hơn vì trước/sau vá rất rõ;
- có artifact JSON/Markdown scorer để đưa thẳng vào slide hoặc báo cáo tiến độ.

## 6. Handoff ngắn cho các lane khác

### Cho lane benchmark/reporting

- cập nhật bảng số liệu trong các doc benchmark/thesis bằng artifact mới ở mục 4.1
- nếu cần biểu đồ trước/sau, ưu tiên vẽ riêng family `PATH_TRAVERSAL` rồi mới tới bảng 4 family

### Cho lane evidence/triage

- refinement hiện đang prune ngay ở detector layer, chưa gắn thành `suppressed` triage status
- nếu muốn giữ “audit trail” đầy đủ hơn cho thesis V2, có thể đổi hướng này thành:
  - detector giữ finding
  - triage/evidence layer gắn reason code kiểu `python-safe-path-refinement`

### Cho lane mở rộng sau Quân

- nếu còn thời gian, nên tổng quát hóa refinement này thành:
  - reusable path-safety evaluator
  - hoặc bridge sang evidence metadata thay vì hard prune
- hiện tại scope vẫn cố ý hẹp cho Python `PATH_TRAVERSAL`

## 7. Giới hạn còn lại

- refinement mới chỉ áp dụng cho Python lane
- đây vẫn là heuristic structural analysis, chưa phải symbolic execution đầy đủ
- chưa tích hợp thành SARIF suppression hoặc benchmark ablation report riêng


# Trạng thái sau khi xong lane Quân (2026-08-17)

## 1. Cái đã xong

### Quân

- Đã audit và vá detector-side cho `PATH_TRAVERSAL` ở lane Python.
- Đã có report benchmark mới và score mới.
- Đã có note handoff kỹ thuật:
  - `docs/thesis/65-quan-path-traversal-fp-fix-2026-08-17.md`

### Kết quả chính

- `PATH_TRAVERSAL`: từ `TP 52 / FP 46 / FN 13 / F1 0.6380` thành `TP 52 / FP 0 / FN 13 / F1 0.8889`
- 4 family core: từ `TP 85 / FP 56 / FN 16 / F1 0.7025` thành `TP 85 / FP 10 / FN 16 / F1 0.8673`

## 2. Cái chưa làm

### Ưu tiên 1: Tách rõ giá trị của triage

Đây là phần còn thiếu lớn nhất sau khi detector đã sạch hơn.

Cần làm:

- làm cho `all`, `visible`, `high-confidence` khác nhau rõ trên dữ liệu thật;
- chốt rubric `confirmed / likely / needs-review / suppressed`;
- chốt route `direct-judge` và `skeptic-review`;
- ghi rõ `reason_codes` nào dẫn tới đổi status.

Owner chính:

- Tuệ

File nên chạm:

- `aegis_sast/triage/engine.py`
- `aegis_sast/orchestration/router.py`
- `aegis_sast/orchestration/nodes.py`
- `aegis_sast/triage/ai_runner.py`
- `tests/test_workflow.py`
- `tests/test_run_ai_triage_overlay.py`

### Ưu tiên 2: Khóa benchmark/runbook theo bản vá mới

Cần làm:

- cập nhật runbook benchmark để dùng artifact mới sau patch của Quân;
- cập nhật bảng số liệu trong các doc thesis/demo;
- ghi note ngắn “core cải thiện gì, triage cải thiện gì”.

Owner chính:

- Ánh

File nên chạm:

- `scripts/score_owasp_benchmark.py`
- `scripts/run_benchmark_v1.py`
- `scripts/analyze_scan_report.py`
- các doc benchmark/thesis đang dùng số cũ

### Ưu tiên 3: Review memory contract

Cần làm:

- chốt spec `ReviewMemory -> TriageMemory` v1;
- định nghĩa payload tối thiểu để dashboard và triage dùng chung được;
- chưa cần full backend, chỉ cần spec + sample payload đủ rõ.

Owner chính:

- Tuệ

File nên chạm:

- `apps/findings-dashboard/src/lib/review-store.ts`
- `aegis_sast/core/models.py`
- `aegis_sast/orchestration/state.py`

### Ưu tiên 4: Integration/demo pack

Cần làm:

- kiểm tra JSON import vào dashboard;
- kiểm tra Markdown report;
- kiểm tra SARIF export;
- chốt cấu trúc thư mục artifact để demo không rối.

Owner chính:

- Ánh

## 3. Nên làm tiếp ngay bây giờ

Nếu đi theo thứ tự tạo giá trị cao nhất cho sprint hiện tại, bước tiếp theo nên là:

1. Tuệ làm cho ba mode triage tách nhau thật trên report mới của Quân.
2. Ánh cập nhật benchmark summary và runbook theo artifact mới.
3. Sau đó mới khóa `ReviewMemory -> TriageMemory` và demo pack.

## 4. Cái chưa nên làm ngay

- không mở thêm language mới
- không redesign lớn dashboard
- không claim AI đã cải thiện benchmark nếu chưa có score delta do triage
- không đụng refactor rộng ngoài Python/triage/reporting sprint path


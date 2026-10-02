# Báo Cáo Nghiệm Thu Pha 1: Chuẩn Hóa Pipeline Semgrep OSS & Taint Bridge

> **Tài liệu khóa luận / Kỹ thuật nội bộ**  
> **Mã tài liệu:** `80-pha-1-hoan-thanh-semgrep-oss-va-taint-bridge.md`  
> **Tác giả:** Nhóm đồ án Aegis-SAST (Phúc Quân, Ánh, Tuệ)  
> **Ngày hoàn thành:** 02/10/2026  
> **Trạng thái:** Đã hoàn thành 100% các mục tiêu Pha 1, kiểm thử tự động đạt 0 lỗi.

---

## 1. Mục Tiêu Pha 1 & Kết Quả Đạt Được

| Hạng mục nhiệm vụ | Trạng thái | Minh chứng / File mã nguồn |
| :--- | :--- | :--- |
| **Nạp bộ quy tắc Semgrep OSS** | Đã hoàn thành | Thư mục `rules/semgrep-oss-full/` và `p/python`, `p/owasp-top-ten`, `p/flask`, `p/django`. |
| **Module Semgrep CLI Runner** | Đã hoàn thành | [`aegis_sast/integrations/semgrep_runner.py`](file:///c:/Users/DELL/codecuaquan/Project_CV2026/SAST_toolAI/aegis_sast/integrations/semgrep_runner.py) |
| **Module Taint Bridge (Backward DFG Slice)** | Đã hoàn thành | [`aegis_sast/integrations/taint_bridge.py`](file:///c:/Users/DELL/codecuaquan/Project_CV2026/SAST_toolAI/aegis_sast/integrations/taint_bridge.py) |
| **Tích hợp Pipeline Orchestration** | Đã hoàn thành | [`aegis_sast/orchestration/service.py`](file:///c:/Users/DELL/codecuaquan/Project_CV2026/SAST_toolAI/aegis_sast/orchestration/service.py) |
| **Tích hợp REST API Backend** | Đã hoàn thành | [`aegis_sast/api/routes.py`](file:///c:/Users/DELL/codecuaquan/Project_CV2026/SAST_toolAI/aegis_sast/api/routes.py) |
| **Tích hợp CLI Scanner** | Đã hoàn thành | [`aegis_sast/cli.py`](file:///c:/Users/DELL/codecuaquan/Project_CV2026/SAST_toolAI/aegis_sast/cli.py) (tùy chọn `--engine semgrep`) |
| **Kiểm thử E2E & Web Dashboard** | Đã hoàn thành | `scripts/test_semgrep_bridge.py`, `scripts/test_api_semgrep.py`, Playwright E2E test `scripts/test_ui_playwright.mjs` pass 100%. |

---

## 2. Kiến Trúc Chi Tiết của Taint Bridge (Semgrep Match + Tree-sitter DFG)

```mermaid
flowchart TD
    Target[Mã nguồn mục tiêu *.py] --> Semgrep[Semgrep OSS CLI Runner]
    Rules[Semgrep OSS Ruleset] --> Semgrep
    
    Semgrep -->|JSON Output: Check_ID, CWE, Line, Metavars| Bridge[Taint Bridge Engine]
    Target -->|Tree-sitter AST & CFG/DFG| GraphBuilder[PythonFlowGraphBuilder]
    GraphBuilder -->|Reaching Definitions Graph| Bridge
    
    subgraph Taint Bridge Logic
        Bridge --> Backward[Backward DFG Slice: Sink Node -> Predecessors]
        Backward --> Source[Xác định Root Source: request.args/form]
        Backward --> Flow[Ghi nhận Propagation Steps: biến trung gian]
        Backward --> Sanitizer[Kiểm tra Sanitizer: quote, int, basename]
        Bridge --> Dedup[Khử trùng lặp đa rule trên cùng 1 Sink]
    end
    
    Taint Bridge Logic -->|NormalizedFinding + 3-Step EvidenceBundle| Workflow[Multi-Agent Triage Workflow]
    Workflow --> Auditor[Auditor Node]
    Workflow --> Skeptic[Skeptic Validator Node]
    Workflow --> Judge[Judge Node]
    Judge --> Dashboard[Web Dashboard / REST API / Reports]
```

### 2.1. Chuẩn hóa Vết Luồng Dữ Liệu 3 Bước (3-Step Taint Flow Trace)
Khi Semgrep tìm thấy một lỗ hổng (ví dụ tại dòng 106 `os.system(command)`):
- **Step 1 (Source - Untrusted Input):**  
  `db_name = request.args.get('database')` (dòng 102)
- **Step 2 (Propagation - Flow):**  
  `command = "mysqldump -u root " + db_name + " > /tmp/backup.sql"` (dòng 105)
- **Step 3 (Sink - Dangerous Execution):**  
  `os.system(command)` (dòng 106)

### 2.2. Nhận Diện Rào Cản Phòng Vệ (Sanitizer Detection)
Hệ thống tự động tra cứu các hàm làm sạch dữ liệu nằm trên chuỗi lan truyền DFG:
- `shlex.quote()`, `quote()`: Khử Command Injection.
- `os.path.basename()`, `os.path.normpath()`: Khử Path Traversal.
- `int()`, `float()`: Ép kiểu an toàn, vô hiệu hóa SQLi, RCE, Path Traversal.
- `html.escape()`: Khử XSS.
- `yaml.safe_load()`: Khử Insecure Deserialization.

Nếu phát hiện sanitizer hữu hiệu, Taint Bridge gán nhãn `triage_status = SUPPRESSED` với độ tin cậy 90%, giúp giảm thiểu trực tiếp False Positive Rate mà không làm mất vết audit trail.

---

## 3. Kết Quả Đo Đạc Thực Nghiệm Trên `examples/vulnerable_rce.py`

Khi thực thi trên file mẫu chứa các bẫy thực tế:
1. **Semgrep thô (Raw Semgrep OSS):** Sinh ra **32 cảnh báo** (do nhiều quy tắc chồng chéo như `dangerous-system-call`, `os-system-injection`, `tainted-os-command-stdlib-flask` cùng bắt 1 dòng gọi hàm).
2. **Sau Taint Bridge & Khử trùng lặp:** Rút gọn còn **19 phát hiện chuẩn hóa**, mỗi phát hiện đều liên kết với một chuỗi vết DFG 3 bước rõ ràng và bảo lưu danh sách rule phụ (`alias_rule_ids`).
3. **Sau Multi-Agent Triage (Auditor + Skeptic + Judge):**
   - **Confirmed (Xác nhận tồn tại lỗ hổng):** 16 phát hiện (độ tin cậy 0.88).
   - **Likely (Có khả năng khai thác):** 1 phát hiện (độ tin cậy 0.75).
   - **Needs Review (Cần lập trình viên thẩm định lại):** 2 phát hiện (độ tin cậy 0.70).
   - **Suppressed (Dương tính giả đã triệt tiêu):** 0 phát hiện (do file mẫu chưa có sanitizer).

---

## 4. Kế Hoạch Tiếp Theo: Bắt Đầu Pha 2 (Cross-File Analysis)

Sau khi hoàn thành Pha 1, nền tảng phân tích nội bộ một file đã hoạt động trơn tru. Giai đoạn tiếp theo (Pha 2) sẽ tập trung vào:
1. **Liên kết luồng đa file:** Nâng cấp [`aegis_sast/analysis/call_graph.py`](file:///c:/Users/DELL/codecuaquan/Project_CV2026/SAST_toolAI/aegis_sast/analysis/call_graph.py) để lần vết khi Source nằm ở `routes/api.py`, đi qua hàm xử lý `services/helper.py`, và Sink nằm ở `database/queries.py`.
2. **Hiển thị định vị file trên UI:** Trình diễn đường dẫn file chuyển tiếp giữa Step 1 (file A) → Step 2 (file B) → Step 3 (file C) trên Web Dashboard.

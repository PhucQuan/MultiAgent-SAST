# Kế Hoạch Phát Triển Core Engine: Tích Hợp Semgrep OSS & Multi-Agent Triage (Aegis-SAST)

> **Tài liệu khóa luận / Kỹ thuật nội bộ**  
> **Mã tài liệu:** `79-ke-hoach-phat-trien-core-semgrep-engine-va-multi-agent-triage.md`  
> **Tác giả:** Nhóm đồ án Aegis-SAST (Phúc Quân, Ánh, Tuệ)  
> **Trạng thái:** Đã nghiệm thu UI Workbench & Kết nối Backend; Bắt đầu giai đoạn tăng tốc Core Engine.

---

## 1. Bối cảnh & Quyết định Chiến lược (Strategic Decision)

### 1.1. Vấn đề của Rule tự viết (Self-authored Rules)
- Trước đây, dự án phát triển các rule regex/AST thủ công để bắt lỗ hổng (SQLi, SSRF, Command Injection, Path Traversal).
- **Hạn chế lớn:**
  1. Thiếu tính toàn diện (dễ bỏ sót cú pháp đa dạng của Python/Django/Flask).
  2. Dễ phát sinh định kiến (bias) của người lập trình khi benchmark (chỉ pass trên test case tự nghĩ ra).
  3. Hội đồng phản biện và chuyên gia bảo mật sẽ đặt câu hỏi về tính chuẩn tắc và độ uy tín của tập rule.

### 1.2. Quyết định Chiến lược: 100% Sử dụng Semgrep OSS Registry
- **Nguồn quy tắc:** Chuẩn hóa toàn bộ tập quy tắc phát hiện dựa trên **Semgrep OSS Community Rulesets** (được đóng góp và kiểm thử bởi các tổ chức uy tín hàng đầu như OWASP, Trail of Bits, Return To Corporation):
  - `p/python`
  - `p/owasp-top-ten`
  - `p/cwe-top-25`
  - `p/flask` & `p/django`
- **Định vị Đóng góp Học thuật (Academic Contributions) của Đồ án:**
  Đồ án không dừng lại ở việc "chạy lại Semgrep", mà giải quyết 2 nhược điểm cố hữu của Semgrep OSS miễn phí:
  1. **Khắc phục điểm mù liên hàm & đa file (Cross-file / Inter-procedural Blindness):** Semgrep OSS chủ yếu quét intra-file (đơn file). Aegis-SAST sử dụng Tree-sitter AST + Data-Flow Graph (DFG) để nối vết luồng ô nhiễm (taint trace) xuyên suốt nhiều file/module.
  2. **Hạ thấp Tỷ lệ Dương tính Giả (False Positive Reduction) bằng Multi-Agent Triage:** Sử dụng cơ chế phản biện đối thoại (**Auditor Agent vs Skeptic Agent vs Judge**) để kiểm định tính khả thi của vụ tấn công (sanitizer check, input validation, execution context), loại bỏ triệt để các cảnh báo giả mà Semgrep gắn cờ.

---

## 2. Đánh giá Hiện trạng Hệ thống (Current State Assessment)

| Thành phần | Hiện trạng thực tế | Mức độ hoàn thiện |
| :--- | :--- | :--- |
| **Giao diện Workbench** | Đạt chuẩn 4 cột (`App Rail` + `Scan Inventory` + `Findings Queue` + `Deep-dive Pane`), responsive, dark/light mode, đã kiểm thử tự động bằng Playwright đạt 100% pass | Hoàn chỉnh (Production-ready) |
| **Kết nối Frontend-Backend** | Dashboard Next.js giao tiếp trực tiếp với FastAPI backend (`http://localhost:8000/api/v1/scan`), polling tiến trình và log realtime | Hoàn chỉnh |
| **Semgrep OSS Adapter** | Đã có adapter thực thi Semgrep CLI và nạp file quy tắc Semgrep YAML chuẩn | Đạt nền tảng (Foundation ready) |
| **Core DFG / Taint Engine** | Đã hỗ trợ AST Python, lần vết DFG đơn file và bước đầu có cross-file | Cần mở rộng inter-procedural |
| **Multi-Agent Triage** | Đã có mock/heuristic và schema kết quả (`Auditor`, `Skeptic`, `Judge`), UI đã dựng card hiển thị hoàn chỉnh | Cần kết nối LLM live streaming |

---

## 3. Khoảng cách Kỹ thuật Cần Giải Quyết (Engineering Gaps)

1. **Mapping 2 chiều giữa Semgrep Match và Aegis DFG:**
   - *Vấn đề:* Khi Semgrep phát hiện một Sink (ví dụ: `cursor.execute(...)`), Aegis cần nhận tọa độ file:dòng này làm Anchor Sink và tự động chạy DFG ngược (backward analysis) hoặc xuôi (forward analysis) để tìm Source đầu vào của người dùng.
2. **Inter-procedural Function Summaries:**
   - Khi luồng dữ liệu truyền qua `views.py -> services.py -> db.py`, cần bộ nhớ tóm tắt hàm (Function Summary) để không bị đứt đoạn Taint Chain.
3. **Chuyển đổi Trạng thái Triage trong DB / State:**
   - Phán quyết của Multi-Agent (Confirmed / Suppressed FP) cần tự động cập nhật vào thống kê tổng (Actionable Count, Suppressed Count) và cho phép người dùng ghi đè (human-in-the-loop disposition).

---

## 4. Lộ Trình Phát Triển Chi Tiết (Milestones & Work Breakdown)

### Pha 1: Chuẩn hóa Pipeline Semgrep OSS & Taint Bridge (Tuần 1)
- **Mục tiêu:** Chạy Semgrep OSS native với ruleset YAML chuẩn và dùng kết quả làm hạt giống (seed) cho DFG.
- **Nhiệm vụ cụ thể:**
  - [x] Ingest toàn bộ ruleset `semgrep-oss-full` và `rules/python.yaml`.
  - [ ] Chuẩn hóa output parser: Trích xuất chính xác `extra.metavars`, CWE ID, OWASP category từ Semgrep JSON sang `AegisFinding`.
  - [ ] Xây dựng **Taint Bridge**: Với mỗi finding do Semgrep tìm thấy, kích hoạt Tree-sitter DFG để trích xuất 3 bước chuẩn:
    - **Step 1 - Source (Untrusted Input):** Ví dụ: `request.args.get("id")`
    - **Step 2 - Propagation (Taint Flow):** Biến trung gian gán dữ liệu qua các hàm
    - **Step 3 - Sink (Vulnerable Function):** Ví dụ: `db.execute(query)`

### Pha 2: Mở rộng Cross-file Inter-procedural Graph (Tuần 2)
- **Mục tiêu:** Kết nối luồng dữ liệu khi Source và Sink nằm ở hai file khác nhau trong dự án Python.
- **Nhiệm vụ cụ thể:**
  - [ ] Nâng cấp `aegis_sast/core/cross_file.py` để parse cây thư mục module (import resolution: `from .service import process_input`).
  - [ ] Lưu vết Call Graph liên module.
  - [ ] Hiển thị Taint Trace rõ ràng trên UI với link đường dẫn file tương ứng cho từng bước.

### Pha 3: Triển khai Multi-Agent Triage Chuyên Sâu (Tuần 3)
- **Mục tiêu:** Giảm thiểu False Positive bằng mô hình tranh luận đa tác tử (Auditor vs Skeptic).
- **Cấu trúc Agent:**
  1. **Auditor Agent (Tấn công):**
     - Đóng vai Penetration Tester.
     - Phân tích xem input từ Source có thể bị chèn payload độc hại hay không.
     - Dựng exploit path giả định.
  2. **Skeptic Agent (Phòng thủ / Phản biện):**
     - Đóng vai Security Reviewer khắt khe.
     - Tìm kiếm các rào cản phòng vệ: Đã có regex validate chưa? Có ép kiểu `int(user_id)` chưa? Có dùng parameterized query chưa? Input có phải từ biến nội bộ đáng tin cậy không?
     - Đề xuất đánh dấu `SUPPRESSED (FP)` nếu tìm thấy bằng chứng an toàn.
  3. **Judge Agent (Trọng tài):**
     - Cân nhắc lập luận giữa Auditor và Skeptic.
     - Đưa ra nhãn cuối cùng: `CONFIRMED (VULNERABLE)`, `SUPPRESSED (FALSE_POSITIVE)`, hoặc `NEEDS_REVIEW`.
     - Tính toán Confidence Score (0.00 - 1.00) và tóm tắt lý do ngắn gọn hiển thị lên UI.

### Pha 4: Đo Đạc & Thực Nghiệm Khóa Luận (Benchmark & Evaluation) (Tuần 4)
- **Mục tiêu:** Cung cấp số liệu định lượng (Quantitative Proof) chứng minh tính hiệu quả của đề tài.
- **Bộ dữ liệu chuẩn:**
  - NIST SAMATE Juliet Test Suite v1.3 for Python:
    - CWE-89 (SQL Injection)
    - CWE-78 (OS Command Injection)
    - CWE-22 (Path Traversal)
    - CWE-918 (Server-Side Request Forgery)
  - OWASP Benchmark / Securibench Micro test cases.
- **Bảng So sánh Trực diện (Head-to-head Matrix):**
  - Cột 1: **Raw Semgrep OSS** (chạy độc lập với cùng bộ rule).
  - Cột 2: **Aegis-SAST Static** (Semgrep + DFG Taint).
  - Cột 3: **Aegis-SAST Full** (Semgrep + DFG Taint + Multi-Agent Triage).
  - Các chỉ số đo đạc:
    $$\text{Precision} = \frac{TP}{TP + FP}$$
    $$\text{Recall} = \frac{TP}{TP + FN}$$
    $$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
    $$\text{FPR Reduction} = \frac{FP_{\text{Semgrep}} - FP_{\text{Aegis}}}{FP_{\text{Semgrep}}} \times 100\%$$

---

## 5. Giá Trị Trình Diễn Demo Trước Hội Đồng (Demo Value)

Khi bảo vệ trước hội đồng, nhóm sẽ trình diễn trực tiếp kịch bản:
1. **Khởi chạy quét trực tiếp trên Web Dashboard:** Chọn một repo mã nguồn thực tế chứa cả case thực tế và case bẫy dương tính giả.
2. **Quan sát tiến trình theo thời gian thực:** Backend FastAPI xử lý, hiển thị log Tree-sitter và Semgrep OSS.
3. **So sánh trực quan trước và sau Triage:**
   - Cho hội đồng thấy nếu chỉ dùng Semgrep, hệ thống sẽ báo 10 cảnh báo (trong đó 4 cảnh báo là dương tính giả do đã có sanitizer).
   - Khi bật **Aegis Multi-Agent Triage**, Skeptic Agent lập tức chỉ ra đoạn code sanitizer, đưa 4 cảnh báo đó vào danh sách **Suppressed (FP)**.
   - Thể hiện rõ ràng exploit path 3 bước trong tab **Taint Flow**.
   - Hội đồng bấm vào **Suggested Remediation** để xem mã sửa lỗi (Fix Patch / Unified Diff) do AI đề xuất.

---

## 6. Phân Công Công Việc Sắp Tới

| Thành viên | Trách nhiệm chính | Kết quả đầu ra |
| :--- | :--- | :--- |
| **Phúc Quân** | **Core Engine & Semgrep Taint Bridge** | Hoàn thiện mapping tọa độ từ Semgrep OSS sang Aegis DFG, mở rộng cross-file taint cho Python. |
| **Ánh** | **Frontend UX & Visual Trace Polish** | Tinh chỉnh giao diện hiển thị diff patch, biểu đồ DFG tương tác nếu cần, xuất báo cáo PDF/SARIF. |
| **Tuệ** | **Multi-Agent Triage Prompts & Benchmark Execution** | Hoàn thiện prompt Auditor/Skeptic/Judge, chạy bộ kiểm thử NIST SAMATE Juliet và trích xuất bảng số liệu LaTeX cho báo cáo. |

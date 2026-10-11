# Báo Cáo Tiến Độ Nghiên Cứu Đề Tài (Cập Nhật Tháng 10/2026)

**Tên đề tài chính thức:** Nghiên cứu kiến trúc Multi-Agent Hybrid kết hợp AST truyền thống và Mô hình ngôn ngữ lớn (LLM) nhằm tối ưu hóa độ chính xác trong kiểm thử bảo mật mã nguồn

**Nhóm sinh viên thực hiện:** Trần Hoàng Phúc Quân, Phạm Thị Vân Ánh, Nguyễn Lê Đức Tuệ

**Giảng viên hướng dẫn:** Kính gửi Thầy hướng dẫn đề tài tốt nghiệp

**Kho lưu trữ mã nguồn:** https://github.com/PhucQuan/MultiAgent-SAST (chuyển từ repo cũ SAST_tool4pentester)

**Ngày báo cáo:** 11/10/2026 (Báo cáo định kỳ tuần 1-2 Tháng 10)

---

## 1. Mục Đích Bản Cập Nhật

Bản báo cáo này tiếp nối Đề cương cập nhật Tháng 9, nhằm báo cáo với Thầy các tiến triển kỹ thuật và kết quả đo đạc thực nghiệm mới nhất của nhóm trong hai tuần đầu Tháng 10/2026. Trọng tâm của giai đoạn này gồm ba nội dung chính:

1. Chuyển từ các tập kiểm thử thu nhỏ sang đo đạc thực nghiệm diện rộng trên toàn bộ 1,230 ca kiểm thử của bộ chuẩn mực quốc tế OWASP Benchmark for Python v0.1.
2. Hoàn thiện nghiên cứu cắt lớp (Ablation Study 4 tầng) để chứng minh định lượng tính đóng góp của từng thành phần: Cú pháp luật (Rule-only), Đồ thị luồng dữ liệu (DFG), Tóm tắt liên hàm (Inter-procedural Summary) và Tác tử phản biện (Multi-Agent Triage).
3. Chuẩn hóa kiến trúc hệ thống theo các đặc tả kỹ thuật chuẩn mực từ các nền tảng SAST hàng đầu (CodeQL, Semgrep Pro, Snyk) và các nghiên cứu mới (VulAgent, VulnDetect AI 2026), thay vì áp dụng các giải pháp chắp vá cục bộ theo bộ benchmark.

---

## 2. Cập Nhật Tiến Độ Dự Án (5 Blocks Architecture)

Dựa trên sơ đồ kiến trúc 5 khối (5 Blocks Architecture) đã báo cáo với Thầy trong Tháng 9, tiến độ hiện tại của đề tài được cập nhật như sau:

| Giai Đoạn (Phase) | Thành Phần Kỹ Thuật Cốt Lõi | Tiến Độ T9 | Tiến Độ Hiện Tại (T10) | Trạng Thái Kỹ Thuật |
|---|---|---:|---:|---|
| **Phase 1: Repo Intake & AST Parsing** | Tree-sitter AST, Symbol Table, Language Intake | 95% | **95%** | Ổn định, hỗ trợ đa ngôn ngữ với lane Python chuyên sâu |
| **Phase 2: SAST Detection Core** | Taint Engine, CFG/DFG, Sanitizer Filters | 90% | **92%** | Tích hợp TaintBridge nối Semgrep OSS và DFG liên hàm |
| **Phase 3: Finding Normalization** | Unified Schema, Heuristic Scorer, Evidence Pack | 90% | **92%** | Cấu trúc hóa Evidence Bundle 3 bước (Source -> Propagation -> Sink) |
| **Phase 4: AI Multi-Agent Triage** | Auditor, Skeptic, Judge, LangGraph Bridge | 75% | **82%** | Hoàn thiện luồng phản biện hai chiều, adapter tương thích OpenAI local |
| **Phase 5: Artifacts, Dashboard & Benchmark** | Dashboard React/Next.js, SARIF, OWASP Scorer | 90% | **95%** | Hoàn thành runner chấm tự động 1,230 cases và REST API điều khiển |
| **Tổng thể dự án** | **Toàn bộ pipeline Aegis-SAST** | **88%** | **91%** | **Đủ điều kiện kiểm thử diện rộng và phục vụ bảo vệ** |

---

## 3. Những Công Việc Kỹ Thuật Đã Hoàn Thành Trong Tuần Qua

### 3.1. Thực nghiệm diện rộng trên 1,230 test cases OWASP Benchmark Python
Nhóm đã hoàn thiện runner đo đạc tự động thời gian thực (`scripts/run_owasp_benchmark_fresh.py`) quét toàn bộ 1,230 tệp mã nguồn Python độc lập (`BenchmarkTest00001.py` đến `BenchmarkTest01230.py`) tại `D:\BenchmarkPython\testcode`.

Hệ thống quét với 1,066 rules từ Semgrep Community Registry, sau đó đưa qua bộ cầu nối Tree-sitter DFG (`TaintBridge`) và đối chiếu trực tiếp với ground-truth `expectedresults-0.1.csv`. Toàn bộ dữ liệu được tính toán động thời gian thực trong 78.38 giây, đảm bảo tính liêm chính học thuật (100% không hardcode).

### 3.2. Nghiên cứu cắt lớp (Ablation Study 4 tầng)
Để phục vụ bài báo khoa học và thuyết minh khóa luận, nhóm đã xây dựng runner `scripts/run_ablation_study.py` để kiểm chứng độc lập 4 tầng kỹ thuật:
- **Tầng 1 (Rule-Only Syntax):** Chỉ dùng đối sánh mẫu cú pháp bề mặt.
- **Tầng 2 (Intra-file DFG Taint):** Bổ sung đồ thị luồng dữ liệu trong phạm vi file đơn.
- **Tầng 3 (Cross-file Inter-procedural Summary):** Bổ sung bộ tóm tắt hàm liên file để giải quyết điểm mù chuỗi khai thác đa module.
- **Tầng 4 (Multi-Agent Skeptic Triage):** Bổ sung tác tử phản biện để kiểm tra cơ chế làm sạch và điều kiện rẽ nhánh.

Kết quả định lượng chứng minh độ chính xác cải thiện rõ rệt: từ 33.3% ở Tầng 1 lên 100% ở Tầng 4 trên chuỗi khai thác đa module.

### 3.3. Hoàn thiện REST API nội bộ và Dashboard tương tác phục vụ Demo
Nhóm đã triển khai module `aegis_sast/api/routes.py` cung cấp các API endpoint:
- Kích hoạt tiến trình quét nền bất đồng bộ và trả về Task ID.
- Theo dõi trạng thái tiến trình quét theo thời gian thực (real-time progress tracking).
- Cung cấp danh sách finding chuẩn hóa phục vụ giao diện người dùng.

Dashboard (`apps/findings-dashboard`) hiện đã kết nối trực tiếp với backend API, cho phép trực quan hóa đường dẫn vấy bẩn (Taint Flow Trace), hiển thị bảng bằng chứng phản biện (Evidence Ledger của Auditor/Skeptic/Judge) và cung cấp gợi ý bản vá bảo mật (Remediation Patch Diff).

### 3.4. Tự động hóa CI/CD với GitHub Actions
Nhóm đã thiết lập workflow `.github/workflows/aegis-scan.yml` trên GitHub. Mỗi lượt cập nhật mã nguồn đều tự động kích hoạt bộ kiểm thử gồm 278 unit tests nhằm ngăn ngừa lỗi hồi quy (regression) trong quá trình phát triển.

---

## 4. Báo Cáo Số Liệu Thực Nghiệm Mới Nhất

### 4.1. Bảng số liệu toàn cục trên 1,230 test cases OWASP Benchmark Python

Kết quả đối chiếu trên 677 test cases nằm trong phạm vi tập luật:

| Hệ Thống / Chế Độ Đánh Giá | TP | FP | FN | TN | Precision | Recall | F1-Score | FP Reduction |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Baseline (Semgrep OSS Thô - Mode all)** | 130 | 640 | 110 | 251 | **16.88%** | 54.17% | 25.74% | *Mốc gốc (0%)* |
| **Aegis-SAST (Taint/DFG Bridge - Mode visible)** | 111 | **224** | 129 | 312 | **33.13%** | 46.25% | **38.61%** | **-65.00%** |

**Phân tích kỹ thuật từ kết quả:**
1. **Triệt tiêu 65.00% False Positive:** Aegis-SAST loại bỏ thành công 416 cảnh báo giả mà Semgrep nguyên bản báo nhầm (từ 640 FP xuống còn 224 FP).
2. **Precision tăng gần gấp đôi:** Tăng từ 16.88% lên 33.13% (tăng tương đối +96.27%).
3. **F1-Score cải thiện 50%:** Tăng từ 0.2574 lên 0.3861.

### 4.2. Bảng số liệu trên 4 họ lỗ hổng trọng tâm (Core 4 Families)

Khi đánh giá riêng trên 4 họ lỗ hổng mục tiêu mà nhóm tập trung thiết kế mô hình đồ thị DFG (Command Injection CWE-78, Path Traversal CWE-22, Insecure Deserialization CWE-502, SQL Injection CWE-89):

| Hệ Thống (Phạm vi 4 Họ Cốt Lõi) | TP | FP | FN | Precision | Recall | F1-Score | FP Reduction |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Semgrep OSS Gốc (Baseline)** | 70 | 348 | 31 | **16.75%** | 69.31% | **26.97%** | *0%* |
| **Aegis-SAST (DFG + Taint Bridge)** | 59 | **36** | 42 | **62.11%** | 58.42% | **60.20%** | **-89.66%** |

**Nhận xét kỹ thuật:**
- Trên 4 họ mục tiêu, Aegis-SAST **triệt tiêu 89.66% False Positive** (từ 348 FP xuống còn 36 FP).
- Precision tăng gần 4 lần (từ 16.75% lên 62.11%), F1 tăng hơn gấp đôi (từ 26.97% lên 60.20%).
- Riêng họ **Path Traversal (CWE-22)**: Giảm 93% False Positive (từ 329 xuống 23 FP) nhờ mô hình nhận diện hàm chuẩn hóa `os.path.basename` và `os.path.abspath`.
- Riêng họ **SQL Injection (CWE-89)**: Đạt Precision 100% (FP = 0).

---

## 5. Tham Chiếu Kiến Trúc Chuẩn Doanh Nghiệp (Không Tối Ưu Cục Bộ Theo Benchmark)

### 5.1. Phân tích nguyên nhân điểm tổng thể bị giới hạn
Khi đánh giá trên toàn bộ 10 họ lỗi, điểm F1 dừng ở mức 38.61% do hơn 70% số lượng False Positive còn lại tập trung ở hai nhóm:
1. **XSS (CWE-79) với 115 FP:** Các ca kiểm thử đều sử dụng hàm `escape_for_html(...)` trong cấu trúc chuỗi multiline `RESPONSE += ...`. Rule Semgrep gắn cờ toàn bộ lệnh trả về, trong khi bộ trích xuất sanitizer cũ chỉ đọc dòng đầu tiên nên bỏ sót cơ chế làm sạch này.
2. **XXE (CWE-611) bị mất Recall:** Semgrep bắt mọi lệnh `import xml.dom.minidom` (sinh ra 77 FP). Bộ lọc cũ của Aegis thấy dòng import không có luồng dữ liệu vấy bẩn nên dập tắt toàn bộ, làm mất 8 ca lỗi thật.

### 5.2. Nguyên tắc nghiên cứu: Tránh bẫy Overfitting, tuân thủ chuẩn công nghiệp
Nhóm kiên định quan điểm: **Tuyệt đối không tự chế các luật chắp vá (ad-hoc regex) để khớp tên biến của benchmark**. Để công cụ có giá trị ứng dụng thực tế trong môi trường doanh nghiệp, nhóm tham chiếu trực tiếp các đặc tả kỹ thuật từ các nền tảng phân tích tĩnh và nghiên cứu quốc tế:

#### A. Đặc tả Taint Barrier chuẩn CodeQL (GitHub CodeQL Specification)
Trong CodeQL Python Taint Tracking (`semmle.python.dataflow.new.TaintTracking`), khái niệm Sanitizer và Guard được chuẩn hóa thông qua vị ngữ `isBarrier(DataFlow::Node node)`. Aegis-SAST sẽ áp dụng cơ chế Barrier chuẩn này:
- **Sanitizer Barrier:** Bắt các hàm mã hóa ngữ cảnh (`html.escape`, `bleach.clean`, `shlex.quote`, `os.path.basename`).
- **Type Barrier:** Các hàm ép kiểu dữ liệu an toàn (`int()`, `float()`, `UUID()`, Pydantic Schema Validator) đóng vai trò là điểm cắt vấy bẩn (untaint barrier).

#### B. Đặc tả kiểm tra cấu hình XXE chuẩn CodeQL `py/xxe` (CWE-611)
Theo đặc tả của CodeQL `python/ql/src/Security/CWE-611/Xxe.ql` và OWASP Cheat Sheet:
- Một parser XML chỉ bị coi là có lỗ hổng XXE khi nhận dữ liệu người dùng **VÀ** cấu hình parser cho phép phân giải thực thể ngoài.
- Với thư viện `xml.sax` / `minidom`: Cờ `feature_external_ges` hoặc `feature_external_pes` phải được gán giá trị `True`. Nếu cờ này không được kích hoạt, parser an toàn theo mặc định $\rightarrow$ Phải coi là Sanitizer Barrier hợp lệ.
- Thư viện `defusedxml` được định nghĩa mặc định là Barrier an toàn cho toàn bộ luồng XML.

#### C. Phân tích khả năng kích hoạt (Reachability Analysis từ Semgrep Pro / CodeQL)
Trong dự án doanh nghiệp, phần lớn code là tiện ích nội bộ hoặc batch job. Aegis-SAST xây dựng ranh giới tin cậy (Trust Boundary):
- Xác định điểm vào công khai (**Public Entrypoints**): Các route controller của Flask (`@app.route`), FastAPI (`@router`), Django views.
- Chỉ gắn cờ nguy hiểm cao (High Risk) khi tồn tại đường dẫn kích hoạt liên hàm từ Public Entrypoint đến Sink. Các hàm nằm ngoài luồng gọi công khai được hạ mức ưu tiên để tránh Alert Fatigue.

#### D. Luồng thẩm định phản biện giả thuyết (Hypothesis-Validation từ VulAgent / VulnDetect AI 2026)
Thay vì sử dụng prompt chung chung "đoán xem code có lỗi không", hệ thống áp dụng luồng kiểm chứng giả thuyết có thể bác bỏ (Falsifiable Hypothesis Testing):
- **Auditor Agent:** Thiết lập giả thuyết tấn công cụ thể (Source, Sink, điều kiện kích hoạt payload).
- **Skeptic Agent:** Tìm kiếm bằng chứng phản bác (Kiểm tra Sanitizer Barrier, điều kiện rẽ nhánh bảo vệ, cấu hình an toàn).
- **Judge Agent:** Đóng vai trò trọng tài, chỉ xác nhận lỗ hổng khi Auditor có đường dẫn đầy đủ và Skeptic không tìm thấy bằng chứng phòng vệ hợp lệ.

---

## 6. Kế Hoạch Triển Khai Trong Tuần Tiếp Theo

Trong tuần tới, nhóm tập trung triển khai các đầu việc kỹ thuật theo đúng đặc tả tham chiếu:

1. **Chuẩn hóa Taint Barrier cho XSS:** Nâng cấp bộ trích xuất Sanitizer trong `TaintBridge` để quét toàn diện biểu thức gán đa dòng, nhận diện chính xác các hàm mã hóa HTML theo chuẩn OWASP.
2. **Áp dụng kiểm tra cấu hình parser cho XXE:** Cập nhật detector theo đặc tả CodeQL `py/xxe`, kiểm tra cờ `feature_external_ges` để khôi phục 100% Recall và triệt tiêu 77 False Positive của họ XXE.
3. **Mô hình hóa Field-Sensitive DFG:** Lần vết dữ liệu chi tiết theo từng khóa (key-sensitive) cho Dictionary và đối tượng cấu hình, nhận diện chính xác các giá trị hằng số an toàn.
4. **Đo đạc thực nghiệm với Local LLM Runtime:** Chạy thử nghiệm lớp Multi-Agent Triage với mô hình mã nguồn mở cục bộ (Ollama / vLLM) để đánh giá độ trễ và khả năng giảm nhiễu.
5. **Chuẩn bị Demo:** Rà soát kịch bản trình diễn end-to-end trên Dashboard để sẵn sàng báo cáo trực tiếp với Thầy.

---

## 7. Kết Luận

Trong hai tuần đầu Tháng 10, đề tài đã đạt được bước chuyển đổi quan trọng: chuyển toàn bộ thực nghiệm sang **bộ dữ liệu chuẩn quốc tế diện rộng 1,230 test cases**, chứng minh được khả năng **giảm 65% - 89% False Positive** của phương pháp lai ghép AST/DFG.

Nhóm kiên định bám sát các chuẩn mực kỹ thuật công nghiệp đã được kiểm chứng (CodeQL, Semgrep Pro, VulAgent) để đảm bảo công cụ có giá trị ứng dụng thực tế trong doanh nghiệp, thay vì tinh chỉnh cục bộ theo bài kiểm thử.

Nhóm kính mong nhận được thêm những ý kiến đóng góp và chỉ dẫn của Thầy để tiếp tục hoàn thiện đề tài trong giai đoạn tới.

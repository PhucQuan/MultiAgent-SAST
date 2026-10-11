# Báo Cáo Tiến Độ Nghiên Cứu Đề Tài (Cập Nhật Tháng 10/2026)

**Tên đề tài chính thức:** Nghiên cứu kiến trúc Multi-Agent Hybrid kết hợp AST truyền thống và Mô hình ngôn ngữ lớn (LLM) nhằm tối ưu hóa độ chính xác trong kiểm thử bảo mật mã nguồn

**Nhóm sinh viên thực hiện:** Trần Hoàng Phúc Quân, Phạm Thị Vân Ánh, Nguyễn Lê Đức Tuệ

**Giảng viên hướng dẫn:** Kính gửi Thầy hướng dẫn đề tài tốt nghiệp

**Kho lưu trữ mã nguồn:** https://github.com/PhucQuan/MultiAgent-SAST (chuyển từ repo cũ SAST_tool4pentester)

**Ngày báo cáo:** 11/10/2026

---

## 1. Khảo Cứu Các Giải Pháp Quốc Tế & Định Vị Kiến Trúc Của Đề Tài

Để giải quyết bài toán cốt lõi của đề tài là **tối ưu hóa độ chính xác và giảm thiểu tỷ lệ cảnh báo giả (False Positive - FP)** trong phân tích tĩnh mã nguồn, nhóm đã tiến hành khảo cứu các giải pháp công nghiệp và học thuật tiêu biểu trên thế giới:

### 1.1. Khảo cứu các giải pháp phân tích tĩnh công nghiệp
1. **GitHub CodeQL:**
   - CodeQL sử dụng mô hình dữ liệu hóa mã nguồn (Code-as-Data) và cơ chế phân tích luồng vấy bẩn toàn cục (`DataFlow::Global`, `TaintTracking::Global`).
   - Điểm kỹ thuật quan trọng của CodeQL là việc chuẩn hóa điểm cắt vấy bẩn thành vị ngữ **`isBarrier(DataFlow::Node node)`**. Vị ngữ này bao gồm cả hàm làm sạch (Sanitizer), cơ chế ép kiểu an toàn (Type Barrier như `int()`, `float()`), và các điều kiện rẽ nhánh bảo vệ (Guard Condition).
   - Với các lỗ hổng cấu hình như XXE (CWE-611), truy vấn chuẩn của CodeQL (`py/xxe`) không gắn cờ toàn bộ lệnh nhập thư viện XML, mà kiểm tra xem parser có bị kích hoạt cờ phân giải thực thể ngoài (`feature_external_ges = True`) hay không.
2. **Meta Pysa & Zoncolan (Taint Analysis at Scale):**
   - Meta giải quyết bài toán phân tích hàng trăm triệu dòng code bằng nguyên lý **Models-as-Data**: tách rời hoàn toàn lõi phân tích (core engine) khỏi các tệp đặc tả luồng dữ liệu (source, sink, sanitizer rules).
   - Các framework web (Django, Flask, Thrift) được mô hình hóa thành tệp đặc tả riêng biệt, giúp engine tái sử dụng ổn định mà không cần chỉnh sửa logic mã nguồn của bộ phân tích.
3. **Semgrep (OSS vs Pro):**
   - Semgrep OSS hoạt động dựa trên đối sánh mẫu cú pháp cục bộ trong phạm vi một tệp (intra-file AST pattern match). Cách tiếp cận này có tốc độ nhanh nhưng gặp hạn chế lớn: mù luồng dữ liệu liên hàm/liên file và không phân tích được khả năng kích hoạt (Reachability), dẫn đến tỷ lệ False Positive cao khi quét các framework hiện đại.

### 1.2. Khảo cứu các nghiên cứu học thuật mới về Multi-Agent SAST (2025–2026)
- **Mô hình kiểm chứng giả thuyết có thể bác bỏ (VulAgent, ACL 2026):** Nghiên cứu chỉ ra rằng việc đưa toàn bộ mã nguồn vào LLM với các câu lệnh nhắc chung chung ("code có an toàn không?") dẫn đến tình trạng đoán mò và sinh ảo giác. VulAgent đề xuất quy trình hai chiều: tác tử sinh giả thuyết tấn công (Auditor) và tác tử tìm kiếm bằng chứng phòng vệ để bác bỏ giả thuyết (Skeptic).
- **Mô hình phối hợp đồ thị tác tử (VulnDetect AI, 2026):** Kết hợp công cụ phân tích tĩnh truyền thống với luồng tác tử theo kiến trúc đồ thị (LangGraph) để truy xuất tài liệu framework và kiểm tra giá trị trả về trước khi đưa ra phán quyết cuối cùng.

### 1.3. Định vị kiến trúc của Aegis-SAST
Từ các khảo cứu trên, nhóm xác định kiến trúc của Aegis-SAST không tự chế các luật chắp vá cục bộ, mà kế thừa các nguyên lý đã được kiểm chứng:
1. **Lớp nền tảng phân tích tĩnh (Deterministic Core):** Kế thừa cơ chế đồ thị luồng điều khiển và luồng dữ liệu (CFG/DFG) dựa trên Tree-sitter, áp dụng đặc tả điểm cắt vấy bẩn (Taint Barrier) theo chuẩn CodeQL và phân tích liên hàm (Inter-procedural Summary).
2. **Lớp ranh giới tin cậy (Reachability Analysis):** Xác định đường dẫn từ điểm vào công khai (Public Entrypoints: `@app.route`, views) xuyên qua Service đến Sink.
3. **Lớp thẩm định đa tác tử (Multi-Agent Verification):** Kế thừa mô hình kiểm chứng giả thuyết (Hypothesis-Validation) của VulAgent với ba vai trò có hợp đồng dữ liệu rõ ràng: Auditor (dựng kịch bản khai thác) $\leftrightarrow$ Skeptic (tìm bằng chứng làm sạch/phòng vệ) $\leftrightarrow$ Judge (phán quyết và xuất bằng chứng).

---

## 2. Các Công Việc Nhóm Đã Hoàn Thành Trong Tuần Qua

Trong tuần vừa qua, nhóm tập trung vào 4 công việc chính:

1. **Thực nghiệm diện rộng trên toàn bộ 1,230 test cases OWASP Benchmark Python:**
   - Xây dựng runner tự động thời gian thực (`scripts/run_owasp_benchmark_fresh.py`) quét và chấm điểm trực tiếp toàn bộ 1,230 tệp mã nguồn độc lập (`BenchmarkTest00001.py` đến `BenchmarkTest01230.py`) đối chiếu với ground-truth chuẩn `expectedresults-0.1.csv`.
   - Toàn bộ kết quả được tính toán động (100% không hardcode), hoàn thành trong 78.38 giây.
2. **Thực hiện nghiên cứu cắt lớp (Ablation Study 4 tầng):**
   - Xây dựng kịch bản kiểm thử độc lập tại `scripts/run_ablation_study.py` để chứng minh định lượng vai trò của từng thành phần kỹ thuật: Rule-only cú pháp $\rightarrow$ Intra-file DFG $\rightarrow$ Inter-procedural Summary $\rightarrow$ Multi-Agent Triage.
3. **Hoàn thiện REST API nội bộ và kết nối Dashboard tương tác:**
   - Triển khai module `aegis_sast/api/routes.py` hỗ trợ khởi chạy tiến trình quét nền bất đồng bộ, theo dõi tiến độ theo thời gian thực và trích xuất finding chuẩn hóa.
   - Nối thành công Dashboard React/Next.js vào backend API để trực quan hóa đường dẫn khai thác (Taint Flow Trace) và bảng bằng chứng phản biện (Evidence Ledger).
4. **Tự động hóa kiểm thử liên tục (CI/CD):**
   - Thiết lập workflow `.github/workflows/aegis-scan.yml` trên GitHub để tự động chạy kiểm thử bộ 278 unit tests của hệ thống sau mỗi lần cập nhật mã nguồn.

---

## 3. Kết Quả Đo Đạc Thực Nghiệm Định Lượng

### 3.1. Kết quả trên toàn bộ 1,230 test cases OWASP Benchmark Python

Đánh giá đối chiếu trên 677 test cases thuộc phạm vi các họ lỗ hổng được hỗ trợ:

| Hệ Thống / Chế Độ Đánh Giá | TP | FP | FN | TN | Precision | Recall | F1-Score | FP Reduction |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Baseline (Semgrep OSS Thô - Mode all)** | 130 | 640 | 110 | 251 | **16.88%** | 54.17% | 25.74% | *Mốc gốc (0%)* |
| **Aegis-SAST (Taint/DFG Bridge - Mode visible)** | 111 | **224** | 129 | 312 | **33.13%** | 46.25% | **38.61%** | **-65.00%** |

**Nhận xét kỹ thuật:**
- **Khử 65.00% False Positive:** Aegis-SAST triệt tiêu được 416 cảnh báo giả mà Semgrep nguyên bản báo nhầm (từ 640 FP xuống 224 FP).
- **Precision tăng gần gấp đôi:** Từ 16.88% lên 33.13% (tăng tương đối +96.27%).
- **F1-Score cải thiện 50%:** Từ 0.2574 lên 0.3861.

### 3.2. Kết quả bóc tách trên 4 họ lỗ hổng trọng tâm (Core 4 Families)

Khi đánh giá trên 4 họ lỗ hổng mà nhóm đã thiết kế mô hình DFG và Sanitizer chuyên sâu (CWE-78 Command Injection, CWE-22 Path Traversal, CWE-502 Deserialization, CWE-89 SQL Injection):

| Hệ Thống (Phạm vi 4 Họ Cốt Lõi) | TP | FP | FN | Precision | Recall | F1-Score | FP Reduction |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Semgrep OSS Gốc (Baseline)** | 70 | 348 | 31 | **16.75%** | 69.31% | **26.97%** | *0%* |
| **Aegis-SAST (DFG + Taint Bridge)** | 59 | **36** | 42 | **62.11%** | 58.42% | **60.20%** | **-89.66%** |

**Nhận xét kỹ thuật:**
- Trên 4 họ trọng tâm, Aegis-SAST **triệt tiêu tới 89.66% False Positive** (từ 348 FP xuống 36 FP).
- Precision đạt **62.11%** (gấp gần 4 lần Semgrep 16.75%), F1 đạt **60.20%** (so với 26.97% của Semgrep).
- Riêng họ **Path Traversal (CWE-22)**: Giảm 93% False Positive (từ 329 xuống 23 FP) nhờ mô hình nhận diện hàm chuẩn hóa đường dẫn `os.path.basename` và `os.path.abspath`.
- Riêng họ **SQL Injection (CWE-89)**: Đạt Precision 100% tuyệt đối (FP = 0).

---

## 4. Những Khó Khăn & Hạn Chế Kỹ Thuật Đang Gặp Phải

Nhóm xin báo cáo trung thực với Thầy 4 khó khăn kỹ thuật cốt lõi hiện nay:

1. **Hiện tượng bị kéo tụt điểm khi mở rộng ra 10 họ lỗ hổng:**
   - Trong 224 FP còn lại của hệ thống, riêng họ XSS chiếm 115 FP. Nguyên nhân do toàn bộ test case của benchmark đều dùng hàm `escape_for_html(...)` trong cấu trúc chuỗi trả về đa dòng (`RESPONSE += ...`). Bộ trích xuất sanitizer cũ của nhóm chỉ đọc dòng đầu nên bỏ sót hàm escape này.
   - Đối với họ XXE, Semgrep bắt bừa mọi dòng `import xml.dom.minidom` (77 FP). Bộ lọc cũ thấy dòng import không có luồng dữ liệu nên dập tắt toàn bộ, làm mất luôn cả 8 ca lỗ hổng thật (Recall XXE về 0).
2. **Rủi ro tối ưu hóa cục bộ theo bài kiểm thử (Overfitting Benchmark):**
   - Trong benchmark có nhiều mẫu gán bẫy hằng số (như đọc key cố định từ Dictionary hay ConfigParser). Nếu nhóm chỉ viết code để bắt đúng các tên biến này thì điểm số sẽ cao nhưng vô dụng trên mã nguồn thực tế của doanh nghiệp. Nhóm cần giải quyết ở mức trừu tượng hóa phân tích trường (Field-sensitive analysis).
3. **Bài toán đóng gói ngữ cảnh cho tác tử LLM:**
   - Không thể đưa toàn bộ cây AST hay mã nguồn cả file vào prompt vì chi phí token lớn và độ trễ cao. Nhóm đang phải giải quyết bài toán trích xuất lát cắt mã nguồn tối thiểu (Slicing Context Window) chỉ chứa Source, Propagation path, Sanitizer và Sink để cung cấp cho tác tử.
4. **Sự chênh lệch độ sâu phân tích giữa các ngôn ngữ:**
   - Lane Python hiện đi sâu nhất với DFG liên hàm và tóm tắt hàm. Trong khi đó, lane Java và JavaScript mới dừng ở mức phân tích cú pháp trong phạm vi file (intra-file), chưa có độ sâu tương đương.

---

## 5. Kế Hoạch Triển Khai Trong Tuần Tiếp Theo

Dựa trên các khảo cứu quốc tế và kết quả đo đạc thực tế, nhóm dự kiến thực hiện các công việc sau trong tuần tới:

1. **Chuẩn hóa Taint Barrier cho XSS theo chuẩn OWASP:**
   - Cập nhật hàm trích xuất Sanitizer trong `TaintBridge` để phân tích đầy đủ biểu thức gán đa dòng, nhận diện chính xác các hàm mã hóa HTML (`escape_for_html`, `html.escape`, `markupsafe.escape`, `bleach.clean`), giải quyết triệt để 115 False Positive của họ XSS.
2. **Triển khai kiểm tra cấu hình XXE theo chuẩn CodeQL `py/xxe`:**
   - Bổ sung logic kiểm tra cờ cấu hình parser `feature_external_ges`: nếu không được bật `True` (hoặc sử dụng `defusedxml`), hệ thống xác định parser an toàn theo mặc định và coi đây là Barrier hợp lệ. Mục tiêu khôi phục 100% Recall và triệt tiêu 77 False Positive của họ XXE.
3. **Phân tích luồng dữ liệu theo trường (Field-Sensitive DFG):**
   - Theo dõi độc lập từng trường dữ liệu cho Dictionary (`map['key']`) và ConfigParser (`conf.get/set`) để phân biệt chính xác giữa giá trị an toàn và giá trị bị vấy bẩn.
4. **Thử nghiệm tích hợp Local LLM Runtime:**
   - Kết nối lớp Multi-Agent Triage với runtime cục bộ (Ollama / vLLM) chạy mô hình mã nguồn mở để đánh giá thực nghiệm về độ trễ, chi phí và chất lượng phản biện.
5. **Chuẩn bị báo cáo trực tiếp:**
   - Hoàn thiện kịch bản demo trực quan trên Web Dashboard để báo cáo tiến độ với Thầy trong buổi làm việc sắp tới.

---

## 6. Kết Luận

Trong giai đoạn vừa qua, nhóm đã chuyển thành công toàn bộ thực nghiệm sang **bộ chuẩn mực quốc tế diện rộng 1,230 test cases**, chứng minh bằng số liệu thực tế khả năng **triệt tiêu 65% - 89% cảnh báo giả** của phương pháp lai ghép AST/DFG.

Nhóm kiên định đi theo các đặc tả kỹ thuật chuẩn mực của các hệ thống quốc tế (CodeQL, Semgrep Pro, VulAgent) nhằm đảm bảo công cụ có giá trị học thuật và khả năng ứng dụng thực tế, thay vì áp dụng các giải pháp chắp vá theo bài kiểm thử.

Nhóm kính mong nhận được thêm các ý kiến nhận xét và định hướng của Thầy để hoàn thiện đề tài trong giai đoạn tiếp theo.

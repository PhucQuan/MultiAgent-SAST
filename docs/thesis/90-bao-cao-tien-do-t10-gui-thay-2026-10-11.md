# Báo Cáo Tiến Độ Nghiên Cứu Đề Tài (Cập Nhật Tháng 10/2026)

**Tên đề tài chính thức:** Nghiên cứu kiến trúc Multi-Agent Hybrid kết hợp AST truyền thống và Mô hình ngôn ngữ lớn (LLM) nhằm tối ưu hóa độ chính xác trong kiểm thử bảo mật mã nguồn

**Nhóm sinh viên thực hiện:** Trần Hoàng Phúc Quân, Phạm Thị Vân Ánh, Nguyễn Lê Đức Tuệ

**Giảng viên hướng dẫn:** Kính gửi Thầy hướng dẫn đề tài tốt nghiệp

**Kho lưu trữ mã nguồn:** https://github.com/PhucQuan/MultiAgent-SAST (chuyển từ repo cũ SAST_tool4pentester)

**Ngày báo cáo:** 11/10/2026 (Báo cáo định kỳ tuần 1-2 Tháng 10)

---

## 1. Mục Đích Bản Cập Nhật

Bản báo cáo này tiếp nối Đề cương cập nhật Tháng 9, nhằm báo cáo với Thầy các kết quả nghiên cứu và thực nghiệm mới nhất của nhóm trong hai tuần đầu Tháng 10/2026. Trọng tâm của giai đoạn này là:

1. Chuyển từ các tập kiểm thử thu nhỏ sang đo đạc thực nghiệm diện rộng trên toàn bộ 1,230 ca kiểm thử của bộ chuẩn quốc tế OWASP Benchmark for Python v0.1.
2. Hoàn thiện nghiên cứu cắt lớp (Ablation Study 4 tầng) để chứng minh định lượng giá trị đóng góp của từng thành phần: AST, Taint Graph, Inter-procedural Summary và Multi-Agent Triage.
3. Tích hợp hoàn chỉnh tầng API nội bộ và Dashboard tương tác để phục vụ kịch bản demo trực quan cho buổi báo cáo sắp tới.
4. Trình bày trung thực các hạn chế khi mở rộng ra 10 họ lỗ hổng, từ đó đề xuất hướng nâng cấp theo kiến trúc SAST doanh nghiệp (Reachability Analysis và Framework Defense Modeling) thay vì tối ưu cục bộ theo benchmark.

---

## 2. Bản Đồ Tiến Độ Thực Hiện: "Dự Án Đang Ở Bước Mấy?"

Dựa trên sơ đồ kiến trúc 5 khối (5 Blocks Architecture) đã báo cáo với Thầy trong Tháng 9, tiến độ hiện tại của đề tài được cập nhật như sau:

| Giai Đoạn (Phase) | Thành Phần Cốt Lõi | Tiến Độ T9 | Tiến Độ Hiện Tại (T10) | Trạng Thái Kỹ Thuật |
|---|---|---:|---:|---|
| **Phase 1: Repo Intake & AST Parsing** | Tree-sitter AST, Symbol Table, Language Detect | 95% | **95%** | Hoàn thành ổn định, hỗ trợ đa ngôn ngữ với lane Python chuyên sâu |
| **Phase 2: SAST Detection Core** | Source-to-Sink Taint Engine, DFG, Sanitizers | 90% | **92%** | Bổ sung TaintBridge nối Semgrep OSS và Tree-sitter DFG liên hàm |
| **Phase 3: Finding Normalization** | Unified Schema, Heuristic Scorer, Evidence Pack | 90% | **92%** | Chuẩn hóa schema CWE/OWASP, cấu trúc hóa Evidence Bundle 3 bước |
| **Phase 4: AI Multi-Agent Triage** | Auditor, Skeptic, Judge, LangGraph Bridge | 75% | **82%** | Bổ sung adapter tương thích OpenAI local, hoàn thiện luồng phản biện |
| **Phase 5: Artifacts, Dashboard & Benchmark** | Dashboard React/Next.js, SARIF, OWASP Scorer | 90% | **95%** | Hoàn thành runner chấm điểm 1,230 cases và API điều khiển Dashboard |
| **Tổng thể dự án** | **Toàn bộ pipeline Aegis-SAST** | **88%** | **91%** | **Đủ điều kiện thực nghiệm diện rộng và chuẩn bị bảo vệ** |

---

## 3. Những Công Việc Kỹ Thuật Nhóm Đã Giải Quyết Trong Tuần Qua

### 3.1. Chạy thực nghiệm diện rộng trên 1,230 file OWASP Benchmark Python
Ở các giai đoạn trước, nhóm chủ yếu đo đạc trên các tệp mẫu rút gọn hoặc các ca kiểm thử đơn lẻ. Trong tuần qua, nhóm đã hoàn thiện runner tự động thời gian thực (`scripts/run_owasp_benchmark_fresh.py`) quét toàn bộ 1,230 tệp mã nguồn Python thật (`BenchmarkTest00001.py` đến `BenchmarkTest01230.py`) tại `D:\BenchmarkPython\testcode`.

Quá trình quét được thực thi độc lập với 1,066 rules từ Semgrep Community Registry, sau đó đưa qua bộ cầu nối Tree-sitter DFG (`TaintBridge`) và chấm điểm tự động đối chiếu với nhãn chuẩn `expectedresults-0.1.csv`. Toàn bộ dữ liệu được tính toán động, không can thiệp thủ công hay hardcode số liệu.

### 3.2. Thực hiện nghiên cứu cắt lớp (Ablation Study 4 tầng)
Để phục vụ bài báo khoa học và thuyết minh khóa luận, nhóm đã xây dựng kịch bản kiểm chứng độc lập 4 tầng kỹ thuật trên runner `scripts/run_ablation_study.py`:
- **Tầng 1 (Rule-Only Syntax):** Chỉ dùng luật đối sánh mẫu cú pháp đơn thuần.
- **Tầng 2 (Intra-file DFG Taint):** Bổ sung đồ thị luồng dữ liệu trong phạm vi file đơn.
- **Tầng 3 (Cross-file Inter-procedural Summary):** Bổ sung bộ tóm tắt hàm liên file để phát hiện chuỗi khai thác đa module.
- **Tầng 4 (Multi-Agent Skeptic Triage):** Bổ sung tác tử phản biện để kiểm tra cơ chế làm sạch và điều kiện rẽ nhánh.

Kết quả định lượng cho thấy sự cải thiện rõ ràng qua từng nấc thang: từ độ chính xác 33.3% ở Tầng 1 lên 100% ở Tầng 4 trên chuỗi khai thác đa module.

### 3.3. Hoàn thiện API nội bộ và Dashboard tương tác phục vụ Demo
Nhóm đã triển khai xong module `aegis_sast/api/routes.py` cung cấp các REST API cho hệ thống:
- Khởi chạy quét nền bất đồng bộ và trả về mã tác vụ.
- Theo dõi tiến độ quét theo thời gian thực (real-time progress tracking).
- Xuất kết quả finding và báo cáo chuẩn hóa.

Dashboard giao diện người dùng (`apps/findings-dashboard`) hiện đã kết nối trực tiếp với backend API. Người dùng có thể xem danh sách lỗ hổng, trực quan hóa đường dẫn vấy bẩn (Taint Flow Trace: Source -> Propagation -> Sink), theo dõi lý lẽ phản biện của Auditor/Skeptic/Judge và xem bản vá code an toàn (Suggested Remediation Patch).

### 3.4. Tự động hóa CI/CD với GitHub Actions
Nhóm đã thiết lập quy trình kiểm thử tự động tại `.github/workflows/aegis-scan.yml`. Mỗi khi có mã nguồn mới được đẩy lên nhánh main, hệ thống tự động chạy toàn bộ 278 unit tests và kiểm tra pipeline quét tĩnh nhằm đảm bảo không phát sinh lỗi hồi quy (regression).

---

## 4. Báo Cáo Số Liệu Thực Nghiệm Mới Nhất

### 4.1. Bảng số liệu toàn cục trên 1,230 test cases OWASP Benchmark Python

Kết quả quét và chấm điểm tự động trên toàn bộ kho chuẩn mực đối chiếu với `expectedresults-0.1.csv`:

| Hệ Thống / Chế Độ Đánh Giá | TP | FP | FN | TN | Precision | Recall | F1-Score | FP Reduction |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Baseline (Semgrep OSS Thô - Mode all)** | 130 | 640 | 110 | 251 | **16.88%** | 54.17% | 25.74% | *Mốc gốc (0%)* |
| **Aegis-SAST (Taint/DFG Bridge - Mode visible)** | 111 | **224** | 129 | 312 | **33.13%** | 46.25% | **38.61%** | **-65.00%** |

**Ý nghĩa học thuật từ kết quả:**
1. **Triệt tiêu 65.00% False Positive:** Aegis-SAST đã loại bỏ được 416 cảnh báo rác mà Semgrep nguyên bản báo nhầm (từ 640 FP xuống còn 224 FP).
2. **Độ chính xác (Precision) tăng gần gấp đôi:** Tăng từ 16.88% lên 33.13% (tăng tương đối +96.27%).
3. **F1-Score cải thiện rõ rệt:** Tăng từ 0.2574 lên 0.3861 (tăng tương đối +50.00%).

### 4.2. Bảng số liệu phân tích sâu trên 4 họ lỗ hổng trọng tâm (Core 4 Families)

Khi bóc tách dữ liệu trên 4 họ lỗ hổng trọng tâm mà nhóm tập trung thiết kế mô hình đồ thị luồng dữ liệu (CWE-78 Command Injection, CWE-22 Path Traversal, CWE-502 Insecure Deserialization, CWE-89 SQL Injection):

| Hệ Thống (Phạm vi 4 Họ Cốt Lõi) | TP | FP | FN | Precision | Recall | F1-Score | FP Reduction |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Semgrep OSS Gốc (Baseline)** | 70 | 348 | 31 | **16.75%** | 69.31% | **26.97%** | *0%* |
| **Aegis-SAST (DFG + Taint Bridge)** | 59 | **36** | 42 | **62.11%** | 58.42% | **60.20%** | **-89.66%** |

**Điểm đột phá:**
- Trên 4 nhóm lỗ hổng cốt lõi, Aegis-SAST **triệt tiêu tới 89.66% cảnh báo giả** (từ 348 FP xuống chỉ còn 36 FP).
- Độ chính xác tăng gần 4 lần (từ 16.75% lên 62.11%).
- Riêng họ **Path Traversal (CWE-22)**: False Positive giảm tới 93% (từ 329 ca FP xuống còn 23 ca FP) nhờ mô hình nhận diện hàm chuẩn hóa đường dẫn `os.path.basename` và `os.path.abspath`.
- Riêng họ **SQL Injection (CWE-89)**: Đạt độ chính xác 100% tuyệt đối (FP = 0).

---

## 5. Phân Tích Khó Khăn Học Thuật & Định Hướng Nâng Cấp Chuẩn Doanh Nghiệp

### 5.1. Nhận diện nguyên nhân điểm tổng thể 10 họ bị kéo tụt
Khi mở rộng đánh giá ra toàn bộ 10 họ lỗi của OWASP, điểm F1 tổng thể đạt 38.61% (dù cải thiện 50% so với Semgrep gốc 25.74%) nhưng chưa đạt mức kỳ vọng cao nhất của nhóm. Khi mổ xẻ nguyên nhân kỹ thuật, nhóm nhận thấy hơn 70% số lượng False Positive còn lại tập trung ở hai điểm nghẽn:
1. **XSS (CWE-79) chiếm 115 / 224 FP:** 100% test case trong OWASP Benchmark Python đều sử dụng hàm `escape_for_html(...)` ở cuối route để trả về kết quả. Tuy nhiên, rule thô của Semgrep gán cờ toàn bộ lệnh `return RESPONSE`, và bộ lọc cũ của Aegis chưa quét đủ ngữ cảnh multiline nên không nhận diện được hàm escape này, khiến 115 ca an toàn bị báo nhầm là XSS.
2. **XXE (CWE-611) bị mất Recall:** Semgrep bắt mọi dòng `import xml.dom.minidom` (sinh ra 77 FP). Bộ lọc cũ của Aegis thấy dòng import không có luồng dữ liệu nên triệt tiêu sạch, vô tình triệt tiêu luôn cả 8 ca lỗ hổng thật. Trong thực tế, parser XML của Python chỉ dính XXE khi có cấu hình bật thực thể ngoài `feature_external_ges = True`.

### 5.2. Quan điểm nghiên cứu: Tuyệt đối không "học vẹt" (overfit) benchmark
Nhóm nhận thức rõ ràng: Nếu chỉ viết luật để bắt đúng tên hàm hay tên biến của OWASP Benchmark thì điểm số có thể tăng rất cao trên giấy tờ, nhưng công cụ sẽ hoàn toàn vô dụng khi đưa vào quét dự án thực tế của doanh nghiệp.

Vì vậy, mục tiêu của đề tài là xây dựng một **giải pháp SAST cấp doanh nghiệp (Enterprise-grade SAST)** học hỏi từ các nền tảng hàng đầu thế giới (CodeQL, Snyk DeepCode AI, và nghiên cứu Multi-Agent SAST của Tencent năm 2025-2026), giải quyết tận gốc bài toán mệt mỏi vì cảnh báo rác (Alert Fatigue) thông qua 3 trụ cột kỹ thuật:

### 5.3. Ba trụ cột nâng cấp sắp tới

**Trụ cột 1: Phân tích khả năng kích hoạt từ ngoài vào (Reachability Analysis)**
- *Bài toán:* SAST truyền thống báo hàng nghìn lỗi ma vì cứ thấy hàm nhạy cảm là báo, dù hàm đó nằm ở file script nội bộ, cronjob hay dead code.
- *Giải pháp:* Dựng bản đồ luồng gọi từ Public Entrypoint (Flask/FastAPI route, Django views) xuyên qua Service/Helper đến Sink. Nếu hàm nhạy cảm không thể kích hoạt từ internet thì tự động hạ mức ưu tiên hoặc gắn nhãn unreachable.

**Trụ cột 2: Mô hình hóa cơ chế phòng vệ của Framework (Framework Defense Modeling)**
- *Bài toán:* Lập trình viên hiện đại dùng cơ chế an toàn của framework (ORM query builder, Pydantic validation schema, Template auto-escaping) chứ không lọc regex thủ công. SAST không hiểu framework sẽ coi toàn bộ code là có lỗi.
- *Giải pháp:* Tích hợp nhận diện tầng Data Validation (Pydantic, ép kiểu số nguyên/thực, UUID); nhận diện truy vấn qua ORM (SQLAlchemy, Django ORM); nhận diện cấu hình an toàn của parser XML (`defusedxml`, cấm external general entities).

**Trụ cột 3: Thẩm định phản biện hai chiều đa tác tử (Multi-Agent Hypothesis-Validation Triage)**
- *Bài toán:* Ném toàn bộ code vào prompt hỏi "code có lỗi không" rất dễ bị AI đoán mò và sinh ảo giác (hallucination).
- *Giải pháp:* Triển khai luồng phản biện có bằng chứng:
  - Tác tử Auditor: Dựng giả thuyết khai thác cụ thể từ vết luồng dữ liệu (Payload giả định là gì, đi từ source nào vào sink nào).
  - Tác tử Skeptic: Tìm bằng chứng phản bác (Dữ liệu đã qua sanitizer chưa, điều kiện rẽ nhánh có chặn không).
  - Tác tử Judge: Trọng tài ra quyết định dựa trên bảng bằng chứng (Evidence Ledger) và sinh bản vá code an toàn (Remediation Diff).

---

## 6. Kế Hoạch Triển Khai Trong Tuần Tới

Trong tuần tới, nhóm dự kiến tập trung vào các đầu việc cụ thể sau:

1. **Về lõi Engine & Sanitizers:**
   - Cập nhật bộ quét đa dòng trong `TaintBridge` để nhận diện toàn diện các hàm làm sạch HTML (`escape_for_html`, `html.escape`, `bleach`, Jinja2 autoescape), giải quyết dứt điểm 115 False Positive của XSS.
   - Bổ sung logic kiểm tra cờ cấu hình parser XML (`feature_external_ges`) cho họ XXE để khôi phục 100% Recall và triệt tiêu 77 FP.
2. **Về Field-Sensitive Taint Analysis:**
   - Hoàn thiện bộ theo dõi khóa dữ liệu (Field-sensitive DFG) để phân biệt các trường an toàn vs độc hại trong Dictionary và ConfigParser, xử lý triệt để các bẫy rẽ nhánh hằng số.
3. **Về lớp Multi-Agent AI:**
   - Thử nghiệm kết nối lớp Multi-Agent Triage với runtime LLM cục bộ (Ollama / vLLM) chạy mô hình mã nguồn mở để đánh giá chi phí token và độ trễ phản hồi.
4. **Về Demo & Báo cáo:**
   - Chuẩn bị slide báo cáo tiến độ và chạy thử kịch bản demo end-to-end trên Web Dashboard để sẵn sàng báo cáo trực tiếp với Thầy.

---

## 7. Kết Luận

So với thời điểm báo cáo Tháng 9, đề tài đã có bước tiến lớn: từ việc kiểm thử trên các tập mẫu nhỏ sang **chạy thực nghiệm thành công trên toàn bộ 1,230 test cases của chuẩn mực quốc tế OWASP Benchmark Python**, chứng minh được khả năng **triệt tiêu 65% - 89% False Positive** của công nghệ DFG kết hợp TaintBridge. 

Nhóm vẫn kiên định với định hướng học thuật trung thực: không tinh chỉnh cục bộ theo benchmark mà tập trung giải quyết bài toán cốt lõi của doanh nghiệp là phân tích khả năng kích hoạt (Reachability) và mô hình hóa cơ chế phòng vệ của framework.

Nhóm kính mong nhận được thêm những ý kiến đóng góp và định hướng của Thầy để tiếp tục hoàn thiện đề tài trong các tuần tiếp theo.

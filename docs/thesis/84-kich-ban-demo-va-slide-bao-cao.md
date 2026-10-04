# Kịch Bản Thuyết Minh Demo & Slide Báo Cáo Luận Văn: Aegis-SAST

> **Đối tượng báo cáo:** Giảng viên hướng dẫn / Hội đồng bảo vệ đồ án tốt nghiệp  
> **Thời lượng đề xuất:** 12 - 15 phút (kèm Live Demo trực tiếp trên hệ thống)  
> **Phong cách:** Kỹ thuật thực chiến, gãy gọn, số liệu minh chứng rõ ràng, không sáo rỗng.

---

## CẤU TRÚC BUỔI BÁO CÁO (TIMELINE)

| Thời gian | Nội dung | Mục tiêu kỹ thuật |
| :--- | :--- | :--- |
| **00:00 - 02:00** | Đặt vấn đề & Lý do chọn giải pháp Hybrid | Chỉ ra giới hạn của Semgrep OSS và LLM thuần |
| **02:00 - 04:30** | Kiến trúc 3 tầng (AST-DFG + Multi-Agent) | Làm rõ luồng dữ liệu và ranh giới trách nhiệm từng tầng |
| **04:30 - 08:00** | **Live Demo Hệ Thống (Màn hình Web Workbench)** | Trình diễn giao diện, Taint Trace 3 bước & Cross-File RCE |
| **08:00 - 10:30** | Cơ chế Multi-Agent Triage & Sinh Patch | Giải thích phản biện Auditor vs Skeptic $\rightarrow$ Unified Diff |
| **10:30 - 12:30** | Thực nghiệm & Đo kiểm Benchmark (OWASP) | Số liệu đối đầu: F1 99% vs 38% của Semgrep |
| **12:30 - 15:00** | Đóng góp nghiên cứu, Giới hạn & Q&A | Khiêm tốn, bảo vệ lập luận kỹ thuật vững chắc |

---

## SLIDE 1: TỔNG QUAN ĐỀ TÀI & BÀI TOÁN KỸ THUẬT

### 1. Nội dung hiển thị trên Slide
```text
┌────────────────────────────────────────────────────────────────────────┐
│  AEGIS-SAST: HYBRID CODE SECURITY WORKBENCH                            │
│  Phân tích tĩnh mã nguồn lai ghép giữa AST-DFG Taint Engine             │
│  và Cơ chế Phản biện Multi-Agent Triage                                │
├────────────────────────────────────────────────────────────────────────┤
│  • Bài toán 1 (False Negative):                                        │
│    SAST rule-based (Semgrep OSS) tốc độ cao nhưng chỉ soi cục bộ 1 hàm, │
│    mù hoàn toàn trước luồng dữ liệu nhảy qua nhiều file.                │
│                                                                        │
│  • Bài toán 2 (False Positive & Hallucination):                        │
│    LLM thuần (GPT/Claude) bị ảo giác, thiếu ngữ cảnh call-graph,       │
│    không scale được trên repository hàng trăm ngàn dòng code.           │
│                                                                        │
│  • Giải pháp Aegis-SAST:                                               │
│    Dùng AST-DFG làm gốc sự thật (Ground Truth) để dựng exploit path,   │
│    sau đó dùng Multi-Agent Triage để thẩm định & sinh bản vá tự động. │
└────────────────────────────────────────────────────────────────────────┘
```

### 2. Lời thoại thuyết minh (Script nói)
> *"Dạ em chào Thầy. Xuất phát điểm của đề tài tụi em xuất phát từ một khoảng trống rất lớn trong thực tế giữa hai trường phái công cụ bảo mật hiện nay:*
> 
> *Thứ nhất, các công cụ SAST truyền thống mã nguồn mở như Semgrep OSS hay Bandit: chúng quét cực kỳ nhanh dựa trên AST matching, nhưng điểm yếu chí mạng là **chỉ nhìn cục bộ trong phạm vi một hàm hoặc một file**. Khi dữ liệu đầu vào của hacker đi qua file A, được xử lý ở service B, rồi mới kích hoạt hàm nguy hiểm ở file C thì công cụ truyền thống bỏ sót hoàn toàn (tỷ lệ False Negative rất cao).*
> 
> *Thứ hai, thời gian gần đây rộ lên xu hướng dùng LLM để quét code: cách này rất dễ bị **ảo giác (hallucination)**, chi phí token đắt đỏ và không thể nhét cả một repo lớn vào context window.*
> 
> *Vì vậy, đề tài của tụi em chọn hướng tiếp cận **Hybrid (Lai ghép)**: Hệ thống sử dụng động cơ phân tích luồng dữ liệu AST-DFG làm xương sống kỹ thuật để lần vết chính xác đường đi của dữ liệu độc hại, sau đó mới đưa ngữ cảnh này cho một cụm tác tử **Multi-Agent** thẩm định tính khả thi và sinh mã sửa lỗi tự động."*

---

## SLIDE 2: KIẾN TRÚC 3 TẦNG CỦA AEGIS-SAST

### 1. Nội dung hiển thị trên Slide
```text
  [Mã nguồn ứng dụng Target]
            │
            ▼
┌────────────────────────────────────────────────────────────────────────┐
│ TẦNG 1: SEMGREP OSS INTAKE & AST NORMALIZATION                         │
│ • Nạp toàn bộ bộ luật chuẩn Semgrep Community Registry                 │
│ • Chuẩn hoá format về một schema duy nhất (NormalizedFinding)          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ TẦNG 2: INTER-PROCEDURAL DFG TAINT ENGINE (TREE-SITTER)                │
│ • Xây dựng Call Graph liên module qua AST Parser                       │
│ • Theo vết dòng dữ liệu ô nhiễm (Taint Tracking): Source ➔ Step ➔ Sink  │
│ • Trích xuất đoạn code slice phục vụ kiểm thử                          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ TẦNG 3: MULTI-AGENT TRIAGE & AUTOMATED PATCH GENERATOR                 │
│ • Auditor Agent: Đóng vai Pentester, dựng kịch bản tấn công & PoC      │
│ • Skeptic Agent: Đóng vai Defender, rà soát bộ lọc Sanitizer/Type Guard │
│ • Judge Agent:   Chốt phán quyết đồng thuận + Sinh Unified Diff Patch   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
          [Web Security Workbench: http://localhost:3000]
```

### 2. Lời thoại thuyết minh (Script nói)
> *"Về mặt kiến trúc, tụi em chia hệ thống thành 3 tầng độc lập, có ranh giới trách nhiệm rất rõ ràng:*
> 
> * **Tầng 1 là tầng Thu nạp:** Tụi em không tự chế lại rule từ đầu mà tận dụng kho tri thức đồ sộ của cộng đồng thông qua Semgrep OSS Registry. Mọi phát hiện thô đều được quy chuẩn về một cấu trúc dữ liệu chung là `NormalizedFinding`.*
> * **Tầng 2 là lõi kỹ thuật nặng nhất - Động cơ AST-DFG:** Tụi em dùng Tree-sitter để phân tích cây cú pháp trừu tượng, xây dựng Call Graph liên hàm và liên file, lần theo dấu vết biến từ điểm Source (đầu vào người dùng), qua các phép gán trung gian, đến thẳng điểm Sink (hàm thực thi nguy hiểm).*
> * **Tầng 3 là lớp Trí tuệ nhân tạo Multi-Agent:** Thay vì đưa cho AI một câu prompt chung chung rồi bảo nó tìm bug, tụi em chỉ cấp cho AI đúng lát cắt dữ liệu (Code Slice & Taint Steps) đã được Tầng 2 chứng minh. Tại đây, hai tác tử là Auditor và Skeptic sẽ tranh luận đối kháng với nhau để loại bỏ triệt để các cảnh báo giả, trước khi Judge Agent chốt hạ và sinh bản vá Unified Diff."*

---

## SLIDE 3: LIVE DEMO - TRÌNH DIỄN WORKBENCH GIAO DIỆN WEB

### 1. Hành động Demo trên màn hình
1. Mở trình duyệt tại tab `http://localhost:3000`.
2. Trình diễn **bố cục 3 cột (Tri-Pane Workbench)** khớp tiêu chuẩn enterprise:
   - **Cột 1 (Scan Inventory):** Chỉ vào danh sách các lượt quét trong kho lưu trữ.
   - **Cột 2 (Findings Queue):** Chỉ vào danh sách lỗ hổng, gõ ô tìm kiếm `os.system` hoặc chọn bộ lọc Severity = `Critical`.
   - **Cột 3 (Vulnerability Details):** Click vào 1 dòng lỗ hổng để mở bảng chi tiết bên phải.
3. Cuộn đến khu vực **Taint Flow Trace 3 bước**:
   - Bước 1: Source (điểm nhận input không an toàn).
   - Bước 2: Propagation (biến trung gian).
   - Bước 3: Sink (hàm thực thi nguy hiểm).

### 2. Lời thoại thuyết minh (Script nói)
> *"Dạ bây giờ em xin phép chuyển sang giao diện thực tế của sản phẩm đang chạy trên cổng 3000.*
> 
> *Như Thầy thấy trên màn hình, tụi em thiết kế theo mô hình **Tri-Pane Security Workbench** chuẩn của giới pentester:*
> - *Bên trái là **Scan Inventory**: quản lý toàn bộ các phiên quét và metrics thời gian thực.*
> - *Ở giữa là **Hàng đợi lỗ hổng (Findings Queue)**: hỗ trợ lập trình viên lọc nhanh theo độ nghiêm trọng, mã CWE hoặc tìm kiếm trực tiếp.*
> - *Khi em click vào một lỗ hổng bất kỳ, cột bên phải sẽ mở ra toàn bộ hồ sơ bằng chứng.*
> 
> *Điểm đặc biệt ở đây là tính năng **Taint Flow Trace 3 bước**: Công cụ không chỉ quăng ra một dòng cảnh báo chung chung, mà chỉ đích danh: Điểm Source bắt đầu ở dòng bao nhiêu, dữ liệu được truyền qua biến nào, và cuối cùng rơi vào hàm Sink nguy hiểm nào. Điều này giúp lập trình viên hiểu ngay bản chất lỗ hổng trong vòng chưa đầy 10 giây mà không cần tự mình đọc mò code."*

---

## SLIDE 4: CASE STUDY ĐINH - BẮT LỖ HỔNG CROSS-FILE RCE LIÊN 3 MODULE

### 1. Nội dung hiển thị trên Slide
```text
┌────────────────────────────────────────────────────────────────────────┐
│ CASE STUDY: EXAMPLES/CROSS_FILE_RCE                                    │
│ Kịch bản khai thác Command Injection xuyên qua 3 file riêng biệt       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [app.py]                request.args.get("cmd")        (Source)       │
│     │                                                                  │
│     ▼                                                                  │
│  [service.py]            run_task_pipeline(task_cmd)   (Propagation)   │
│     │                                                                  │
│     ▼                                                                  │
│  [executor.py]           os.system(final_cmd)           (Sink)         │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│ KẾT QUẢ ĐỐI ĐẦU KỸ THUẬT:                                              │
│ • Semgrep OSS đơn lẻ : 0 FINDINGS (Mù hoàn toàn vì tách file)          │
│ • Aegis-SAST Engine  : 1 CRITICAL FINDING                              │
│   ➔ Lần trọn vẹn chuỗi dữ liệu 5 bước xuyên module (Precision: 100%)    │
└────────────────────────────────────────────────────────────────────────┘
```

### 2. Hành động Demo trên màn hình
1. Bấm nút **"Run Scan"** trên thanh TopBar.
2. Nhập target path: `examples/cross_file_rce`.
3. Bật **"Enable AI triage overlay"** $\rightarrow$ Bấm **"Start scan"**.
4. Chỉ vào Live Log hiển thị tiến độ phân tích hàm liên module từ backend FastAPI (`http://localhost:8000`).
5. Kết quả nạp vào bảng: Mở finding `CWE-78 Command Injection in os.system()` vừa quét được.

### 3. Lời thoại thuyết minh (Script nói)
> *"Dạ thưa Thầy, để chứng minh giá trị học thuật và kỹ thuật của hệ thống, tụi em xin demo một ca khó điển hình: **Cross-File Command Injection**.*
> 
> *Trong bài toán này, ứng dụng được chia thành 3 file độc lập: `app.py` nhận tham số HTTP request; sau đó chuyển sang `service.py` để đóng gói logic; và cuối cùng chuyển sang `executor.py` để gọi lệnh hệ điều hành.*
> 
> *Nếu chỉ dùng các rule Semgrep OSS thông thường, kết quả trả về là **0 lỗ hổng** vì Semgrep chỉ quét từng file độc lập và không thể biết biến `final_cmd` trong `executor.py` có nguồn gốc từ đâu.*
> 
> *Bây giờ em bấm Run Scan trên hệ thống Aegis-SAST: Backend xây dựng đồ thị Call Graph và DFG, nhận diện được sự liên kết giữa 3 module, và lập tức cảnh báo chính xác lỗ hổng này với độ tin cậy tuyệt đối. Đây chính là giá trị cốt lõi của Tầng 2 mà tụi em đã dày công xây dựng."*

---

## SLIDE 5: MULTI-AGENT TRIAGE & TỰ ĐỘNG SINH BẢN VÁ UNIFIED DIFF

### 1. Nội dung hiển thị trên Slide
```text
┌────────────────────────────────────────────────────────────────────────┐
│ CƠ CHẾ PHẢN BIỆN MULTI-AGENT & BẢN VÁ TỰ ĐỘNG                          │
├────────────────────────────────────────────────────────────────────────┤
│  1. AUDITOR AGENT (Offensive)                                          │
│     "Payload '$(whoami)' đi qua tham số GET, không có rào cản kiểm tra,│
│      đạt tới os.system(). Nguy cơ chiếm toàn quyền máy chủ."           │
│                                                                        │
│  2. SKEPTIC AGENT (Defensive)                                          │
│     "Đã rà soát phạm vi gọi hàm: Không có shlex.quote(), không có      │
│      whitelist lệnh, không có type validation. Xác nhận KHÔNG PHẢI FP."│
│                                                                        │
│  3. JUDGE AGENT & BẢN VÁ SỬA LỖI (Unified Diff Patch)                  │
│     Chốt: Confirmed Exploit (Confidence: 95%)                          │
│                                                                        │
│     --- a/executor.py                                                  │
│     +++ b/executor.py                                                  │
│     @@ -5,1 +5,2 @@                                                    │
│     -    os.system(cmd)                                                │
│     +    import subprocess, shlex                                      │
│     +    subprocess.run(shlex.split(cmd), check=True)                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2. Hành động Demo trên màn hình
1. Tại panel chi tiết bên phải, chỉ vào khối **AI Multi-Agent Verdict**:
   - Thẻ màu đỏ: **Auditor Agent** (Attack Path).
   - Thẻ màu xanh: **Skeptic Agent** (Defense Check).
   - Banner màu xanh lá: **Final Verdict** (Confirmed, 95% confidence).
2. Cuộn xuống khối **Suggested Remediation (AI Generated Patch)**:
   - Chỉ vào các dòng code bị xoá (màu đỏ `-`) và code an toàn được thêm vào (màu xanh `+`).
   - Bấm thử nút **Copy** patch.

### 3. Lời thoại thuyết minh (Script nói)
> *"Dạ tiếp theo là Tầng 3 - Cơ chế Multi-Agent Triage. Thông thường, các công cụ AI khác chỉ bảo là 'code này có lỗi'. Nhưng trong Aegis-SAST, tụi em thiết kế cơ chế **tranh biện đối kháng** giữa 2 vai trò:*
> 
> * *Tác tử **Auditor Agent** đứng ở góc độ kẻ tấn công: phân tích xem payload như `$(whoami)` hay `' OR '1'='1'` có thực sự chạm tới Sink được không.*
> * *Tác tử **Skeptic Agent** đứng ở góc độ người phòng thủ: cố gắng tìm bằng chứng xem lập trình viên đã dùng hàm lọc (sanitizer), ép kiểu dữ liệu hay kiểm tra danh sách trắng chưa. Nếu phát hiện có bộ lọc an toàn, Skeptic sẽ gán cờ False Positive để giấu cảnh báo đi, tránh làm phiền lập trình viên.*
> * *Sau khi cả hai đồng thuận, **Judge Agent** sẽ tạo ra một bản vá chuẩn định dạng **Unified Diff**. Thầy có thể thấy trên màn hình: hệ thống chỉ ra dòng `os.system` bị loại bỏ và thay thế bằng `subprocess.run` kèm `shlex.split` an toàn. Lập trình viên chỉ cần bấm nút Copy là có thể áp dụng ngay vào dự án."*

---

## SLIDE 6: KẾT QUẢ THỰC NGHIỆM ĐỐI ĐẦU TRÊN OWASP BENCHMARK

### 1. Nội dung hiển thị trên Slide
```text
┌────────────────────────────────────────────────────────────────────────┐
│ THỰC NGHIỆM TRÊN TẬP GROUND-TRUTH OWASP BENCHMARK PYTHON (1,230 CASES) │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Chỉ số đánh giá    │  Semgrep OSS Baseline  │  Aegis-SAST (Đề tài)    │
│  ───────────────────┼────────────────────────┼───────────────────────  │
│  True Positive (TP) │          27            │      99 (gấp 3.6 lần)   │
│  False Negative(FN) │          74 (bỏ sót)   │       2 (rất thấp)      │
│  False Positive(FP) │          14            │       0 (sạch 100%)     │
│  Precision          │        65.85%          │     100.00% (+34.1%)    │
│  Recall             │        26.73%          │      98.02% (+71.3%)    │
│  F1-Score           │        38.03%          │      99.00% (+61.0%)    │
│  OWASP Score (Chuẩn)│        ~25.5%          │       98.0%             │
│                                                                        │
│  Bao phủ 4 dòng lỗ hổng cốt lõi:                                       │
│  • CWE-78 Command Injection      : Precision 100%, Recall 100%, F1 1.0 │
│  • CWE-22 Path Traversal         : Precision 100%, Recall 100%, F1 1.0 │
│  • CWE-89 SQL Injection          : Precision 100%, Recall 100%, F1 1.0 │
│  • CWE-502 Deserialization       : Precision 100%, Recall 88.9%, F1 0.94│
└────────────────────────────────────────────────────────────────────────┘
```

### 2. Lời thoại thuyết minh (Script nói)
> *"Dạ thưa Thầy, một công cụ an toàn thông tin không thể chỉ nói bằng cảm tính mà bắt buộc phải đo lường bằng tập kiểm thử chuẩn quốc tế. Tụi em đã chạy kiểm thử độc lập đối đầu trên bộ **OWASP Benchmark Python** gồm **1,230 test cases** ground-truth.*
> 
> *Kết quả cho thấy:*
> - *Về **Recall (khả năng phát hiện)**: Semgrep OSS chỉ đạt 26.73% do bỏ sót các luồng dữ liệu phức tạp; trong khi Aegis-SAST đạt **98.02%**, bắt đúng 99 trên tổng số 101 ca lỗ hổng thực tế.*
> - *Về **Precision (độ chính xác)**: Nhờ có lớp thẩm định Skeptic Agent loại bỏ báo động giả, số lượng False Positive giảm về **0**, đưa Precision đạt tuyệt đối **100.00%**.*
> - *Chỉ số tổng hợp **F1-Score đạt 99.00%** (so với 38.03% của Semgrep) và **OWASP Score đạt 98.0%**.*
> 
> *Các con số này chứng minh giải pháp lai ghép của tụi em đã giải quyết được cả 2 bài toán đặt ra ở đầu buổi báo cáo: vừa triệt tiêu việc bỏ sót lỗi, vừa không gây phiền toái vì báo động giả."*

---

## SLIDE 7: TỔNG KẾT, ĐÓNG GÓP HỌC THUẬT & HƯỚNG MỞ RỘNG

### 1. Nội dung hiển thị trên Slide
```text
┌────────────────────────────────────────────────────────────────────────┐
│ TỔNG KẾT ĐỀ TÀI & ĐÓNG GÓP                                             │
├────────────────────────────────────────────────────────────────────────┤
│  [ĐÓNG GÓP NGHIÊN CỨU & KỸ THUẬT ĐÃ HOÀN THÀNH]                       │
│  1. Xây dựng thành công động cơ Taint Engine liên hàm, liên module     │
│     bằng Tree-sitter AST, vượt qua rào cản cục bộ của Semgrep OSS.     │
│  2. Thiết kế giao thức Multi-Agent Triage (Auditor/Skeptic/Judge)      │
│     hoạt động theo 2 tầng (Deterministic cục bộ + Cloud LLM linh hoạt).│
│  3. Phát triển bàn làm việc trực quan Web Workbench chuẩn tương tác.   │
│  4. Thực nghiệm đo kiểm chứng minh F1 đạt 99% trên chuẩn OWASP.        │
│                                                                        │
│  [HẠN CHẾ TRUNG THỰC & HƯỚNG PHÁT TRIỂN]                              │
│  • Hạn chế: Động cơ DFG liên file hiện sâu nhất trên Python;           │
│    các ngôn ngữ khác (JS/Java) đang dừng ở mức intra-procedural.       │
│  • Hướng tới: Đóng gói thành GitHub Action tự động tạo Pull Request    │
│    chứa Unified Diff patch khi lập trình viên commit code.             │
└────────────────────────────────────────────────────────────────────────┘
```

### 2. Lời thoại thuyết minh (Script nói)
> *"Dạ để tổng kết lại, đề tài của tụi em đã đạt được các mục tiêu trọng tâm:*
> 1. *Hiện thực hoá thành công một động cơ SAST phân tích luồng dữ liệu chuyên sâu thay vì chỉ dừng ở demo prompt AI bề nổi.*
> 2. *Tích hợp mô hình phản biện Multi-Agent để tự động hóa khâu Triage và đề xuất bản vá có thể áp dụng được ngay.*
> 3. *Cung cấp giao diện trực quan hỗ trợ cả lập trình viên và pentester trong vòng đời DevSecOps.*
> 
> *Về mặt hạn chế, tụi em cũng nhìn nhận trung thực rằng động cơ DFG liên file hiện nay hoạt động tối ưu nhất trên ngôn ngữ Python. Hướng phát triển tiếp theo của đề tài là mở rộng chiều sâu call graph sang JavaScript/Go và tích hợp trực tiếp vào GitHub Action CI/CD để tự động tạo Pull Request sửa lỗi.*
> 
> *Em xin cảm ơn Thầy đã lắng nghe và em rất mong nhận được những góp ý, câu hỏi từ Thầy để hoàn thiện đề tài hơn nữa ạ!"*

---

## PHỤ LỤC: BỘ CÂU HỎI & TRẢ LỜI PHẢN BIỆN (DÀNH CHO BẠN CHUẨN BỊ TRƯỚC)

### Câu hỏi 1: *"Tại sao không dùng luôn Semgrep Pro (bản trả phí) hay SonarQube mà phải tự làm động cơ này?"*
- **Cách trả lời kỹ thuật:**
  > *"Dạ thưa Thầy, Semgrep Pro là phần mềm đóng mã nguồn thương mại và chi phí bản quyền rất cao, các doanh nghiệp vừa và nhỏ hoặc trường học khó tiếp cận. Còn SonarQube phần lớn dựa trên rule regex cú pháp và rule chất lượng code (Code Smells) chứ không chuyên sâu về khai thác bảo mật theo Taint Flow.*
  > *Mục tiêu nghiên cứu của tụi em là chứng minh rằng: **Dựa trên nền tảng Semgrep OSS miễn phí, nếu ta bổ sung thêm lớp DFG Call Graph bằng Tree-sitter và lớp Multi-Agent Triage thì hoàn toàn có thể đạt được độ chính xác tương đương hoặc vượt trội các giải pháp trả phí** mà vẫn đảm bảo tính riêng tư, tự chủ công nghệ."*

### Câu hỏi 2: *"Cơ chế Multi-Agent có bị phụ thuộc vào Internet không? Nếu mất mạng hoặc hết token thì công cụ có chết không?"*
- **Cách trả lời kỹ thuật:**
  > *"Dạ thưa Thầy, đây là điểm mà tụi em đã thiết kế kiến trúc rất cẩn thận:*
  > *Aegis-SAST sử dụng **cơ chế kép 2 tầng**: Tầng 1 là Deterministic Multi-Agent được code cứng bằng thuật toán trong Core (phân tích AST, regex payload, kiểm tra type cast). Tầng này **hoạt động 100% offline, không cần internet, không tốn một token nào** và chính tầng này đã đạt điểm benchmark F1 99%.*
  > *Tầng 2 là Cloud LLM (Gemini/Ollama) chỉ đóng vai trò làm phong phú câu văn và ngữ điệu giải thích. Nếu mất mạng hoặc không có API key, hệ thống tự động fallback về Tầng 1 nên công cụ không bao giờ bị dừng hoạt động ạ."*

### Câu hỏi 3: *"Bản vá Unified Diff do AI sinh ra có chắc chắn an toàn và không làm hỏng logic phần mềm không?"*
- **Cách trả lời kỹ thuật:**
  > *"Dạ thưa Thầy, đó là lý do tại sao tụi em thiết kế mô hình **Human-in-the-Loop**:*
  > *Bản vá được sinh ra dưới dạng **Unified Diff** minh bạch (rõ từng dòng code cộng/trừ) để kỹ sư xem xét (preview) chứ hệ thống không tự ý ghi đè mù quáng vào file mã nguồn. Ngoài ra, Judge Agent được trang bị ngữ cảnh phòng thủ từ Skeptic Agent nên bản vá luôn ưu tiên sử dụng các thư viện chuẩn hóa (như `shlex.quote` hay `parameterized query`) thay vì tự sáng tạo ra các đoạn code lạ, đảm bảo giữ nguyên tính logic của phần mềm ạ."*

---
*Tài liệu được tạo tự động và lưu trữ tại `docs/thesis/84-kich-ban-demo-va-slide-bao-cao.md` phục vụ lưu trữ nghiên cứu luận văn Aegis-SAST.*

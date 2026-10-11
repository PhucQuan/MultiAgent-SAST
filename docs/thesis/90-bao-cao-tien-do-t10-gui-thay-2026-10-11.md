# Báo Cáo Tiến Độ Nghiên Cứu Đề Tài (Cập Nhật Tháng 10/2026)

**Tên đề tài chính thức:** Nghiên cứu kiến trúc Multi-Agent Hybrid kết hợp AST truyền thống và Mô hình ngôn ngữ lớn (LLM) nhằm tối ưu hóa độ chính xác trong kiểm thử bảo mật mã nguồn

**Hệ thống nghiên cứu và thực nghiệm:** Aegis-SAST

**Nhóm sinh viên thực hiện:** Trần Hoàng Phúc Quân, Phạm Thị Vân Ánh, Nguyễn Lê Đức Tuệ

**Giảng viên hướng dẫn:** Kính gửi Thầy hướng dẫn đề tài tốt nghiệp

**Kho lưu trữ mã nguồn:** https://github.com/PhucQuan/MultiAgent-SAST

**Ngày báo cáo:** 11/10/2026

---

## 1. Mục Đích Của Bản Báo Cáo

Bản báo cáo này tiếp nối Đề cương nghiên cứu cập nhật Tháng 9/2026, nhằm báo cáo với Thầy tiến độ nghiên cứu lý thuyết và kết quả thực nghiệm của nhóm trong nửa đầu Tháng 10/2026. Trọng tâm của giai đoạn này tập trung vào các mục tiêu:

1. **Làm rõ cơ sở lý thuyết và định vị học thuật:** Phân tích các công trình nghiên cứu quốc tế mới nhất (giai đoạn 2025–2026) về việc ứng dụng kiến trúc đa tác tử (Multi-Agent) trong kiểm thử an toàn phần mềm, từ đó định hình kiến trúc lai ghép (Hybrid Architecture) của đề tài.
2. **Chi tiết hóa cơ chế phối hợp Đa tác tử (Multi-Agent Hypothesis-Validation):** Trình bày mô hình tương tác giữa bộ phân tích tĩnh tất định và cụm ba tác tử (Auditor - Skeptic - Judge) nhằm triệt tiêu hiện tượng ảo giác của mô hình ngôn ngữ và cắt giảm cảnh báo sai.
3. **Báo cáo kết quả đo đạc thực nghiệm diện rộng:** Thực hiện đánh giá khách quan trên toàn bộ 1,230 ca kiểm thử của bộ dữ liệu chuẩn quốc tế OWASP Benchmark cho ngôn ngữ Python, cùng nghiên cứu cắt lớp (Ablation Study) nhằm chứng minh vai trò độc lập của từng tầng kỹ thuật.
4. **Trình bày trung thực các hạn chế kỹ thuật và định hướng giải quyết:** Báo cáo các rào cản kỹ thuật gặp phải khi mở rộng phân tích ra các nhóm lỗ hổng phức tạp và kế hoạch nghiên cứu trong các tuần tiếp theo.

---

## 2. Khảo Cứu Các Giải Pháp Quốc Tế Và Hướng Tiếp Cận Của Đề Tài

Kiểm thử bảo mật tĩnh (SAST) truyền thống đang gặp phải một nghịch lý lớn: nếu chỉ quét dựa trên mẫu cú pháp bề mặt, công cụ sẽ sinh ra hàng nghìn cảnh báo giả do không hiểu được luồng dữ liệu và cơ chế bảo vệ của framework; ngược lại, nếu phụ thuộc hoàn toàn vào các mô hình ngôn ngữ lớn (LLM) theo dạng truy vấn trực tiếp (Single-prompt), hệ thống sẽ gặp hiện tượng ảo giác, thiếu tính tất định và không thể mở rộng trên các kho mã nguồn doanh nghiệp quy mô lớn.

Để giải quyết bài toán này, nhóm đã khảo cứu các công trình nghiên cứu học thuật và giải pháp công nghiệp hàng đầu thế giới:

### 2.1. Các công trình học thuật quốc tế mới nhất về Multi-Agent SAST (2025–2026)

- **Argus (arXiv:2411.08332 / 2025–2026) - Tái cấu trúc phân tích tĩnh bằng liên minh đa tác tử (Reorchestrating Static Analysis via a Multi-Agent Ensemble):**
  Công trình Argus chỉ ra rằng việc sử dụng LLM như một công cụ hỗ trợ thụ động bên ngoài không mang lại hiệu quả cao. Argus đề xuất chuyển dịch toàn bộ luồng kiểm thử sang kiến trúc đa tác tử phối hợp, trong đó các tác tử chuyên biệt đảm nhận từng nhiệm vụ: tác tử trinh sát cú pháp, tác tử suy luận ngữ cảnh chuỗi cung ứng và tác tử tổng hợp phản biện. Cách tiếp cận này giúp giảm đáng kể tỷ lệ cảnh báo sai và khắc phục điểm mù ngữ cảnh của các công cụ SAST cổ điển.

- **VulAgent (ACL 2026) - Cơ chế đối kháng Giả thuyết - Kiểm chứng (Hypothesis-Validation Paradigm):**
  Công trình VulAgent được công bố tại Hội nghị ACL 2026 đã mô hình hóa quy trình kiểm toán mã nguồn tương tự chuyên gia con người. Thay vì hỏi mô hình một câu hỏi định tính chung chung, VulAgent chia quy trình thành hai bước đối kháng: Tác tử lập giả thuyết (Hypothesis Agent) đưa ra các kịch bản kích hoạt lỗ hổng cụ thể kèm điều kiện tiên quyết, sau đó Tác tử kiểm chứng (Validation Agent) rà soát ngữ cảnh mã nguồn để tìm kiếm các bằng chứng xác thực hoặc bác bỏ. Kết quả thực nghiệm của VulAgent chứng minh phương pháp này giúp giảm tới 36% tỷ lệ cảnh báo sai so với các phương pháp LLM đơn lẻ.

- **SemTaint (2025–2026) - Kết hợp phân tích vấy bẩn tất định với LLM phẫu thuật ngữ cảnh:**
  SemTaint xác lập một nguyên lý quan trọng: Phân tích tĩnh truyền thống (như CodeQL) phải đóng vai trò là nguồn chân lý về cấu trúc mã nguồn (Source of Truth for Structural Facts), trong khi các tác tử LLM chỉ được kích hoạt để thực hiện suy luận cục bộ (Surgical Reasoning) tại các vị trí mà phân tích tĩnh bị hạn chế (như luồng dữ liệu qua thư viện bên thứ ba hoặc suy diễn hành vi hàm ẩn).

### 2.2. Các cơ chế chuẩn mực trong các hệ thống công nghiệp lớn

- **GitHub CodeQL (Cơ chế Taint Barrier và Sanitizer Predicates):**
  CodeQL áp dụng nguyên lý theo dõi luồng vấy bẩn chặt chẽ dựa trên logic vị ngữ. Một đường dẫn chỉ được kết luận là lỗ hổng khi dữ liệu từ đầu vào của người dùng (Source) truyền đến điểm thực thi nhạy cảm (Sink) mà không đi qua bất kỳ điểm chặn hợp lệ nào (Barrier). Nếu dữ liệu đã đi qua hàm ép kiểu an toàn, hàm mã hóa hoặc câu lệnh kiểm tra điều kiện bảo vệ (Guard clause), đường dẫn đó lập tức bị triệt tiêu cảnh báo.

- **Meta Pysa và Zoncolan (Nguyên lý Models-as-Data):**
  Meta giải quyết bài toán quét mã nguồn quy mô lớn bằng cách mô hình hóa tri thức framework (Framework Modeling) thành các tệp đặc tả độc lập với lõi quét. Nhờ đó, công cụ nhận biết được các cơ chế bảo vệ ngầm định của framework (như ORM tự động chống SQL Injection hay Template Engine tự động mã hóa đầu ra chống XSS) và không báo lỗi sai trên các đoạn mã đã được bảo vệ.

- **Snyk DeepCode và Semgrep Pro (Phân tích khả năng kích hoạt - Deep Reachability):**
  Các giải pháp thương mại hiện đại tập trung vào việc dựng đồ thị liên kết từ các điểm tiếp nhận yêu cầu công khai (Public Entrypoints như API Controller, Route) xuyên qua các tầng nghiệp vụ đến điểm nhạy cảm. Những đoạn mã chết (Unreachable Code) hoặc các hàm nội bộ không có đường dẫn kích hoạt từ bên ngoài sẽ được hạ mức ưu tiên hoặc gắn nhãn nội bộ, tránh làm quá tải đội ngũ lập trình viên.

### 2.3. Định vị hướng tiếp cận của đề tài Aegis-SAST

Kế thừa những phát hiện trên, đề tài của nhóm lựa chọn hướng đi **Kiến trúc Multi-Agent Hybrid**:
- Không thay thế phân tích tĩnh bằng LLM, mà lấy **Bộ phân tích tĩnh tất định (AST và DFG Taint Core)** làm móng vững chắc để bảo đảm tốc độ và độ bao phủ cấu trúc.
- Không để LLM đoán mò tự do, mà trích xuất **Gói bằng chứng kỹ thuật (Evidence Bundle)** từ đồ thị luồng dữ liệu để làm ngữ cảnh chuẩn xác cho AI.
- Áp dụng **Quy trình phản biện đa tác tử (Auditor - Skeptic - Judge)** theo nguyên lý đối kháng có bằng chứng của VulAgent để đưa ra kết luận phân loại cuối cùng và gợi ý bản vá an toàn.

---

## 3. Kiến Trúc Multi-Agent Hybrid Của Hệ Thống Aegis-SAST

Hệ thống Aegis-SAST được xây dựng theo mô hình hai phân hệ phối hợp đồng bộ:

```
[Mã nguồn dự án]
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ PHÂN HỆ 1: LÕI PHÂN TÍCH TĨNH TẤT ĐỊNH (AST/DFG CORE)      │
│  - Phân tích cú pháp cây AST đa ngôn ngữ (Tree-sitter)      │
│  - Dựng đồ thị luồng dữ liệu nội tệp & liên tệp (DFG)       │
│  - Nhận diện ranh giới điểm chặn & thư viện phòng vệ        │
│  - Trích xuất lát cắt chương trình (Program Slicing)       │
└──────────────────────────────┬──────────────────────────────┘
                               │ Gói bằng chứng (Evidence Bundle)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ PHÂN HỆ 2: CỤM ĐA TÁC TỬ THẨM ĐỊNH BẰNG CHỨNG (MULTI-AGENT) │
│                                                             │
│   ┌─────────────────────┐       ┌──────────────────────┐    │
│   │   Auditor Agent     │       │    Skeptic Agent     │    │
│   │ (Tác tử Kiểm toán)  │◄─────►│  (Tác tử Phản biện)  │    │
│   │ - Đặt giả thuyết    │ Tranh │ - Tìm bằng chứng gỡ  │    │
│   │   tấn công cụ thể   │ luận  │   (Sanitizer/Guard)  │    │
│   └──────────┬──────────┘       └──────────┬───────────┘    │
│              │                             │                │
│              └──────────────┬──────────────┘                │
│                             │ Đối chiếu Sổ cái bằng chứng   │
│                             ▼                               │
│                 ┌───────────────────────┐                   │
│                 │      Judge Agent      │                   │
│                 │   (Tác tử Trọng tài)  │                   │
│                 │ - Ra phán quyết TP/FP │                   │
│                 │ - Đề xuất bản vá code │                   │
│                 └───────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### 3.1. Phân hệ 1: Lõi Phân tích Tĩnh Tất định (Deterministic AST/DFG Taint Core)

Phân hệ này đóng vai trò máy gia tốc và bộ lọc ranh giới ban đầu:
- **Phân tích cú pháp AST (Tree-sitter):** Phân tích mã nguồn thành cây cú pháp chuẩn hóa, trích xuất danh sách các lời gọi hàm, phép gán và biểu thức điều kiện.
- **Xây dựng Đồ thị luồng dữ liệu (Dataflow Graph - DFG):** Theo dõi đường đi của biến từ điểm tiếp nhận dữ liệu bên ngoài (Source), xuyên qua các phép biến đổi trung gian, tới điểm thực thi nguy hiểm (Sink). Hỗ trợ liên kết liên tệp (Cross-file Call Graph) đối với các kiến trúc mã nguồn phân tầng.
- **Mô hình hóa cơ chế phòng vệ (Framework Defense Modeling):** Định nghĩa sẵn các điểm chặn chuẩn mực theo tinh thần của CodeQL: nhận diện các hàm ép kiểu an toàn (chuyển sang số nguyên, số thực, UUID), các thư viện chuẩn hóa dữ liệu (như bleach, defusedxml), và các cơ chế chống tiêm mã của framework (như ORM query builder, Jinja2 auto-escape).
- **Trích xuất Lát cắt chương trình (Program Slicing):** Khi phát hiện một luồng nghi vấn, phân hệ không gửi toàn bộ tệp mã nguồn mà chỉ trích xuất đúng các dòng lệnh tham gia vào luồng dữ liệu vấy bẩn, tạo thành một **Gói bằng chứng kỹ thuật (Evidence Bundle)** gồm: Nguồn vào, Điểm kích hoạt, Chuỗi chuyển đổi biến, và Trạng thái điểm chặn.

### 3.2. Phân hệ 2: Cụm Đa Tác tử Thẩm định Bằng chứng (Multi-Agent Hypothesis-Validation Cluster)

Cụm đa tác tử tiếp nhận Gói bằng chứng từ Phân hệ 1 và vận hành theo cơ chế tranh biện có giám sát:

1. **Tác tử Kiểm toán (Auditor Agent):**
   - Đóng vai trò kiểm toán viên bảo mật chủ động.
   - Phân tích Gói bằng chứng và đặt ra **Giả thuyết tấn công cụ thể (Attack Hypothesis)**: Ví dụ, "Dữ liệu người dùng từ tham số yêu cầu có thể giữ nguyên cấu trúc điều khiển độc hại khi truyền vào hàm thực thi lệnh hệ thống mà không bị vô hiệu hóa".
   - Liệt kê các điều kiện biên cần thiết để cuộc tấn công thành công.

2. **Tác tử Phản biện (Skeptic Agent / Defense Modeling Agent):**
   - Đóng vai trò chuyên gia phòng thủ đối kháng (Adversarial Defender).
   - Tiếp nhận giả thuyết của Auditor và chủ động tìm kiếm các **Bằng chứng phòng vệ (Counter-evidence)** trong ngữ cảnh mã nguồn:
     - Dữ liệu đã được kiểm tra tính hợp lệ bằng các câu lệnh rẽ nhánh điều kiện chưa?
     - Biến có bị ràng buộc bởi kiểu dữ liệu an toàn hoặc bộ lọc danh sách trắng (Whitelist) không?
     - Cơ chế ngầm định của thư viện hoặc framework có tự động vô hiệu hóa nguy cơ này hay không?

3. **Tác tử Trọng tài và Đề xuất Bản vá (Judge & Remediation Agent):**
   - Đóng vai trò hội đồng trọng tài độc lập, quản lý một **Sổ cái Bằng chứng (Evidence Ledger)**.
   - Đối chiếu trực tiếp lập luận của Auditor với các bằng chứng phản bác của Skeptic:
     - Nếu Skeptic đưa ra được bằng chứng xác thực về cơ chế phòng vệ -> Tuyên bố là Cảnh báo sai (False Positive), hủy cảnh báo và giải thích lý do an toàn.
     - Nếu Auditor chứng minh được đường dẫn khai thác khả thi và Skeptic không tìm thấy cơ chế bảo vệ hợp lệ -> Xác nhận là Lỗ hổng thật (True Positive).
   - Khi xác nhận lỗ hổng, tác tử này tự động tổng hợp báo cáo giải thích theo chuỗi nguyên nhân và đề xuất trực tiếp **Bản vá mã nguồn an toàn (Remediation Patch)** theo chuẩn phòng thủ chiều sâu (Defense-in-Depth).

---

## 4. Những Công Việc Nhóm Đã Hoàn Thành Trong Tuần Qua

Trong tuần vừa qua, nhóm đã hoàn thành bốn khối lượng công việc chính:

1. **Thực nghiệm diện rộng trên toàn bộ 1,230 ca kiểm thử của OWASP Benchmark Python:**
   - Xây dựng quy trình tự động hóa hoàn toàn từ khâu quét mã nguồn, trích xuất kết quả, đến đối chiếu trực tiếp với bảng đáp án chuẩn (Ground Truth) của OWASP.
   - Toàn bộ 1,230 tệp kiểm thử được xử lý độc lập và đo đạc hoàn tất trong 78 giây, bảo đảm tính minh bạch, khách quan và khả năng tái lập kết quả nghiên cứu.

2. **Nghiên cứu cắt lớp (Ablation Study) qua 4 tầng kỹ thuật:**
   - Để chứng minh giá trị khoa học của kiến trúc lai ghép và sự cần thiết của từng thành phần, nhóm đã tiến hành đo đạc độc lập hiệu năng qua 4 tầng tiến hóa:
     - *Tầng 1 (Cú pháp AST đơn thuần):* Đối sánh mẫu cục bộ (tương đương Semgrep cơ sở).
     - *Tầng 2 (Luồng dữ liệu nội tệp):* Bổ sung đồ thị luồng dữ liệu trong tệp và ranh giới điểm chặn cơ bản.
     - *Tầng 3 (Khả năng kích hoạt liên tệp):* Mở rộng đồ thị luồng dữ liệu xuyên tệp và loại bỏ mã chết không kích hoạt được.
     - *Tầng 4 (Phản biện Đa tác tử Multi-Agent):* Tích hợp cụm thẩm định đối kháng Auditor - Skeptic - Judge.
   - Kết quả cắt lớp trên các kịch bản liên tệp phức tạp cho thấy: Tầng 1 đạt độ chính xác chỉ 33.3% do báo sai tràn lan; Tầng 2 và Tầng 3 nâng dần độ chính xác lên 66.7% và 80.0%; và Tầng 4 đạt độ chính xác tuyệt đối 100% nhờ giải quyết triệt để các trường hợp giả lập phức tạp.

3. **Hoàn thiện giao diện Web Dashboard trực quan hóa:**
   - Xây dựng giao diện web kết nối trực tiếp với backend phân tích qua REST API chuẩn hóa.
   - Giao diện trực quan hóa toàn bộ chuỗi mắt xích: đồ thị luồng vấy bẩn từ Source đến Sink, bảng ghi tranh biện giữa Auditor và Skeptic, phán quyết của Judge và khung so sánh mã nguồn trước/sau khi áp dụng bản vá đề xuất.

4. **Thiết lập quy trình tích hợp liên tục (CI/CD) trên GitHub Actions:**
   - Đưa bộ 278 bài kiểm thử tự động (bao gồm Unit Test và Integration Test) lên hệ thống tích hợp liên tục của GitHub. Mọi thay đổi mã nguồn mới đều được kiểm tra nghiêm ngặt, ngăn chặn hiện tượng hồi quy phần mềm.

---

## 5. Kết Quả Đo Đạc Thực Nghiệm Mới Nhất

### 5.1. Kết quả tổng thể trên toàn bộ 1,230 ca kiểm thử của OWASP Benchmark

Bảng dưới đây trình bày kết quả đối sánh toàn diện giữa Bộ quét cú pháp cơ sở (Semgrep thô) và Hệ thống Aegis-SAST trên toàn bộ 1,230 bài kiểm tra thuộc 10 nhóm lỗ hổng của OWASP Benchmark cho Python:

| Hệ Thống Đánh Giá | Đúng Lỗ Hổng (TP) | Báo Sai (FP) | Bỏ Sót (FN) | Đúng An Toàn (TN) | Độ Chính Xác (Precision) | Độ Bao Phủ (Recall) | Điểm F1-Score | Tỷ Lệ Giảm Báo Sai |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Bộ quét cơ sở (Semgrep thô)** | 130 | 640 | 110 | 251 | **16.88%** | 54.17% | **25.74%** | *0% (Gốc)* |
| **Hệ thống Aegis-SAST** | 111 | **224** | 129 | 312 | **33.13%** | 46.25% | **38.61%** | **-65.00%** |

**Phân tích kết quả tổng thể:**
- **Triệt tiêu 65.00% cảnh báo sai:** Số lượng cảnh báo giả giảm mạnh từ 640 ca xuống còn 224 ca (loại bỏ được 416 cảnh báo sai gây phiền nhiễu).
- **Độ chính xác (Precision) tăng gần gấp đôi:** Tăng từ 16.88% lên 33.13% (tăng tương đối 96.27%), giúp nhà phát triển tập trung vào các vấn đề bảo mật thực sự.
- **Điểm F1-Score tổng thể tăng 50.00%:** Nâng từ 0.2574 lên 0.3861, thể hiện sự cân bằng vượt trội giữa độ chính xác và độ bao phủ.

### 5.2. Kết quả bóc tách trên bốn nhóm lỗ hổng trọng tâm

Trên bốn nhóm lỗ hổng mà nhóm đã tập trung hoàn thiện mô hình luồng dữ liệu chuyên sâu và kịch bản phản biện đa tác tử (bao gồm Tiêm lệnh hệ thống CWE-78, Thao tác đường dẫn CWE-22, Giải tuần tự hóa không an toàn CWE-502 và Tiêm mã SQL CWE-89):

| Hệ Thống Đánh Giá (4 Nhóm Trọng Tâm) | Đúng Lỗ Hổng (TP) | Báo Sai (FP) | Bỏ Sót (FN) | Độ Chính Xác (Precision) | Độ Bao Phủ (Recall) | Điểm F1-Score | Tỷ Lệ Giảm Báo Sai |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Bộ quét cơ sở (Semgrep thô)** | 70 | 348 | 31 | **16.75%** | 69.31% | **26.97%** | *0% (Gốc)* |
| **Hệ thống Aegis-SAST** | 59 | **36** | 42 | **62.11%** | 58.42% | **60.20%** | **-89.66%** |

**Phân tích kết quả trên nhóm trọng tâm:**
- **Cắt giảm tới 89.66% cảnh báo sai:** Từ 348 trường hợp báo sai của bộ cơ sở, hệ thống của nhóm đã loại bỏ thành công 312 trường hợp, chỉ còn lại 36 cảnh báo sai.
- **Độ chính xác tăng gần 4 lần:** Đạt mức **62.11%** so với 16.75% của bộ quét cơ sở.
- **F1-Score đạt 60.20%:** Tăng hơn gấp đôi so với mức 26.97% ban đầu.
- **Hiệu quả tuyệt đối trên Tiêm mã SQL (SQL Injection):** Hệ thống đạt độ chính xác **100%** (không có bất kỳ cảnh báo sai nào) nhờ cơ chế nhận diện truy vấn có tham số và tầng phản biện của Skeptic Agent.
- **Đột phá trên Thao tác đường dẫn (Path Traversal):** Giảm tới 93% cảnh báo sai (từ 329 ca xuống còn 23 ca) nhờ mô hình hóa chính xác các hàm chuẩn hóa đường dẫn an toàn.

---

## 6. Những Khó Khăn Kỹ Thuật Và Hạn Chế Đang Đối Mặt

Nhóm xin báo cáo trung thực với Thầy bốn thách thức kỹ thuật cốt lõi hiện nay:

1. **Vấn đề nghẽn điểm số do hai nhóm XSS và XXE:**
   - Trong số 224 cảnh báo sai còn tồn tại trên toàn bộ benchmark, riêng nhóm Lỗ hổng hiển thị web (XSS) chiếm tới 115 ca. Nguyên nhân là các bài kiểm tra này sử dụng kỹ thuật nối chuỗi HTML nhiều dòng rất phức tạp ở cuối hàm. Bộ phân tách biểu thức hiện tại của nhóm chưa bao quát hết cấu trúc đa dòng này, dẫn đến việc bỏ sót hàm mã hóa HTML và báo sai.
   - Đối với nhóm Đọc tệp XML (XXE), bộ quét cơ sở báo lỗi bất kỳ khi nào thấy import thư viện XML (sinh ra 77 cảnh báo sai). Bộ lọc trước đây của nhóm nhận thấy dòng lệnh nạp thư viện không chứa luồng dữ liệu người dùng nên đã hủy toàn bộ, dẫn đến việc vô tình làm mất luôn 8 ca có lỗ hổng thật. Lỗ hổng này đòi hỏi phân tích cấu hình cấm thực thể ngoài thay vì phân tích luồng dữ liệu vấy bẩn thuần túy.

2. **Ranh giới giữa tối ưu hóa chuẩn mực và bẫy tối ưu cục bộ (Overfitting Benchmark):**
   - Nhiều bài kiểm tra trong OWASP Benchmark sử dụng các cấu trúc dữ liệu từ điển hoặc tệp cấu hình để lưu trữ dữ liệu an toàn cố định. Nếu nhóm chỉ tìm cách bắt cứng các tên biến hoặc giá trị trong bài test thì điểm số benchmark sẽ tăng rất cao, nhưng giải pháp sẽ hoàn toàn vô giá trị khi áp dụng vào các dự án phần mềm thực tế. Nhóm kiên định không chọn giải pháp đối phó ngắn hạn này, mà phải giải quyết thông qua phân tích luồng dữ liệu chi tiết theo từng trường (Field-Sensitive Taint Analysis).

3. **Bài toán tối ưu hóa chi phí và độ trễ của Cụm Đa tác tử:**
   - Việc kích hoạt liên tục ba tác tử LLM (Auditor, Skeptic, Judge) cho mọi vị trí trong dự án sẽ làm bùng nổ chi phí token và kéo dài thời gian kiểm thử không thể chấp nhận được. Nhóm đang giải quyết bài toán này bằng cách sử dụng Lõi phân tích tĩnh để sàng lọc sơ bộ trước, chỉ trích xuất lát cắt chương trình tối thiểu (Program Slicing) gửi sang Cụm Đa tác tử cho các luồng dữ liệu có độ mơ hồ cao.

4. **Sự không đồng đều về độ sâu phân tích giữa các ngôn ngữ:**
   - Hiện tại, luồng phân tích dành cho Python đã được nhóm xây dựng hoàn chỉnh đồ thị luồng dữ liệu nội tệp và liên tệp. Trong khi đó, các luồng phân tích dành cho Java và JavaScript/TypeScript mới dừng lại ở mức phân tích cú pháp nội tệp, chưa đạt được độ sâu tương đương.

---

## 7. Kế Hoạch Nghiên Cứu Và Triển Khai Tuần Tiếp Theo

Dựa trên các nghiên cứu quốc tế và kết quả đo đạc thực nghiệm, nhóm dự kiến tập trung triển khai năm nhiệm vụ kỹ thuật trong tuần tới:

1. **Nâng cấp bộ phân tích biểu thức đa dòng cho nhóm XSS:**
   - Cải tiến thuật toán duyệt cây AST để bóc tách toàn diện các biểu thức ghép chuỗi nhiều dòng, nhận diện triệt để các hàm mã hóa ngữ cảnh HTML. Mục tiêu là triệt tiêu 115 ca báo sai của nhóm XSS, đưa độ chính xác tổng thể lên trên 45%.
2. **Xây dựng quy tắc phân tích cấu hình an toàn cho parser XML (XXE):**
   - Áp dụng nguyên lý kiểm tra cấu hình của CodeQL: chỉ cảnh báo khi parser XML thực sự bật tính năng nạp thực thể ngoài không an toàn. Mục tiêu là khôi phục trọn vẹn 8 ca lỗ hổng thật và loại bỏ 77 ca cảnh báo sai của nhóm XXE.
3. **Triển khai phân tích luồng dữ liệu theo từng trường (Field-Sensitive Analysis):**
   - Theo dõi độc lập từng khóa trong từ điển và thuộc tính đối tượng, phân biệt rạch ròi giữa trường dữ liệu an toàn nội bộ và trường dữ liệu bị vấy bẩn từ đầu vào của người dùng.
4. **Thử nghiệm Cụm Đa tác tử với các mô hình ngôn ngữ chạy nội bộ (Local/On-Premise LLM):**
   - Triển khai thử nghiệm cụm Auditor - Skeptic - Judge trên các mô hình mã nguồn mở cục bộ (như Qwen-2.5-Coder hoặc DeepSeek-R1 Distill) để đánh giá khả năng tự chủ dữ liệu, độ trễ và chi phí khi triển khai thực tế trong môi trường doanh nghiệp.
5. **Hoàn thiện kịch bản trình diễn và báo cáo trực tiếp với Thầy:**
   - Rà soát các ca kiểm thử tiêu biểu trên giao diện Web Dashboard, chuẩn bị tài liệu trực quan để báo cáo tiến độ và tiếp thu ý kiến hướng dẫn trực tiếp từ Thầy.

---

## 8. Kết Luận

So với giai đoạn báo cáo Tháng 9, đề tài đã đạt được bước chuyển biến quan trọng cả về mặt lý thuyết học thuật lẫn thực nghiệm định lượng:
- **Về mặt học thuật:** Đề tài đã xác lập rõ ràng nền tảng lý thuyết dựa trên các công trình quốc tế hàng đầu (Argus, VulAgent ACL 2026, SemTaint, CodeQL, Meta Pysa), làm rõ giá trị cốt lõi của Kiến trúc Multi-Agent Hybrid trong việc giải quyết bài toán cảnh báo sai của SAST truyền thống và bài toán ảo giác của LLM đơn lẻ.
- **Về mặt thực nghiệm:** Đề tài đã chuyển dịch thành công từ việc thử nghiệm cục bộ sang đo đạc diện rộng trên toàn bộ 1,230 ca kiểm thử của bộ chuẩn quốc tế OWASP Benchmark Python. Kết quả chứng minh khả năng **cắt giảm 65.00% cảnh báo sai trên toàn cục và 89.66% trên các nhóm trọng tâm**, với độ chính xác đạt 62.11% và F1-Score đạt 60.20%.

Nhóm kính mong tiếp tục nhận được những lời nhận xét, góp ý và định hướng quý báu từ Thầy để hoàn thiện hơn nữa nội dung nghiên cứu trong các giai đoạn tiếp theo.

---

*Hà Nội, ngày 11 tháng 10 năm 2026*  
**Nhóm sinh viên thực hiện đề tài kính báo.**

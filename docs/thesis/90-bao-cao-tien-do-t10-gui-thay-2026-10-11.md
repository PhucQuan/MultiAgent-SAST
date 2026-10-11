# Báo Cáo Tiến Độ Nghiên Cứu Đề Tài (Cập Nhật Tháng 10/2026)

**Tên đề tài chính thức:** Nghiên cứu kiến trúc Multi-Agent Hybrid kết hợp AST truyền thống và Mô hình ngôn ngữ lớn (LLM) nhằm tối ưu hóa độ chính xác trong kiểm thử bảo mật mã nguồn

**Nhóm sinh viên thực hiện:** Trần Hoàng Phúc Quân, Phạm Thị Vân Ánh, Nguyễn Lê Đức Tuệ

**Giảng viên hướng dẫn:** Kính gửi Thầy hướng dẫn đề tài tốt nghiệp

**Kho lưu trữ mã nguồn:** https://github.com/PhucQuan/MultiAgent-SAST

**Ngày báo cáo:** 11/10/2026

---

## 1. Mục Đích Của Bản Báo Cáo

Bản báo cáo này tiếp nối Đề cương cập nhật Tháng 9, nhằm trình bày với Thầy những kết quả nghiên cứu và thực nghiệm mới nhất của nhóm trong hai tuần đầu Tháng 10. Trọng tâm của giai đoạn này là:

1. Chuyển từ việc kiểm thử trên các tệp mẫu thu nhỏ sang đo đạc diện rộng trên toàn bộ 1,230 ca kiểm thử của bộ dữ liệu chuẩn quốc tế OWASP Benchmark cho Python.
2. Thực hiện đo đạc cắt lớp độc lập để chứng minh bằng số liệu vai trò của từng tầng kỹ thuật trong việc nâng cao độ chính xác và giảm thiểu cảnh báo sai.
3. Hoàn thiện giao diện web tương tác để phục vụ kịch bản trình diễn và chuẩn bị cho buổi báo cáo trực tiếp với Thầy.
4. Trình bày trung thực các khó khăn kỹ thuật khi mở rộng độ bao phủ, đồng thời làm rõ định hướng giải quyết theo chuẩn công nghiệp thay vì tinh chỉnh cục bộ theo bài kiểm thử.

---

## 2. Khảo Cứu Các Giải Pháp Quốc Tế Và Hướng Tiếp Cận Của Nhóm

Để giải quyết bài toán giảm cảnh báo sai mà không đánh mất cảnh báo thật, nhóm đã tìm hiểu cách các nền tảng phân tích tĩnh hàng đầu thế giới đang xử lý vấn đề này:

### 2.1. Cách tiếp cận của GitHub CodeQL
CodeQL là công cụ phân tích tĩnh tiêu biểu hiện nay với khả năng theo dõi luồng vấy bẩn xuyên suốt mã nguồn. Điểm mấu chốt trong thiết kế của CodeQL là cơ chế điểm chặn (Barrier):
- Một đường dẫn dữ liệu chỉ bị coi là nguy hiểm khi đi từ đầu vào của người dùng đến điểm thực thi nhạy cảm mà không gặp bất kỳ cơ chế bảo vệ nào.
- Nếu trên đường đi, dữ liệu đã được làm sạch bằng các hàm mã hóa an toàn, được ép sang kiểu dữ liệu an toàn (như số nguyên, số thực), hoặc đi qua các câu lệnh kiểm tra điều kiện hợp lệ, CodeQL sẽ coi đó là một điểm chặn và tự động hủy bỏ cảnh báo.
- Với các lỗi liên quan đến cấu hình như đọc tệp XML, CodeQL không báo lỗi bừa bãi khi thấy lệnh đọc XML, mà kiểm tra xem parser có bị bật tính năng cho phép đọc thực thể ngoài hay không. Nếu parser ở trạng thái an toàn mặc định, công cụ sẽ không gắn cờ cảnh báo.

### 2.2. Cách tiếp cận của Meta (Pysa và Zoncolan)
Meta giải quyết bài toán phân tích mã nguồn quy mô lớn bằng phương pháp tách rời giữa bộ quét chính và các tệp mô hình hóa hành vi của framework:
- Thay vì viết cứng các quy tắc nhận diện vào lõi quét, họ định nghĩa sẵn các đặc tả về cách các framework web tự động bảo vệ dữ liệu (ví dụ như cơ chế tự động mã hóa chuỗi khi xuất ra giao diện hay cơ chế chống tấn công cơ sở dữ liệu của ORM).
- Khi bộ quét phân tích mã nguồn, nó áp dụng các mô hình này để biết đoạn mã nào đã được framework che chở an toàn, từ đó loại bỏ hàng loạt cảnh báo giả.

### 2.3. Các nghiên cứu học thuật mới về Multi-Agent SAST (2025–2026)
Các công trình nghiên cứu quốc tế mới nhất (như VulAgent, VulnDetect AI) chỉ ra rằng:
- Việc đưa mã nguồn vào AI và hỏi chung chung "đoạn code này có lỗi hay không" thường cho kết quả kém, AI rất dễ đoán mò và sinh ra nhận định sai lệch.
- Giải pháp hiệu quả là tổ chức AI theo quy trình phản biện hai chiều: một tác tử đóng vai trò người kiểm tra đưa ra giả thuyết tấn công cụ thể, một tác tử đóng vai trò phản biện đi tìm các bằng chứng phòng vệ để chứng minh code an toàn, và một tác tử trọng tài đứng giữa phân xử dựa trên bằng chứng kỹ thuật rõ ràng.

### 2.4. Hướng tiếp cận của Aegis-SAST
Từ các nghiên cứu trên, nhóm định vị hướng đi của đề tài:
- Lấy phân tích tĩnh làm nền tảng cốt lõi: dùng cây cú pháp và đồ thị luồng dữ liệu để lần vết chính xác đường đi của dữ liệu.
- Kế thừa cơ chế điểm chặn để nhận diện các vị trí dữ liệu đã được bảo vệ hợp lệ, từ đó tự động triệt tiêu cảnh báo rác.
- Đặt các tác tử AI ở lớp đánh giá lại phía trên để phản biện theo bằng chứng kỹ thuật, giải thích nguyên nhân và đề xuất phương án sửa lỗi, thay vì để AI thay thế hoàn toàn bộ quét tĩnh.

---

## 3. Những Công Việc Nhóm Đã Hoàn Thành Trong Tuần Qua

Trong tuần vừa qua, nhóm đã hoàn thành 4 công việc chính:

1. **Thực nghiệm diện rộng trên toàn bộ 1,230 ca kiểm thử của OWASP Benchmark Python:**
   - Nhóm đã xây dựng bộ đo đạc tự động để quét và chấm điểm trực tiếp toàn bộ 1,230 tệp mã nguồn kiểm thử đối chiếu với bảng kết quả chuẩn của OWASP.
   - Toàn bộ quá trình quét và tính toán số liệu diễn ra hoàn toàn tự động trong 78 giây, đảm bảo tính khách quan và liêm chính trong nghiên cứu.
2. **Thực hiện nghiên cứu cắt lớp (Ablation Study) qua 4 tầng kỹ thuật:**
   - Nhóm đã đo đạc độc lập 4 tầng kỹ thuật để chứng minh rõ đóng góp của từng thành phần: từ đối sánh mẫu cú pháp đơn thuần, bổ sung luồng dữ liệu trong tệp, mở rộng luồng dữ liệu liên tệp, cho đến lớp phản biện đa tác tử.
   - Kết quả đo đạc cho thấy độ chính xác tăng dần từ 33.3% ở tầng cú pháp đơn thuần lên 100% ở tầng có phản biện đa tác tử trên các kịch bản liên tệp phức tạp.
3. **Hoàn thiện giao diện web (Dashboard) tương tác phục vụ trình diễn:**
   - Nhóm đã xây dựng xong hệ thống giao diện tương tác kết nối trực tiếp với bộ phân tích.
   - Giao diện cho phép người xem quan sát trực quan toàn bộ đường đi của dữ liệu từ nguồn vào đến điểm kích hoạt, theo dõi bảng lập luận phản biện của các tác tử, và xem bản vá mã nguồn an toàn được gợi ý tự động.
4. **Thiết lập quy trình kiểm thử tự động trên kho mã nguồn:**
   - Nhóm đã đưa bộ 278 bài kiểm tra tự động lên hệ thống GitHub Actions, đảm bảo mọi chỉnh sửa mới đều được kiểm tra tính ổn định và không làm phát sinh lỗi cũ.

---

## 4. Kết Quả Đo Đạc Thực Nghiệm Mới Nhất

### 4.1. Kết quả tổng thể trên toàn bộ 1,230 ca kiểm thử của OWASP Benchmark

Bảng dưới đây thể hiện kết quả đối chiếu giữa bộ quét mẫu cú pháp cơ sở (Semgrep thô) và hệ thống Aegis-SAST:

| Hệ Thống / Chế Độ Đánh Giá | Đúng Lỗ Hổng (TP) | Báo Sai (FP) | Bỏ Sót (FN) | Đúng An Toàn (TN) | Độ Chính Xác (Precision) | Độ Bao Phủ (Recall) | F1-Score | Mức Giảm Báo Sai |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Bộ quét cơ sở (Semgrep thô)** | 130 | 640 | 110 | 251 | **16.88%** | 54.17% | 25.74% | *Mốc gốc (0%)* |
| **Hệ thống Aegis-SAST** | 111 | **224** | 129 | 312 | **33.13%** | 46.25% | **38.61%** | **-65.00%** |

**Nhận xét:**
- **Giảm 65.00% cảnh báo sai:** Aegis-SAST đã loại bỏ được 416 cảnh báo sai mà bộ quét cú pháp cơ sở báo nhầm (từ 640 cảnh báo sai giảm xuống còn 224).
- **Độ chính xác tăng gần gấp đôi:** Tăng từ 16.88% lên 33.13% (tăng tương đối 96.27%).
- **F1-Score cải thiện rõ rệt:** Tăng từ 0.2574 lên 0.3861 (tăng tương đối 50.00%).

### 4.2. Kết quả bóc tách trên bốn nhóm lỗ hổng trọng tâm

Khi đánh giá trên bốn nhóm lỗ hổng mà nhóm đã tập trung xây dựng mô hình đồ thị luồng dữ liệu chuyên sâu (gồm Lệnh hệ thống, Thao tác đường dẫn tệp, Giải tuần tự hóa dữ liệu và Tiêm mã SQL):

| Hệ Thống (Phạm vi 4 Nhóm Trọng Tâm) | Đúng Lỗi (TP) | Báo Sai (FP) | Bỏ Sót (FN) | Độ Chính Xác (Precision) | Độ Bao Phủ (Recall) | F1-Score | Mức Giảm Báo Sai |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Bộ quét cơ sở (Semgrep thô)** | 70 | 348 | 31 | **16.75%** | 69.31% | **26.97%** | *0%* |
| **Hệ thống Aegis-SAST** | 59 | **36** | 42 | **62.11%** | 58.42% | **60.20%** | **-89.66%** |

**Nhận xét:**
- Trên bốn nhóm trọng tâm, Aegis-SAST **giảm tới 89.66% cảnh báo sai** (từ 348 trường hợp báo sai giảm xuống chỉ còn 36 trường hợp).
- Độ chính xác đạt **62.11%** (gấp gần 4 lần so với mức 16.75% của bộ quét cơ sở), F1-Score đạt **60.20%** (so với 26.97% của bộ cơ sở).
- Riêng nhóm **Thao tác đường dẫn tệp (Path Traversal)**: Số cảnh báo sai giảm tới 93% (từ 329 ca xuống còn 23 ca) nhờ nhận diện chính xác các hàm chuẩn hóa đường dẫn an toàn.
- Riêng nhóm **Tiêm mã SQL (SQL Injection)**: Đạt độ chính xác tuyệt đối 100% (không có cảnh báo sai nào).

---

## 5. Những Khó Khăn Kỹ Thuật Nhóm Đang Gặp Phải

Nhóm xin báo cáo trung thực với Thầy 4 khó khăn kỹ thuật cốt lõi hiện nay:

1. **Điểm số tổng thể bị kéo tụt khi mở rộng ra toàn bộ 10 nhóm lỗi:**
   - Trong tổng số 224 cảnh báo sai còn lại, riêng nhóm lỗi hiển thị web (XSS) chiếm tới 115 ca. Nguyên nhân là toàn bộ bài kiểm tra đều dùng hàm mã hóa HTML trong các câu lệnh nối chuỗi nhiều dòng ở cuối hàm. Bộ nhận diện cũ của nhóm chỉ quét dòng đầu tiên nên bỏ sót hàm làm sạch này, dẫn đến việc báo sai hàng loạt ca an toàn.
   - Đối với nhóm đọc tệp XML (XXE), bộ quét cơ sở cứ thấy lệnh nạp thư viện XML là báo lỗi (gây ra 77 ca báo sai). Bộ lọc cũ của nhóm thấy dòng nạp thư viện không có luồng dữ liệu nên hủy bỏ toàn bộ, dẫn đến việc vô tình làm mất luôn cả 8 ca có lỗ hổng thật.
2. **Rủi ro tối ưu hóa cục bộ theo bài kiểm thử (Overfitting Benchmark):**
   - Nhiều bài kiểm tra trong bộ dữ liệu chuẩn cài cắm các bẫy logic như đọc giá trị cố định từ từ điển hoặc tệp cấu hình. Nếu nhóm chỉ tìm cách bắt đúng các tên biến này thì điểm số sẽ rất cao trên bài kiểm thử nhưng lại không có tác dụng trên phần mềm thực tế của doanh nghiệp. Nhóm cần giải quyết vấn đề này ở mức theo dõi từng trường dữ liệu tổng quát.
3. **Bài toán chi phí và độ trễ khi tích hợp AI:**
   - Không thể gửi toàn bộ tệp mã nguồn vào cho AI đọc vì chi phí và thời gian phản hồi sẽ rất lớn. Nhóm đang phải hoàn thiện cơ chế chỉ trích xuất đúng lát cắt mã nguồn tối thiểu liên quan đến cảnh báo để cung cấp ngữ cảnh vừa đủ cho AI.
4. **Sự chênh lệch về độ sâu phân tích giữa các ngôn ngữ:**
   - Hiện tại lane Python được đầu tư sâu nhất về đồ thị luồng dữ liệu và phân tích liên tệp. Trong khi đó, lane Java và JavaScript mới dừng ở mức phân tích cú pháp trong phạm vi tệp đơn, chưa đạt được độ sâu tương đương.

---

## 6. Kế Hoạch Triển Khai Trong Tuần Tiếp Theo

Dựa trên các nghiên cứu quốc tế và kết quả đo đạc thực tế, nhóm dự kiến tập trung vào các công việc sau trong tuần tới:

1. **Nâng cấp bộ nhận diện cơ chế làm sạch cho nhóm XSS:**
   - Cải tiến bộ quét để phân tích toàn bộ biểu thức ghép chuỗi nhiều dòng, nhận diện đầy đủ các hàm mã hóa HTML theo chuẩn an toàn, nhằm giải quyết triệt để 115 trường hợp báo sai của nhóm này.
2. **Bổ sung kiểm tra cấu hình parser cho nhóm XXE:**
   - Áp dụng đúng nguyên lý kiểm tra cấu hình an toàn: chỉ cảnh báo khi parser XML thực sự bật tính năng đọc thực thể ngoài và nhận dữ liệu chưa được kiểm soát. Mục tiêu là khôi phục đầy đủ các ca lỗi thật và loại bỏ 77 ca báo sai.
3. **Phân tích luồng dữ liệu theo từng trường (Field-Sensitive Analysis):**
   - Theo dõi độc lập từng khóa trong từ điển và tệp cấu hình để phân biệt chính xác giá trị nào an toàn và giá trị nào bị nhiễm độc từ bên ngoài.
4. **Thử nghiệm kết nối AI với mô hình chạy nội bộ:**
   - Thử nghiệm kết nối lớp phản biện AI với các mô hình mã nguồn mở chạy cục bộ để đánh giá chi phí, thời gian phản hồi và độ ổn định khi không phụ thuộc vào dịch vụ bên ngoài.
5. **Chuẩn bị nội dung báo cáo trực tiếp:**
   - Rà soát kịch bản trình diễn trên giao diện web để sẵn sàng báo cáo tiến độ và demo trực tiếp với Thầy.

---

## 7. Kết Luận

So với đợt báo cáo Tháng 9, đề tài đã có bước tiến thực chất: chuyển từ việc thử nghiệm nhỏ lẻ sang **đo đạc thực tế trên toàn bộ 1,230 ca kiểm thử của chuẩn mực quốc tế OWASP Benchmark**, chứng minh được khả năng **giảm từ 65% đến gần 90% cảnh báo sai** của phương pháp lai ghép.

Nhóm kiên định bám sát các nguyên lý phân tích tĩnh chuẩn mực quốc tế để bảo đảm hệ thống có giá trị thực tiễn, thay vì chỉnh sửa đối phó theo bài kiểm thử.

Nhóm kính mong tiếp tục nhận được những ý kiến nhận xét và định hướng của Thầy để hoàn thiện đề tài trong các giai đoạn tiếp theo.

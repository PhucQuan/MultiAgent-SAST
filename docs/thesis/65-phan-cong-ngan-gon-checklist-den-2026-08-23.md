# Phân công ngắn gọn dạng checklist đến Chủ nhật 23/08/2026

## Dự án hiện tại đang cần làm tiếp gì

Đúng với repo hiện tại thì tuần này nhóm cần chốt 4 việc lớn:

- [ ] Giảm false positive của bản scan Python, nhất là `PATH_TRAVERSAL`
- [ ] Làm cho 3 mức benchmark tách nhau rõ hơn: `all`, `visible`, `high-confidence`
- [ ] Làm cho phần triage / AI / LangGraph hiện có tạo ra khác biệt rõ trên finding thật
- [ ] Gom được 1 bộ demo ngắn, dễ chạy lại: `scan -> triage -> report -> dashboard`

## Mục tiêu chung của cả nhóm đến tối Chủ nhật

- [ ] Có **1 report JSON mới** để cả nhóm dùng chung
- [ ] Có **1 bảng benchmark mới** sau khi scan lại
- [ ] Có **1 bản triage chạy được trên finding thật** và nhìn ra được nó giúp gì
- [ ] Có **1 flow demo ngắn** để cả nhóm nói cùng một ý khi báo cáo

## Phân công theo người

### 1. Quân

**Quân làm phần scanner chính:**

- [ ] Sửa scanner Python để đỡ nhiễu hơn
- [ ] Ưu tiên xử lý `PATH_TRAVERSAL` trước
- [ ] Xuất **1 report JSON mới** cho cả nhóm dùng chung
- [ ] Làm **1 bản before / after** để thấy kết quả đã đỡ nhiễu hơn

**Quân cần giao:**

- [ ] 1 report JSON mới
- [ ] 1 note ngắn ghi rõ đã sửa gì
- [ ] 1 bản so sánh trước / sau

**Hạn nên xong:** chậm nhất **Thứ Sáu 21/08/2026**

### 2. Ánh

**Ánh làm phần benchmark và gom kết quả cuối:**

- [ ] Lấy report mới của Quân để chạy benchmark lại
- [ ] Chấm lại 3 mức: `all`, `visible`, `high-confidence`
- [ ] Chốt **1 cách chạy benchmark thống nhất** cho cả nhóm
- [ ] Gom artifact cuối: score, report, SARIF, checklist demo

**Ánh cần giao:**

- [ ] 1 bảng score mới
- [ ] 1 runbook benchmark ngắn
- [ ] 1 checklist demo / integration

**Hạn nên xong:** chậm nhất **Thứ Bảy 22/08/2026**

### 3. Tuệ

**Tuệ làm phần triage / AI / LangGraph:**

- [ ] Không làm LangGraph từ số 0
- [ ] Lấy phần workflow triage / LangGraph đang có rồi làm cho chạy rõ trên finding thật
- [ ] Chốt 4 trạng thái ngắn gọn, dễ hiểu:
- [ ] `confirmed`
- [ ] `likely`
- [ ] `needs-review`
- [ ] `suppressed`
- [ ] Làm sao để 3 mức `all`, `visible`, `high-confidence` bắt đầu khác nhau thật
- [ ] Viết 1 note ngắn giải thích: AI đi qua những bước nào, khi nào thì đổi status
- [ ] Nếu kịp thì chốt luôn cách lưu review / note đơn giản để làm nền cho triage memory

**Tuệ cần giao:**

- [ ] 1 bản triage / LangGraph chạy được trên finding thật
- [ ] 1 note ngắn giải thích status và route
- [ ] 1 ví dụ cho thấy triage có tác động thật lên kết quả

**Hạn nên xong:** chậm nhất **Chủ nhật 23/08/2026**

## Trả lời ngắn gọn câu hỏi: phần LangGraph khi nào mới làm được?

Repo hiện tại **không phải chưa có gì**. Phần workflow triage, AI runner và LangGraph bridge **đã có sẵn khung rồi**.

Vì vậy tuần này mục tiêu của Tuệ **không phải viết mới từ đầu**, mà là:

- [ ] Làm cho phần đang có chạy được trên finding thật
- [ ] Làm cho kết quả triage nhìn ra được khác biệt
- [ ] Chuẩn bị để demo được cùng luồng `scan -> triage -> report`

Nói ngắn gọn:

- [ ] Quân sửa scanner cho đỡ nhiễu
- [ ] Ánh chấm benchmark và gom kết quả
- [ ] Tuệ làm cho triage / LangGraph hiện có tạo ra tác dụng thật

## 4 thứ bắt buộc phải có vào tối Chủ nhật

- [ ] Report mới
- [ ] Bảng benchmark mới
- [ ] Bản triage / LangGraph chạy được trên finding thật
- [ ] Flow demo ngắn để cả nhóm gửi báo cáo và nói cùng một ý

# Phân việc tuần 07/09/2026 - 13/09/2026

Tuần này không mở thêm việc mới. Mục tiêu là chốt phần đang làm dở để có đồ demo và có cái để báo cáo.

## Việc cần làm tiếp ngay

1. Chốt phần LangGraph của Tuệ và đưa lên repo.
2. Khóa một bộ benchmark/report chạy ổn định.
3. Gom lại thành một luồng demo ngắn: scan -> report -> dashboard -> phần triage.

## Phân việc theo người

### Tuệ

- Việc đầu tiên là dọn và push phần vẽ node LangGraph đã làm.
- Viết ngắn một note giải thích sơ đồ node: node nào làm gì, luồng đi ra sao, chỗ nào đang là demo, chỗ nào chưa hoàn chỉnh.
- Sau khi push xong thì nối phần đó với flow triage hiện tại để cả nhóm nhìn vào là hiểu được câu chuyện.

Kết quả cần có:

- code đã push;
- 1 hình hoặc 1 file mô tả flow node;
- 1 đoạn giải thích ngắn để dùng khi demo.

### Quân

- Chốt phần scanner/rule bên dưới để đầu ra ổn định.
- Chạy lại scan trên đúng bộ case đang dùng, kiểm tra output JSON/Markdown có sạch không.
- Nếu còn lỗi nhỏ làm vỡ flow demo thì sửa luôn, không mở thêm nhánh lớn.

Kết quả cần có:

- 1 bộ report mới dùng được;
- ghi ngắn chỗ nào đã sửa trong detector/rule;
- bàn giao file report cho Ánh và Tuệ.

### Ánh

- Nhận report từ Quân để chốt benchmark và phần đem đi báo cáo.
- Gom lại một runbook ngắn: chạy lệnh nào, lấy file nào, mở dashboard ở đâu.
- Kiểm tra phần demo từ report sang dashboard có chạy mượt không.

Kết quả cần có:

- 1 bảng benchmark ngắn;
- 1 checklist demo;
- 1 runbook ngắn để ai mở máy lên cũng làm lại được.

## Thứ tự làm trong tuần

1. Tuệ đẩy phần LangGraph lên trước.
2. Quân chốt lại report đầu ra.
3. Ánh gom benchmark và demo pack.
4. Cuối tuần cả nhóm ráp lại một lượt để chạy thử.

## Chốt ngắn gọn

Tuần này chia rất rõ:

- Tuệ lo phần LangGraph và flow triage.
- Quân lo đầu ra scan và report.
- Ánh lo benchmark, runbook và demo.

Không ôm thêm việc mới. Làm xong ba phần này là đủ đẹp để báo cáo và demo.

# Kich ban demo

## Muc tieu demo

Trong 8 den 12 phut, can cho hoi dong thay:

- project scan duoc
- project co logic phan tich ro
- project co triage thong minh
- project co huong remediation
- project co gia tri do an, khong chi la CLI demo

## Kich ban de xuat

### Buoc 1: Gioi thieu bai toan

Noi ngan:

- code review thu cong ton thoi gian
- regex-based scan de false positive
- can scanner co evidence va triage

### Buoc 2: Gioi thieu Aegis-SAST hien tai

Mo ta nhanh:

- plugin architecture
- Tree-sitter AST
- taint analysis
- AI verification

### Buoc 3: Demo scan

Chay tren:

- `test_projects/cross_file_app/`

Muc tieu:

- show cross-file detection cho Python
- show report output

### Buoc 4: Demo triage vision

Neu da co triage:

- mo finding status
- giai thich vi sao confirmed hoac likely

Neu chua code kip:

- mo file docs benchmark va triage schema de cho thay huong nang cap da ro

### Buoc 5: Demo remediation

- lay mot finding SQLi hoac RCE
- trinh bay secure pattern thay the
- neu co patch thi show patch

### Buoc 6: Demo benchmark plan

- show bang metrics
- show baseline voi Semgrep va CodeQL

## Diem quan trong khi demo

- Khong claim support sau cho tat ca ngon ngu neu chua co
- Nhan manh Python cross-file la dong gop hien tai
- Nhan manh AI la triage assistant, khong phai "oracle"


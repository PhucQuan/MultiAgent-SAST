# Ke hoach benchmark

## Muc tieu benchmark

Can chung minh 3 dieu:

1. Scanner core cua Aegis-SAST co kha nang phat hien duoc nhieu case co nghia.
2. AI triage giup giam noise.
3. Aegis-SAST co gia tri rieng so voi baseline.

## Baseline de xuat

| Baseline | Muc dich |
|---|---|
| Semgrep | So sanh voi scanner rule-based da ngon ngu, de setup |
| CodeQL | So sanh voi he thong query/dataflow truong thanh |
| Local vulnerable samples | Kiem soat duoc ground truth va de demo |

## Datasets nen dung

- `examples/` trong repo
- `test_projects/` trong repo
- bo mau tu xay them cho SQLi, RCE, path traversal, XSS tren Python, JavaScript, Java, PHP
- neu co the, mot tap benchmark cong khai phu hop voi Python cho benchmark sau
- bo sample nho de kiem tra do phu da ngon ngu tren JavaScript, Java, PHP

## Metrics can bao cao

| Metric | Y nghia |
|---|---|
| Precision | Ty le finding dung tren tong finding |
| Recall | Ty le loi tim duoc tren tong ground truth |
| F1 | Tong hop precision va recall |
| Runtime | Toc do scan |
| Findings by class | Do phu theo tung loai loi |
| FP reduction | Muc giam false positive sau triage |

## Thi nghiem de xuat

### Thi nghiem A

So sanh:

- Aegis-SAST core
- Aegis-SAST core + AI triage

### Thi nghiem B

So sanh:

- Aegis-SAST
- Semgrep

Huong danh gia:

- benchmark sau tren Python
- benchmark mo rong tren JavaScript, Java, PHP o muc coverage va quality finding

### Thi nghiem C

So sanh:

- Aegis-SAST
- CodeQL

Chi nen ap dung tren lop loi va ngon ngu ma ban thuc su ho tro tot, uu tien Python va scope hep cho Java neu phu hop.

## Nguyen tac bao cao

- Khong so sanh tren pham vi ban khong ho tro that
- Ghi ro ngon ngu nao la ngon ngu phan tich sau, ngon ngu nao la ngon ngu mo rong
- Ghi ro gioi han tung tool va tung ngon ngu
- Ghi ro command va config da dung

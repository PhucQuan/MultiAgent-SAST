# Benchmark core va ra soat DOCX ngay 2026-09-07

## 1. Muc tieu

File nay chot 2 viec da lam trong ngay:

1. Chay lai benchmark that tren `D:\BenchmarkPython\testcode` cho core Python 4-family.
2. Doc lai cac file `.docx` trong `docs/thesis` de xem noi dung nao dang bam sat codebase, noi dung nao da cu.

Khong mo them scope moi. Muc tieu la co mot moc thuc nghiem moi va mot ket luan ro rang de ca nhom dung chung.

## 2. Lenh da chay

### 2.1. Core mac dinh

```powershell
python -m aegis_sast.cli scan "D:\BenchmarkPython\testcode" `
  --no-ai `
  -o json `
  --output-dir "reports/manual_targets/benchmark_python_current_core_20260907_default"
```

```powershell
python scripts/score_owasp_benchmark.py `
  --report "reports/manual_targets/benchmark_python_current_core_20260907_default/aegis_sast_report_20260907_162210.json" `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --family COMMAND_INJECTION `
  --family PATH_TRAVERSAL `
  --family INSECURE_DESERIALIZATION `
  --family SQL_INJECTION `
  --output-dir "reports/benchmark/owasp/benchmark_python_current_core_20260907_default_score4"
```

### 2.2. Core + reviewed overlay

```powershell
python -m aegis_sast.cli scan "D:\BenchmarkPython\testcode" `
  --no-ai `
  --reviewed-rule-profile semgrep-python-core4 `
  -o json `
  --output-dir "reports/manual_targets/benchmark_python_current_core_20260907_reviewed_core4"
```

```powershell
python scripts/score_owasp_benchmark.py `
  --report "reports/manual_targets/benchmark_python_current_core_20260907_reviewed_core4/aegis_sast_report_20260907_162351.json" `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --family COMMAND_INJECTION `
  --family PATH_TRAVERSAL `
  --family INSECURE_DESERIALIZATION `
  --family SQL_INJECTION `
  --output-dir "reports/benchmark/owasp/benchmark_python_current_core_20260907_reviewed_core4_score4"
```

## 3. Ket qua benchmark moi nhat

### 3.1. Core mac dinh

| Mode | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| all | 85 | 10 | 16 | 0.8947 | 0.8416 | 0.8673 |
| visible | 85 | 0 | 16 | 1.0000 | 0.8416 | 0.9140 |
| high-confidence | 73 | 0 | 28 | 1.0000 | 0.7228 | 0.8391 |

Per-family o mode `all`:

| Family | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| COMMAND_INJECTION | 13 | 4 | 0 | 0.7647 | 1.0000 | 0.8667 |
| PATH_TRAVERSAL | 52 | 0 | 13 | 1.0000 | 0.8000 | 0.8889 |
| INSECURE_DESERIALIZATION | 15 | 6 | 3 | 0.7143 | 0.8333 | 0.7692 |
| SQL_INJECTION | 5 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

### 3.2. Core + reviewed overlay

Bang diem ra giong het core mac dinh:

| Mode | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| all | 85 | 10 | 16 | 0.8947 | 0.8416 | 0.8673 |
| visible | 85 | 0 | 16 | 1.0000 | 0.8416 | 0.9140 |
| high-confidence | 73 | 0 | 28 | 1.0000 | 0.7228 | 0.8391 |

Kiem tra diff tren JSON report cho thay:

- default findings: `144`
- reviewed findings: `144`
- chi co o default: `0`
- chi co o reviewed: `0`

Nghia la tren full OWASP Benchmark Python 4-family, profile `semgrep-python-core4` hien chua lam thay doi tap finding so voi core mac dinh.

## 4. Cach hieu ket qua nay

1. Core Python hien tai van on va khong bi troi sau cac thay doi gan day. So diem benchmark khop lai moc thesis da dung truoc do.
2. Triage 3 muc `all / visible / high-confidence` van tach nhau ro va co gia tri bao cao:
   - `visible` hien dat precision `1.0000`
   - `high-confidence` la tap hep hon, giu precision `1.0000` nhung doi lai recall giam
3. Huong reviewed overlay van dung ve mat chien luoc, nhung can noi that:
   - no da cho gia tri ro tren reviewed smoke suite va artifact nho
   - tren full OWASP Python run ngay 2026-09-07, no chua tao delta moi
4. Vi vay, cau chuyen chot hop ly hien tai van la:
   - giu Aegis lam scanner chinh
   - giu reviewed Semgrep profile lam overlay co kiem soat
   - khong claim rang reviewed overlay da nang diem full benchmark Python ngay luc nay

## 5. Ra soat cac file DOCX trong `docs/thesis`

Danh sach da doc:

- `14-de-cuong-nghien-cuu-de-tai.docx`
- `15-phase-3-thang-va-phan-cong-quan-tue.docx`
- `16-de-cuong-bao-cao-de-tai-ban-giang-vien.docx`
- `69-de-cuong-cap-nhat-gui-thay-2026-08-30.docx`
- `phan-cong-checklist-den-2026-08-23.docx`
- `phan-cong-checklist-den-2026-08-23-cap-nhat.docx`

Quan sat ky thuat:

- ca 6 file deu khong co `comments.xml`
- ca 6 file deu con dau vet tracked changes trong OOXML
- 4 file `14/15/16/69` deu co ban `.md` song song trong repo

### 5.1. File 69 la file bam sat hien trang nhat

`69-de-cuong-cap-nhat-gui-thay-2026-08-30.docx` la file phu hop nhat de dung lam nen trao doi voi giang vien o thoi diem hien tai vi:

- giu cau chuyen dung: deterministic core la lop phat hien chinh, AI nam o lop triage
- ghi ro huong rule la baseline Semgrep da review nap vao Aegis nhu overlay
- ghi ro bang diem core 4-family dang dung duoc
- khong claim qua muc rang LangGraph da dieu phoi end-to-end toan bo pipeline

Noi dung file nay van khop voi benchmark rerun ngay 2026-09-07.

### 5.2. File 14 va 16 dung de dinh huong, khong nen dung nguyen van de bao cao state hien tai

Hai file nay van co gia tri de mo ta bai toan nghien cuu va tham vong thesis, nhung co mot so doan de bai toan va roadmap con rat tham vong:

- benchmark dong nhat 4 ngon ngu
- LangGraph / agent workflow day du hon muc hien tai
- cac RQ va ablation quanh AI triage chua co du bang chung benchmark that o muc on dinh

Vi vay:

- dung `14` va `16` de lay khung cau chuyen nghien cuu
- khong dung chung nhu tai lieu chinh de mo ta trang thai implementation hien tai

### 5.3. File 15 la ke hoach cu, hien da lech kha nhieu so voi sprint hien tai

File `15-phase-3-thang-va-phan-cong-quan-tue.docx` chu yeu la ke hoach 12 tuan va phan cong Quan - Tue theo scope lon hon:

- parity da ngon ngu
- benchmark da ngon ngu
- LangGraph end-to-end
- ablation AI ro rang

Tai sprint hien tai, file nay nen duoc xem la tai lieu lich su de tham khao, khong phai runbook thuc thi tuan nay.

### 5.4. Hai file checklist 23/08 hien da cu

`phan-cong-checklist-den-2026-08-23.docx` va ban `-cap-nhat.docx`:

- text trich xuat hien tai giong nhau
- noi dung la checklist sprint cu tap trung vao:
  - giam FP PATH_TRAVERSAL
  - tach `all / visible / high-confidence`
  - lam triage / LangGraph co tac dung that
  - gom bo demo scan -> triage -> report -> dashboard

Nhieu muc trong do den ngay 2026-09-07 da duoc lam xong hoac chuyen sang pham vi moi, nen 2 file nay khong nen dung de phan cong hay bao cao nua.

## 6. Ket luan ngan

Tinh den ngay 2026-09-07, ket luan an toan nhat la:

1. Core SAST Python 4-family dang on, benchmark that van giu duoc moc diem manh nhat cua thesis.
2. Reviewed overlay la huong dung, nhung tren full OWASP Python run hien chua tao delta moi.
3. File docx nen dung lam nen bao cao state hien tai la `69-de-cuong-cap-nhat-gui-thay-2026-08-30.docx`.
4. Hai file checklist `23/08` da cu va nen xem la artifact lich su.

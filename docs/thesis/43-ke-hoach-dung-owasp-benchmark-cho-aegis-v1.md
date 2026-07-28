# Ke hoach dung OWASP Benchmark cho Aegis-SAST V1

## 1. Vi sao can file nay

Aegis da co:

- scanner core
- reviewed rule bundle flow
- triage labels
- rule workbench scaffold

Nhung de bien thanh bai khoa luan/NCKH manh, can them mot lop chung minh:

- scanner co bat duoc loi that khong
- reviewed bundle co giam on khong
- triage co giam false positives ma khong lam mat qua nhieu true positives khong

OWASP Benchmark la lua chon hop ly nhat de lam moc do vi no cho phep do ket qua tren bo test co cau truc va co scoring.

## 2. Muc tieu benchmark V1

Benchmark V1 khong nham "danh bai" Semgrep hay CodeQL.
Muc tieu thuc te hon:

1. Chung minh Aegis co the scan tren mot benchmark duoc cong nhan rong rai.
2. Do duoc su khac nhau giua:
   - default rules
   - reviewed bundles
   - reviewed bundles + triage
3. Co baseline de viet phan thuc nghiem va limitations.

## 3. Chot scope benchmark nho nhung sach

De tranh to scope, benchmark V1 nen chia 2 lane:

### 3.1. Lane chinh: Python

Dung cho:

- reviewed bundles `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`
- triage evidence cua Aegis hien tai

Y nghia:

- sat voi lane ky thuat manh nhat cua repo hien tai
- de lien ket voi rule workbench va reviewed bundles

### 3.2. Lane phu: Java chi de doi chieu benchmark cong nghiep

Dung cho:

- nhin benchmark truong thanh hon
- tham khao cau truc scoring/corpus
- khong bat buoc dua vao claim chinh cua khoa luan V1

Y nghia:

- vi OWASP Benchmark Java truong thanh hon;
- nhung khong nen de lane Java lam loi tam vi scanner sau cua Aegis hien tai van la Python.

## 4. Cac che do can do

Toi thieu nen co 4 che do:

### 4.1. Aegis core

- detector runtime mac dinh
- khong reviewed bundle rieng
- khong triage nang cao

### 4.2. Aegis reviewed bundle

- dung bundle da review cho tung family
- khong them multi-agent triage nang cao

### 4.3. Aegis reviewed bundle + triage

- reviewed bundle
- co evidence summary / graph slice / labels `likely`, `needs-review`, `suppressed`

### 4.4. Semgrep baseline

- dung nhu baseline deterministic rules engine
- khong can co tham vong dat so rule ngang nhau
- muc tieu la co moc doi chieu ben ngoai

## 5. Metrics can do

Toi thieu:

- precision
- recall
- F1
- tong so findings
- false positives
- false negatives
- runtime

Neu co triage:

- FP reduction sau triage
- TP retention sau triage
- ty le finding bi `suppressed`

Neu co AI draft rule sau nay:

- ty le rule qua validator
- ty le rule qua human review
- delta so findings truoc/sau reviewed bundle

## 6. Ground truth can giu ro

Ground truth trong benchmark can tach ro:

### 6.1. Synthetic / benchmark truth

- testcase nao co vulnerability
- testcase nao la safe
- family nao map voi CWE nao

### 6.2. Real-repo review truth

- mau nho
- co human review
- dung de bo sung phan "repo that"

Khong nen tron 2 loai nay vao mot bang ket qua duy nhat.

## 7. Ranh gioi claim can giu

Khi viet ket qua, nen claim nhu sau:

- Aegis V1 benchmark sau nhat tren Python lane;
- reviewed bundles giup giam on so voi default rules;
- triage giup uu tien finding va giam FP review burden;
- Semgrep la baseline tham chieu;
- CodeQL la semantic/data-flow reference cho huong mo rong, khong phai baseline chinh cua V1.

Khong nen claim:

- da dat capability parity da ngon ngu;
- da vuot CodeQL;
- da co benchmark day du cho moi OWASP Top 10 family.

## 8. Thu tu trien khai hop ly

### Buoc 1

- hoan tat 3 reviewed bundles:
  - `COMMAND_INJECTION`
  - `PATH_TRAVERSAL`
  - `INSECURE_DESERIALIZATION`

### Buoc 2

- chuan hoa corpus synthetic nho cho tung family
- moi family co:
  - TP cases
  - FP cases
  - edge cases

### Buoc 3

- tao benchmark runner V1
- runner xuat:
  - json
  - markdown summary
  - per-family metrics

### Buoc 4

- chay benchmark voi:
  - Aegis core
  - reviewed bundle
  - reviewed bundle + triage
  - Semgrep baseline

### Buoc 5

- viet error analysis:
  - FP do rule
  - FP do source attribution
  - FP do sink overmatch
  - miss do thieu family coverage

## 9. Deliverables nen co

Toi thieu:

- `datasets/benchmark/...`
- `scripts/run_benchmark_v1.py`
- `reports/benchmark/...`
- `docs/thesis/44-...` cho runbook benchmark
- `docs/thesis/45-...` cho ket qua va dien giai

## 10. Ket luan ngan

Neu phai chot 1 benchmark cho khoa luan, thi huong dep nhat la:

- dung OWASP Benchmark lam benchmark co ten tuoi;
- dung synthetic corpus nho de test reviewed bundles;
- dung Semgrep lam baseline deterministic;
- va dung Aegis triage de chung minh `FP reduction after scan`.

Nhu vay cau chuyen se rat ro:

- co benchmark chuan
- co baseline
- co cai tien do duoc
- va co khong gian de viet phan limitations that tha

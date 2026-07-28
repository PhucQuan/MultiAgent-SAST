# Review Bundle va Legacy Bridge V1

## 1. Tai sao can them buoc nay

Sau khi co:

- `normalized rule schema`
- `Semgrep subset importer`
- `validator` cho normalized rule

repo van con mot khoang trong thuc te:

- lam sao de chay mot flow review gon trong 1 lenh;
- va lam sao de dung rule da review voi scanner hien tai, trong khi detector van doc format rules cu.

Tai lieu nay chot 2 artifact de lap khoang trong do:

1. `scripts/build_rule_review_bundle.py`
2. `scripts/export_normalized_rules_legacy.py`

## 2. Rule review bundle la gi

`build_rule_review_bundle.py` la wrapper nho chay lien tiep:

1. import Semgrep-shaped seed
2. normalize ve schema Aegis
3. validate theo profile review
4. neu can thi export sang legacy rules format

No giup bien quy trinh review thanh mot lenh co the lap lai thay vi phai goi 3-4 script roi rac.

## 3. Legacy bridge giai quyet bai toan gi

Detector hien tai van doc custom rules theo format cu:

- `sources`
- `sinks`
- `sanitizers`

Trong khi flow ingestion moi dang di theo:

- `identity`
- `taxonomy`
- `detection`
- `triage`
- `provenance`

`export_normalized_rules_legacy.py` la cau noi tam thoi de:

- rule da review van duoc dua vao `scan_target.py --rules`
- trong luc detector chua an truc tiep normalized schema

Day la **bridge tam thoi co kiem soat**, khong phai dich den cuoi cung.

## 4. Manual seed fixture

Repo da duoc bo sung:

- `datasets/synthetic/rule_review_v1/seed_inputs/python_command_injection_semgrep_shape.yaml`

Day la fixture local tu viet tay, chi mo phong shape cua Semgrep subset de test flow:

- importer
- validator
- legacy bridge

No khong phai raw Semgrep registry snapshot, nen khong gay mo ho provenance/license.

## 5. Flow V1 hien tai

Flow hop ly luc nay la:

1. chon seed fixture hoac snapshot local
2. chay `build_rule_review_bundle.py`
3. xem normalized output
4. xem validation report
5. neu on, dung legacy bridge output de scan thu nghiem

Noi ngan gon:

- `seed -> normalize -> validate -> export bridge -> scan`

## 6. Vi sao buoc nay dung huong

Buoc nay giu duoc 4 nguyen tac da chot trong docs `34-37`:

1. khong cho AI nap rule thang vao detector runtime
2. co provenance va review gate
3. giu detector deterministic
4. mo duong benchmark/scan thu nghiem ma khong vo contract

## 7. Gioi han hien tai

Bridge hien tai co chu y thuc dung, nen co gioi han ro:

- uu tien pattern call-like don gian
- bo qua pattern-regex va pattern co metavariable khong map dep sang engine cu
- chua phai la full semantic transfer

Nghia la:

- review bundle dung de dua V1 vao van hanh
- khong duoc overclaim rang moi normalized rule deu convert day du sang detector runtime

## 8. Buoc tiep theo sau artifact nay

Sau khi co 2 script nay, thu tu tiep theo hop ly nhat la:

1. chay review bundle cho `COMMAND_INJECTION`
2. dung legacy output scan 1 corpus Python nho
3. ghi lai TP/FP so bo
4. sau do moi scaffold web Rule Workbench V1

## 9. Ket luan

`build_rule_review_bundle.py` va `export_normalized_rules_legacy.py` giup Aegis-SAST co mot cau noi rat quan trong giua:

- rule ingestion/review flow moi
- va scanner runtime hien tai

Day la buoc thuc dung, nho scope, nhung co gia tri ky thuat ro rang cho V1.

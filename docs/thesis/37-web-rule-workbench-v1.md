# Web Rule Workbench V1 cho Aegis-SAST

## 1. Tai sao tai lieu nay can thiet

Sau khi doc lai cac file `30` den `36`, huong di hop ly nhat khong con la:

- quet them nhieu repo mot cach on ao;
- hay nap them that nhieu rule vao detector ngay lap tuc.

Huong hop ly hon la tao mot lop **rule workbench** nho de:

1. sinh draft rule co cau truc;
2. review truoc khi dua vao detector;
3. giu provenance va taxonomy ro rang;
4. benchmark duoc voi Semgrep subset.

Tai lieu nay chot y tuong "lam web de AI sinh rule roi moi scan" theo huong an toan scope va hop voi roadmap hien tai.

## 2. Ket luan sau khi doc lai file 30-36

### File 30-31 da cho thay

- repo da co graph smoke va mini benchmark cho Python graph core;
- nghia la lop "chung minh core co gia tri" da bat dau hinh thanh.

### File 32-33 da cho thay

- roadmap lon van uu tien deterministic core, benchmark, parity va evidence;
- AI khong duoc nhay vao lam detector chinh;
- Python van la deep lane, JS/Java la breadth lane.

### File 34-36 da cho thay

- normalized rule schema va Semgrep subset importer la huong dung;
- Phase A cleanup phai lam truoc khi ingest them rule;
- sau cleanup thi buoc tiep theo hop ly la import subset nho, review, roi benchmark.

Tu do, y tuong "web sinh rule" la **co the lam**, nhung phai lam dung vai tro:

- **khong** phai web scanner toan nang ngay;
- **ma la** web workbench de author/review rule.

## 3. Chot vai tro cua web V1

Web nay nen duoc dat ten dung ban chat:

- `Rule Workbench`
- hoac `Rule Authoring Studio`

Chu khong nen dat ki vong no la:

- thay Semgrep;
- thay CodeQL;
- hay thay detector runtime hien tai.

Vai tro dung cua no la:

1. nhan input tu docs/example/Semgrep subset/snippet loi;
2. AI sinh **draft normalized rule YAML**;
3. he thong validate schema;
4. con nguoi review va sua;
5. luu rule vao snapshot co provenance;
6. chi sau do moi dua vao scan thu nghiem.

## 4. Vi sao huong nay hop ly hon "quet bua"

Neu detector chua co workflow author/review cho rules, scanner se gap 3 van de:

1. coverage tang nhanh nhung FP tang nhanh hon;
2. khong biet rule nao den tu dau;
3. kho benchmark va kho giai thich voi giang vien.

Neu co rule workbench truoc, nhom se co:

- mot noi de rule duoc sinh ra theo schema thong nhat;
- mot noi de review source/sink/sanitizer;
- mot noi de luu provenance;
- mot cach de noi "rule nay la draft AI", "rule nay la imported tu Semgrep", "rule nay da human-reviewed".

Day moi la diem co gia tri ky thuat va nghien cuu.

## 5. Scope V1 nen that nho

Khong nen lam web qua to ngay tu dau.

V1 nen chot:

- chi `Python`
- chi 3 family:
  - `COMMAND_INJECTION`
  - `PATH_TRAVERSAL`
  - `INSECURE_DESERIALIZATION`
- chi sinh `draft rule`
- chi validate va review
- chua can auto-scan nguyen repo trong web

Neu scope to hon ngay:

- se chong cheo voi scanner core;
- web dep nhung khong co bang chung benchmark;
- mat dung uu tien cua file `35` va `36`.

## 6. Workflow de xuat cho web V1

### Buoc 1. Chon nguon rule seed

Nguon vao co the la:

- mot Semgrep rule subset local;
- mot doan docs API;
- mot vulnerable example;
- mot secure vs insecure code pair.

### Buoc 2. AI sinh draft normalized rule

AI khong sinh detector logic tu do, ma phai sinh theo schema Aegis:

- `rule_id`
- `language`
- `family`
- `cwe`
- `owasp`
- `source_patterns`
- `sink_patterns`
- `sanitizers`
- `match_mode`
- `severity`
- `provenance`
- `notes`

### Buoc 3. Validator check schema

He thong validate:

- field nao thieu;
- family co hop scope V1 khong;
- pattern nao qua rong;
- provenance co mat khong.

### Buoc 4. Human review

Reviewer phai check:

- source co qua rong khong;
- sink co exact-call hay khong;
- sanitizer co hop ngon ngu khong;
- metadata CWE/OWASP co dung khong.

### Buoc 5. Snapshot va luu provenance

Moi rule duoc luu kem:

- ai tao ra;
- tao tu nguon nao;
- ngay gio;
- co human-review chua;
- snapshot version nao.

### Buoc 6. Scan thu nghiem tren corpus nho

Khong scan nguyen repo lon ngay.

Chi scan tren:

- synthetic cases;
- repo subset nho;
- benchmark overlap voi Semgrep.

## 7. Kien truc V1 nen dung

Kien truc nhe nhat la:

1. `Frontend web nho`
   - form nhap docs/snippet
   - xem draft YAML
   - nut validate
   - nut save snapshot

2. `Backend rule service`
   - goi AI de sinh YAML draft
   - goi validator
   - goi importer/normalizer neu input la Semgrep rule

3. `Storage`
   - luu draft rules
   - luu reviewed rules
   - luu provenance

4. `Optional test runner`
   - scan 1 folder synthetic nho
   - tra finding count de reviewer nhin nhanh

Quan trong:

- detector runtime va rule workbench phai tach nhau;
- web khong duoc tu y nap rule vao detector production ma khong qua review gate.

## 8. Nen tai su dung gi tu repo hien tai

Web nay khong bat dau tu con so 0.

Co the tai su dung ngay:

- `rules/schema/normalized_rule.example.yaml`
- `scripts/import_semgrep_subset.py`
- `tests/test_semgrep_importer.py`
- docs `34`, `35`, `36`

Neu lam dung, web chi la lop phia tren cua:

- normalized schema
- importer
- review flow

Chu khong phai mot he thong rieng biet.

## 9. Gia tri nghien cuu cua huong nay

Neu trinh bay dung, huong nay co the thanh mot dong gop dep:

1. **Curated rule transfer**
   - chuyen subset rule nguon mo thanh normalized schema co provenance

2. **AI-assisted rule drafting**
   - AI chi sinh ban nhap
   - con nguoi review truoc khi detector dung

3. **Controlled rule governance**
   - rule co version
   - co provenance
   - co benchmark truoc khi dua vao scan chinh

4. **Tach detector va triage knowledge**
   - detector van deterministic
   - AI chi giup authoring va triage

Huong nay khoa hoc hon viec noi chung chung rang "AI giup quet code".

## 10. Dieu khong nen lam trong V1

De giu scope an toan, V1 chua nen:

- import full Semgrep registry;
- crawl live rules tren web;
- cho AI nap rule thang vao detector runtime;
- cho AI lam detector chinh;
- lam dashboard qua dep nhung khong co validator va provenance;
- pitch web nhu mot ban sao cua Semgrep/CodeQL.

Semgrep va CodeQL manh vi:

- kho rule/query cua ho duoc review rat lau;
- co governance;
- co benchmark;
- co semantics da duoc kiem chung.

Aegis V1 nen hoc cach **quan ly va chuyen giao rule co kiem soat**, khong can canh tranh ve so luong rule.

## 11. Thu tu trien khai hop ly nhat tu bay gio

Sau khi doi chieu voi docs `35` va `36`, thu tu hop ly la:

1. chot Phase A cleanup da on bang so lieu PyTorch da co
2. import that 1 Semgrep subset local cho `COMMAND_INJECTION`
3. review normalized output
4. viet validator rule nho neu can
5. tao web workbench V1 de hien draft + validate + save snapshot
6. scan thu nghiem tren corpus nho
7. sau do moi tinh benchmark Aegis vs Semgrep

Noi ngan gon:

- **rule contract truoc**
- **rule workbench sau**
- **benchmark ngay sau do**

Khong nen dao nguoc thanh:

- web truoc
- benchmark de sau
- detector chua co rule governance.

## 12. Deliverable nen co neu trien khai huong nay

Neu chot lam tiep, bo artifact hop ly nhat cho 1 luot tiep theo la:

1. `docs/thesis/37-web-rule-workbench-v1.md`
2. `scripts/validate_normalized_rule.py`
3. `tests/test_normalized_rule_validator.py`
4. `aegis_sast/rule_workbench/webapp.py`
5. `scripts/run_rule_workbench.py`
6. `apps/rule_workbench/` hoac `web/rule_workbench/` ban rat nho
7. 1 tap draft rule Python dau tien da review

## 12.1. Scaffold V1 da co the dung duoc

De giu scope nho va dung roadmap, scaffold V1 nen va da co the di theo huong:

- backend mong trong `aegis_sast/rule_workbench/webapp.py`
- launcher rieng `scripts/run_rule_workbench.py`
- frontend tinh trong `apps/rule_workbench/`

Vai tro cua scaffold nay la:

- liet ke seed inputs local
- goi `RuleWorkbenchService.build_review_bundle(...)`
- preview normalized output, validation report, va legacy bridge

No van giu nguyen tac cua V1:

- khong nap rule thang vao detector runtime
- khong overclaim AI authoring da san sang production
- giu detector va rule governance tach nhau

## 13. Ket luan

Y tuong lam web de AI sinh rule roi moi scan la **on**, nhung chi on neu minh dinh nghia no la:

- mot `rule authoring/review workbench`
- dua tren normalized schema
- co provenance
- co human review
- benchmark duoc voi Semgrep subset

Neu lam dung kieu do, no rat hop voi huong cua Aegis-SAST.

Neu lam theo kieu "AI tu sinh rules roi scan bua", thi no se lech het nhung gi file `34`, `35`, `36` dang co gang chot scope.

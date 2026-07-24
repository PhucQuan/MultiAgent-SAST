# Rule ingestion va normalized schema V1 cho Aegis-SAST

## 1. Muc tieu cua tai lieu nay

Tai lieu nay chot cach dua Aegis-SAST di tiep tu:

- rule YAML thu cong theo tung ngon ngu;

thanh:

- mot pipeline `rule ingestion` co provenance ro rang;
- co `normalized rule schema` de giu contract on dinh;
- co the map subset rule tu nguon mo nhu Semgrep vao Aegis de benchmark va review.

Muc tieu cua giai doan nay khong phai la:

- import that nhieu rule mot cach a o at;
- thay rule engine hien tai bang mot he thong qua phuc tap;
- hoac day AI vao detector runtime.

Muc tieu dung la:

1. chot duoc schema rule on dinh;
2. import duoc mot subset nho, review duoc;
3. de benchmark voi baseline cong nghiep;
4. giu detector deterministic va reproducible.

## 2. Current implementation

Hien tai repo dang co:

- `rules/python.yaml`
- `rules/javascript.yaml`
- `rules/java.yaml`
- `rules/php.yaml`
- `RuleEngine` doc YAML/JSON va cap rule cho detector

Mo hinh hien tai co uu diem:

- don gian;
- de sua tay;
- hop voi scanner AST/rule-based giai doan dau.

Nhung no co 4 gioi han ro:

1. chua co `normalized rule contract` tach biet giua detection va triage;
2. chua co provenance de biet rule den tu dau;
3. chua co quy trinh import subset tu nguon mo de benchmark;
4. chua co review gate cho rule moi truoc khi nap vao detector.

## 3. Engineering gaps can dong

De phase tiep theo on dinh, can dong 5 khoang trong:

### 3.1. Chua co schema normalize

Rule hien tai chi la:

- `sources`
- `sinks`
- `sanitizers`

Neu muon import rule tu Semgrep hoac tao rule bang LLM, can co schema chung de:

- map metadata,
- luu taxonomy,
- giu provenance,
- va bo sung triage notes ma khong lam ban detector.

### 3.2. Chua tach detection metadata va triage knowledge

Trong phase nghien cuu tiep theo:

- detector chi nen doc phan phuc vu detect;
- triage chi nen doc phan guidance, FP hints, remediation notes.

Neu de chung mot khoi, rule engine se bi "ban" boi knowledge khong can cho matching.

### 3.3. Chua co ingestion pipeline co kiem soat

Can mot script nho:

- doc subset rule;
- normalize;
- gan provenance;
- ghi output de human review.

### 3.4. Chua co review policy cho nguon mo

Khong nen copy raw rules tu ben ngoai vao repo ma khong:

- review semantics;
- review overlap voi rule hien tai;
- review provenance va license.

### 3.5. Chua co scope V1 du nho

Neu import ca registry ngay:

- se tang FP;
- kho benchmark;
- kho debug.

V1 can chot rat nho:

- chi `python`;
- chi `command_injection`, `path_traversal`, `insecure_deserialization`;
- chi `Semgrep taint-mode subset` co source/sink/sanitizer map duoc.

## 4. Normalized rule schema de xuat

Schema V1 nen co 5 cum thong tin:

### 4.1. Identity

- `rule_id`
- `title`
- `language`
- `family`
- `severity`

### 4.2. Taxonomy

- `cwe`
- `owasp`

Taxonomy la metadata de:

- report;
- benchmark;
- triage;

chu khong phai detector runtime.

### 4.3. Detection

Cum nay chi chua thong tin detector duoc phep doc:

- `match_mode`
- `source_patterns`
- `sink_patterns`
- `sanitizers`

Moi pattern co the giu:

- `pattern`
- `pattern_mode`
- `exact`
- `by_side_effect`
- `focus_metavariable`

### 4.4. Triage

Cum nay chi phuc vu AI triage va review:

- `fp_hints`
- `remediation_notes`
- `knowledge_refs`

Detector khong duoc can vao cum nay.

### 4.5. Provenance

Cum nay bat buoc de benchmark va governance:

- `source`
- `source_rule_id`
- `source_path`
- `importer`
- `snapshot_version`

Neu khong co provenance, rule moi se kho review va kho lap lai ket qua.

## 5. Why Semgrep subset duoc chon cho V1

Semgrep khong phai toan bo giai phap cuoi, nhung hop nhat cho V1 vi:

- rule o dang YAML;
- co metadata kha ro;
- co nhieu rule taint-mode co san source/sink/sanitizer;
- de lam baseline benchmark.

Nhung V1 chi nen nhan:

- rule `mode: taint`;
- ngon ngu `python`;
- co `pattern-sources` va `pattern-sinks`;
- uu tien pattern co the human-review ro rang.

Nhung rule pattern-only, rule regex qua dac thu, hoac query semantics qua sau nen de phase sau.

## 6. Pipeline ingestion V1

Pipeline de xuat:

1. Chon mot tap file rule nho tu snapshot ngoai repo.
2. Chay `scripts/import_semgrep_subset.py`.
3. Script doc rule, loc theo:
   - language;
   - mode;
   - family override hoac family infer.
4. Script normalize ve schema Aegis.
5. Ghi output thanh mot file review.
6. Human review:
   - pattern nao map duoc;
   - pattern nao nen bo;
   - source/sink nao qua rong;
   - rule nao trung lap.
7. Chi sau review moi xem xet dua vao detector chinh.

## 7. Deliverables V1

Phase nay nen cho ra 4 artifact ro rang:

1. `rules/schema/normalized_rule.example.yaml`
2. `scripts/import_semgrep_subset.py`
3. `tests/test_semgrep_importer.py`
4. bo tai lieu nay

## 8. Current implementation vs engineering gaps vs research contribution vs demo value

### Current implementation

- RuleEngine da on dinh cho YAML/JSON local.
- Detector da chay that cho Python va breadth lane co plugin cho JS/Java/PHP.
- Triage va workflow da co state metadata va route summary.

### Engineering gaps

- Chua co normalized schema cho rule.
- Chua co importer co provenance.
- Chua co review gate cho rule external.
- Chua co benchmark co baseline voi Semgrep.

### Research contribution

Neu lam dung, phase nay tao 3 dong gop khoa hoc/ky thuat ro:

1. mot contract thong nhat giua rule ingestion, detector, triage va benchmark;
2. mot quy trinh chuyen doi subset rule nguon mo thanh rule reviewable;
3. mot nen de do tac dong cua rule transfer den false positives va benchmark.

### Demo value

Demo khong can "hang nghin rules".

Chi can:

- import 10-20 rule subset;
- scan mot repo mau;
- cho thay provenance, taxonomy, va review flow;
- benchmark Aegis vs Semgrep baseline.

## 9. Rui ro va cach giam thieu

### Rui ro 1: Import nham semantics

Giam thieu:

- chi support `taint-mode subset`;
- bo qua rule khong map ro rang;
- human review bat buoc.

### Rui ro 2: Tang FP vi pattern qua rong

Giam thieu:

- scanner cleanup phai lam truoc;
- exact-call matching;
- reject source/sink qua rong khi review.

### Rui ro 3: Khong lap lai duoc benchmark

Giam thieu:

- luu provenance;
- luu snapshot version;
- giu normalized output o dang machine-readable.

## 10. Ket luan

Rule ingestion V1 khong phai muc tieu "them that nhieu rules".

No la buoc dat nen cho:

- scanner core sach hon;
- benchmark baseline that hon;
- triage giau metadata hon;
- va workflow de mo rong rule sau nay ma khong vo contract.

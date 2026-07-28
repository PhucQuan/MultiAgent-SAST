# Commit Moc Ky Thuat va Context Map

## 1. Muc dich

File nay dung de giu context ky thuat cua repo theo cac moc commit lon, tranh truong hop lam nhieu dot roi sau do khong nho:

- phan nao da len GitHub;
- phan nao la milestone ky thuat that su;
- va khi sua subsystem nao thi nen doc lai commit nao truoc.

## 2. Nguyen tac doc lai commit

Khong can moi lan deu doc lai toan bo lich su git.

Nen doc theo **milestone commit** gan voi subsystem dang sua:

- sua Python detector / taint / matcher: doc moc `2bdb54c`, `1ac07b4`
- sua triage / workflow / report metadata: doc moc `64aed3e`, `1ac07b4`, `ba45234`
- sua Semgrep importer / normalized rules: doc moc `17c6930`
- sua JavaScript / Java parity: doc moc `dd58b2d`, `3eeb1fe`

## 3. Cac moc commit lon da len remote

### `0ed0b02`

- khoi tao phan dau cua project
- moc nen dau tien

### `dd58b2d` - multi-language support + OWASP rules expansion

Moc nay dat nen cho:

- plugin JavaScript, Java, PHP
- bo rules da ngon ngu ban dau
- huong mo rong OWASP Top 10

Neu sua breadth lane da ngon ngu thi day la moc phai doc lai.

### `2bdb54c` - cross-file taint + unit test suite

Moc nay quan trong cho:

- Python cross-file taint
- `call_graph.py`
- detector va plugin Python
- test suite nen cho rule engine / taint analysis

Neu sua luong source -> sink cua Python thi day la moc context rat quan trong.

### `64aed3e` - triage workflow + knowledge layer + repo intake

Moc nay chot:

- `knowledge/`
- `triage/`
- `repo_intake`
- workflow state va JSON/Markdown/SARIF report nen dau
- bo docs thesis 00-22 va skill pack ban dau

Neu sua phan AI triage / reporting / orchestration thi phai quay lai moc nay.

### `1ac07b4` - Python graph core + benchmark foundation

Moc ky thuat sau nhat trong nhom core:

- `python_flow_graph.py`
- benchmark ablation cho graph
- workflow metadata va docs 23-31
- `doctor_env.py`, smoke scripts

Neu sua detector Python sau hon substring-rule level, day la moc quan trong nhat.

### `d9bd683`

- roadmap thesis va analyzer availability status
- moc chuyen tiep ve docs/claim/demo

### `17c6930` - normalized schema + Semgrep subset importer

Moc nay chot huong:

- khong tu viet het rules tu dau
- normalize rules truoc
- import Semgrep subset co provenance

File chinh:

- `rules/schema/normalized_rule.example.yaml`
- `scripts/import_semgrep_subset.py`
- `tests/test_semgrep_importer.py`

### `3eeb1fe` - polyglot parity planning

Moc nay chot:

- parity plan Python / JavaScript / Java
- cap nhat plugin dataflow tests
- docs 15, 16, 33 theo huong khoa luan ro hon

### `ba45234` - evidence summary + graph-slice metadata

Moc remote moi nhat hien tai.

Moc nay chot:

- evidence summary
- graph slice metadata
- router / triage / markdown report bo sung context cho finding

Day la moc GitHub hien dang bang voi `origin/main`.

## 4. Batch hien dang nam o working tree, chua commit

Sau `ba45234`, working tree hien tai dang co 3 cum cong viec lon:

### Cum A - reviewed bundle / rule workbench

- `scripts/build_rule_review_bundle.py`
- `scripts/compare_reviewed_bundle_scan.py`
- `scripts/export_normalized_rules_legacy.py`
- `scripts/validate_normalized_rule.py`
- `scripts/run_rule_workbench.py`
- `aegis_sast/rule_workbench/`
- dataset synthetic va benchmark reviewed bundle
- docs 37 -> 48

### Cum B - SQLi regression fix o Python matcher

- `aegis_sast/plugins/python_plugin.py`
- `tests/test_python_plugin.py`

Fix nay da duoc verify bang ket qua:

- compare SQLi: `default 5`, `reviewed 5`
- benchmark SQLi extension: `5 -> 5`, delta `0`

### Cum C - benchmark extension cho SQLi

- `scripts/run_benchmark_v1.py`
- `tests/test_run_benchmark_v1.py`
- `datasets/benchmark/reviewed_bundle_v1/cases_sql_injection_extension.json`
- `docs/thesis/48-benchmark-extension-sql-injection.md`

## 5. Cach khong bi sot context ve sau

Khi lam task moi, nen tu hoi 3 cau:

1. task nay thuoc subsystem nao:
   - detector
   - triage
   - rule ingestion
   - benchmark
   - workbench
2. subsystem do gan voi milestone commit nao trong file nay
3. code dang sua da nam tren remote hay moi chi nam o working tree

Neu tra loi duoc 3 cau nay, kha nang sot context se giam rat nhieu.

## 6. Chot ngan

Khong can doc lai moi commit cu.

Can giu 2 lop context:

- **milestone commits da len remote**
- **batch chua commit trong working tree**

File nay dung de nhin nhanh ca 2 lop do truoc moi dot sua lon tiep theo.

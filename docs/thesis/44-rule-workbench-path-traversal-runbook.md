# Runbook Phase 2 cho Rule Workbench V1 - PATH_TRAVERSAL

## 1. Muc dich

File nay lap lai flow `COMMAND_INJECTION`, nhung cho family `PATH_TRAVERSAL`.

Scope van giu nho:

- chi `Python`
- chi reviewed bundle `PATH_TRAVERSAL`
- chi corpus demo nho
- chi muc tieu chung minh flow review bundle tiep tuc chay duoc o family thu 2

No chua phai benchmark.
No la moc chuyen tu "1 family chay duoc" sang "review flow co the lap lai".

## 2. Dau vao can co

Can co 3 thu:

1. seed fixture:
   - `datasets/synthetic/rule_review_v1/seed_inputs/python_path_traversal_semgrep_shape.yaml`
2. reviewed bundle flow:
   - `scripts/build_rule_review_bundle.py`
3. scan comparison flow:
   - `scripts/compare_reviewed_bundle_scan.py`

Corpus nho mac dinh de smoke:

- `examples/vulnerable_path_traversal.py`

## 3. Cach chay theo CLI

### Buoc 1 - Build reviewed bundle

```powershell
python scripts/build_rule_review_bundle.py `
  datasets/synthetic/rule_review_v1/seed_inputs/python_path_traversal_semgrep_shape.yaml `
  --output-dir reports/rule_review/path_traversal_seed `
  --language python `
  --family PATH_TRAVERSAL `
  --profile python-rule-workbench-v1 `
  --provenance-source manual-semgrep-fixture `
  --snapshot-version local-seed-v1 `
  --normalized-format json `
  --validation-format json `
  --legacy-format yaml
```

Artifact can thay:

- `*.normalized.json`
- `*.validation.json`
- `*.legacy.yaml`
- `*.legacy.report.json`

### Buoc 2 - Compare default rules voi reviewed bundle

```powershell
python scripts/compare_reviewed_bundle_scan.py `
  examples/vulnerable_path_traversal.py `
  --reviewed-rules reports/rule_review/path_traversal_seed/python_path_traversal_semgrep_shape.legacy.yaml `
  --format json `
  --format markdown
```

Artifact can thay:

- `reports/rule_review_smoke/<run>/default_scan/...json`
- `reports/rule_review_smoke/<run>/reviewed_scan/...json`
- `reports/rule_review_smoke/<run>/comparison_summary.json`

## 4. Cach doc ket qua

Muc tieu cua Phase 2 khong phai la "bao duoc moi path API".
Muc tieu la:

- reviewed bundle co tap trung hon vao sink truy cap tep that su khong;
- reviewed bundle co bot on hon default path rules khong;
- output co giup tach `path construction` khoi `file access sink` ro hon khong.

Can nhin dac biet vao:

1. `finding_delta`
2. `unique_delta`
3. `by_type_delta`
4. `by_sink_pattern_delta`

## 5. Khac biet mong doi so voi default rules

Default Python rules hien tai con co mot so sink path traversal kha rong nhu:

- `open(`
- `os.path.join(`
- `pathlib.Path(`

Reviewed bundle nay chu dong focus vao sink truy cap tep/deletion/listing gan hon:

- `send_file(`
- `open(`
- `os.remove(`
- `os.listdir(`

Y nghia:

- de review signal hon;
- de giam viec coi moi path construction deu la finding hoan chinh;
- va hop hon voi huong benchmark reviewed bundles.

## 6. Push gate cho PATH_TRAVERSAL reviewed bundle

Co the xem la on neu:

1. bundle build on dinh qua CLI;
2. validation report khong co error;
3. legacy bridge export du 4 sink reviewed;
4. compare scan chay ra `comparison_summary.json`;
5. artifact path ro rang de demo lai duoc.

## 7. Buoc tiep theo sau runbook nay

Sau khi `PATH_TRAVERSAL` on, thu tu tiep theo nen la:

1. lap lai flow cho `INSECURE_DESERIALIZATION`
2. gom 3 family thanh benchmark mini
3. so sanh:
   - `Aegis core`
   - `reviewed bundle`
   - `reviewed bundle + triage`
   - `Semgrep baseline`

## 8. Ket luan ngan

Runbook nay quan trong vi no chung minh:

- Rule Workbench V1 khong chi chay duoc 1 family;
- reviewed bundle flow co the lap lai co kiem soat;
- va benchmark mini sau nay se co it nhat 2 family that de doi chieu.

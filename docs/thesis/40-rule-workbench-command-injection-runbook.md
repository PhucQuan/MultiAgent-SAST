# Runbook Phase 1 cho Rule Workbench V1 - COMMAND_INJECTION

## 1. Muc dich

File nay chot luong chay that dau tien sau khi repo da co:

- reviewed bundle flow;
- legacy bridge;
- va web Rule Workbench V1.

Scope cua runbook nay rat nho:

- chi `Python`;
- chi family `COMMAND_INJECTION`;
- chi corpus nho;
- chi muc tieu chung minh flow chay duoc end-to-end.

No khong phai benchmark day du.
No la moc "Phase 1 van hanh that" trong file `39`.

## 2. Dau vao can co

Can co 3 thu:

1. seed fixture:
   - `datasets/synthetic/rule_review_v1/seed_inputs/python_command_injection_semgrep_shape.yaml`
2. reviewed bundle flow:
   - `scripts/build_rule_review_bundle.py`
3. scan comparison flow:
   - `scripts/compare_reviewed_bundle_scan.py`

Corpus nho mac dinh de smoke:

- `examples/vulnerable_rce.py`

## 3. Cach chay theo CLI

### Buoc 1 - Build reviewed bundle

```powershell
python scripts/build_rule_review_bundle.py `
  datasets/synthetic/rule_review_v1/seed_inputs/python_command_injection_semgrep_shape.yaml `
  --output-dir reports/rule_review/command_injection_seed `
  --language python `
  --family COMMAND_INJECTION `
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
  examples/vulnerable_rce.py `
  --reviewed-rules reports/rule_review/command_injection_seed/python_command_injection_semgrep_shape.legacy.yaml `
  --format json `
  --format markdown
```

Artifact can thay:

- `reports/rule_review_smoke/<run>/default_scan/...json`
- `reports/rule_review_smoke/<run>/reviewed_scan/...json`
- `reports/rule_review_smoke/<run>/comparison_summary.json`

## 4. Cach chay theo web

### Buoc 1 - Mo Rule Workbench

```powershell
python scripts/run_rule_workbench.py --port 8765
```

Mo:

- `http://127.0.0.1:8765`

### Buoc 2 - Build reviewed bundle trong web

Chon seed input:

- `datasets/synthetic/rule_review_v1/seed_inputs/python_command_injection_semgrep_shape.yaml`

Gia tri goi y:

- language: `python`
- family: `COMMAND_INJECTION`
- profile: `python-rule-workbench-v1`
- provenance source: `manual-semgrep-fixture`
- snapshot version: `local-seed-v1`
- legacy bridge: `yaml`

Sau khi build xong:

- preview normalized output
- preview validation report
- preview legacy bridge

### Buoc 3 - Quay lai CLI de compare scan

Web V1 chua auto-scan.
Buoc compare van nen chay bang:

- `scripts/compare_reviewed_bundle_scan.py`

## 5. Cach doc ket qua

Muc tieu cua Phase 1 khong phai la "tim nhieu finding hon".
Muc tieu la:

- reviewed bundle it on hon default rules hay khong;
- finding co tap trung dung family hon hay khong;
- mismatch source pattern co giam hay khong.

Trong `comparison_summary.json`, can nhin 3 cum:

1. `default`
   - tong finding
   - duplicate delta
   - mismatch count
2. `reviewed`
   - tong finding
   - duplicate delta
   - mismatch count
3. `comparison`
   - `finding_delta`
   - `unique_delta`
   - `by_type_delta`
   - `by_sink_pattern_delta`

## 6. Push gate cho Phase 1

Co the xem la on de push neu dat duoc:

1. build reviewed bundle on dinh qua CLI;
2. web preview doc duoc artifact;
3. compare script chay ra `comparison_summary.json`;
4. reviewed bundle scan ra finding gon hon hoac dung family hon default rules;
5. artifact path ro va co the demo lai duoc.

## 7. Thu can luu lai cho bao cao

Nen luu:

- 1 screenshot web Rule Workbench;
- 1 screenshot terminal build bundle;
- 1 screenshot terminal compare scan;
- 1 ban `comparison_summary.json`;
- 1 note ngan:
  - default rules ra bao nhieu finding
  - reviewed bundle ra bao nhieu finding
  - giam duoc nhom nao

## 8. Buoc tiep theo sau runbook nay

Sau khi `COMMAND_INJECTION` on, thu tu tiep theo la:

1. lap lai flow cho `PATH_TRAVERSAL`
2. lap lai flow cho `INSECURE_DESERIALIZATION`
3. gom 3 family thanh benchmark mini
4. sau do moi them phase `noi bang loi -> AI draft rule`

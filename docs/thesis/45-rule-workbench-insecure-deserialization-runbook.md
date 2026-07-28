# Runbook Phase 2 cho Rule Workbench V1 - INSECURE_DESERIALIZATION

## 1. Muc dich

File nay hoan tat family thu 3 trong scope reviewed bundles V1:

- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`

Scope van giu nho:

- chi `Python`
- chi reviewed bundle `INSECURE_DESERIALIZATION`
- chi corpus demo nho
- chi muc tieu chot du 3 family reviewed bundles de sang benchmark mini

## 2. Dau vao can co

Can co 3 thu:

1. seed fixture:
   - `datasets/synthetic/rule_review_v1/seed_inputs/python_insecure_deserialization_semgrep_shape.yaml`
2. reviewed bundle flow:
   - `scripts/build_rule_review_bundle.py`
3. scan comparison flow:
   - `scripts/compare_reviewed_bundle_scan.py`

Corpus nho mac dinh de smoke:

- `examples/vulnerable_deserialization.py`

## 3. Cach chay theo CLI

### Buoc 1 - Build reviewed bundle

```powershell
python scripts/build_rule_review_bundle.py `
  datasets/synthetic/rule_review_v1/seed_inputs/python_insecure_deserialization_semgrep_shape.yaml `
  --output-dir reports/rule_review/insecure_deserialization_seed `
  --language python `
  --family INSECURE_DESERIALIZATION `
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
  examples/vulnerable_deserialization.py `
  --reviewed-rules reports/rule_review/insecure_deserialization_seed/python_insecure_deserialization_semgrep_shape.legacy.yaml `
  --format json `
  --format markdown
```

## 4. Cach doc ket qua

Muc tieu cua Phase nay la:

- reviewed bundle co tap trung dung vao deserialization sinks khong;
- reviewed bundle co giu ro `pickle.loads`, `yaml.unsafe_load`, `yaml.load` khong;
- safe case `yaml.safe_load` co tranh bi keo vao finding khong.

Can nhin dac biet vao:

1. `by_sink_pattern`
2. `by_type_delta`
3. `mismatch_count`
4. `added_keys` / `removed_keys`

## 5. Khac biet mong doi so voi default rules

Family nay khac `PATH_TRAVERSAL` o cho sink da tuong doi ro ngay tu dau.
Vi vay reviewed bundle nay khong nham "doi sang sink khac", ma nham:

- dong goi reviewed set nho, ro provenance;
- tach `yaml.safe_load` thanh reviewed sanitizer;
- va chot du 3 family V1 cho benchmark mini.

## 6. Push gate cho INSECURE_DESERIALIZATION reviewed bundle

Co the xem la on neu:

1. bundle build on dinh qua CLI;
2. validation report khong co error;
3. legacy bridge export du 3 sink reviewed;
4. compare scan chay ra `comparison_summary.json`;
5. safe case `yaml.safe_load` khong lam tang finding vo ly.

## 7. Buoc tiep theo sau runbook nay

Sau khi family nay on, Phase reviewed bundles V1 co the xem la da du.
Buoc tiep theo nen la:

1. gom 3 family thanh benchmark mini
2. so sanh:
   - `Aegis core`
   - `reviewed bundle`
   - `reviewed bundle + triage`
   - `Semgrep baseline`
3. viet note error analysis cho top miss/FP patterns

## 8. Ket luan ngan

Runbook nay danh dau moc:

- reviewed bundle flow da lap lai duoc tren 3 family Python V1;
- workbench/validator/legacy bridge da co artifact that cho benchmark;
- va roadmap co the chuyen tu `rule authoring flow` sang `benchmark mini`.

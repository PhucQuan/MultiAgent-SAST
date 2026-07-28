# Rule Workbench Extension - SQL_INJECTION

## 1. Muc dich

Sau khi da chot 3 reviewed bundles V1:

- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`

family hop ly tiep theo de mo rong la `SQL_INJECTION`.

Day la family mo rong sau V1 strict scope, khong phai mot phan cua profile `python-rule-workbench-v1` goc.

## 2. Vi sao chon SQL_INJECTION tiep theo

`SQL_INJECTION` hop voi Aegis vi:

- van la bai toan source -> sink -> evidence rat ro;
- co knowledge card san;
- co example `examples/vulnerable_sqli.py`;
- va rat de noi vao phan benchmark sau nay.

No cung la mot trong nhung family de bao cao/khoa luan de hieu nhat.

## 3. Seed fixture da them

Fixture moi:

- `datasets/synthetic/rule_review_v1/seed_inputs/python_sql_injection_semgrep_shape.yaml`

Scope reviewed sink hien tai:

- `execute(...)`
- `executemany(...)`
- `raw(...)`

Scope reviewed sanitizer hien tai:

- `int(...)`
- `float(...)`

## 4. Vi sao dung `execute(...)` thay vi `.execute(`

Default rules cu dung pattern kieu:

- `.execute(`

Reviewed SQLi seed nay dung pattern callable suffix:

- `execute(...)`

Y nghia:

- de legacy bridge xuat ra `execute(`;
- plugin Python co the match cac call kieu `cursor.execute(...)`, `conn.execute(...)`;
- va khong phu thuoc vao substring pattern loang hon.

## 5. Cach build reviewed bundle

Vi SQLi la extension sau V1 strict scope, nen tam thoi dung profile `generic` thay vi `python-rule-workbench-v1`.

```powershell
python scripts/build_rule_review_bundle.py `
  datasets/synthetic/rule_review_v1/seed_inputs/python_sql_injection_semgrep_shape.yaml `
  --output-dir reports/rule_review/sql_injection_seed `
  --language python `
  --family SQL_INJECTION `
  --profile generic `
  --provenance-source manual-semgrep-fixture `
  --snapshot-version local-seed-v1 `
  --normalized-format json `
  --validation-format json `
  --legacy-format yaml
```

## 6. Cach compare voi default rules

```powershell
python scripts/compare_reviewed_bundle_scan.py `
  examples/vulnerable_sqli.py `
  --reviewed-rules reports/rule_review/sql_injection_seed/python_sql_injection_semgrep_shape.legacy.yaml `
  --format json `
  --format markdown
```

## 7. Cach doc ket qua

Muc tieu cua extension nay khong nhat thiet la giam finding ngay.
Can nhin 3 y:

1. reviewed bundle co giu execute-family sink coverage khong;
2. reviewed bundle co cho artifact/provenance ro hon khong;
3. safe case parameterized query co van bi flag khong.

Neu safe case van bi flag, do la signal cho phase triage/evidence sau, khong phai ly do de bo reviewed bundle flow.

## 8. Ket luan ngan

SQLi la family mo rong dep nhat sau 3 family V1 vi:

- sat voi core scanner;
- de benchmark;
- de giai thich trong khoa luan;
- va mo duong cho `SSRF` hoac `XSS` sau do.

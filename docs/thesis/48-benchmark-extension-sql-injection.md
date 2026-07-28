# Benchmark Extension cho SQL_INJECTION

## 1. Muc dich

Sau khi fix xong regression `cursor.execute(...)` o default Python scanner, can co mot artifact benchmark nho de:

- chay lai SQLi mot cach on dinh;
- khong pha benchmark V1 strict 3 family;
- va de minh chung rang default scanner da bat kip reviewed bundle o execute-family sinks.

Vi vay, benchmark SQLi duoc dat thanh **extension benchmark** rieng.

## 2. Manifest moi

Manifest moi nam o:

- `datasets/benchmark/reviewed_bundle_v1/cases_sql_injection_extension.json`

Case duy nhat hien tai:

- `python-sql-injection-extension`

Target:

- `examples/vulnerable_sqli.py`

Reviewed rules:

- `reports/rule_review/sql_injection_seed/python_sql_injection_semgrep_shape.legacy.yaml`

## 3. Cach chay

```powershell
python scripts/run_benchmark_v1.py `
  --manifest datasets/benchmark/reviewed_bundle_v1/cases_sql_injection_extension.json
```

Neu chi muon chay dung case SQLi extension:

```powershell
python scripts/run_benchmark_v1.py `
  --manifest datasets/benchmark/reviewed_bundle_v1/cases_sql_injection_extension.json `
  --case python-sql-injection-extension
```

## 4. Cach doc ket qua

Moc mong doi sau khi da fix matcher:

- `default findings` va `reviewed findings` can bang nhau tren example SQLi nay;
- `unique sink delta` nen bang `0`;
- `mismatch delta` nen bang `0`.

Neu ket qua nay giu on dinh qua nhieu lan rerun, co the xem SQLi da san sang cho:

- dua vao bang benchmark tong hop cua khoa luan nhu mot **extension family**;
- hoac lam moc truoc khi mo sang `SSRF` / `XSS`.

## 5. Y nghia doi voi roadmap

Buoc nay quan trong vi no chot duoc 2 dieu:

1. core scanner da khong bi lech so voi reviewed SQLi bundle nua;
2. reviewed bundle flow khong chi dung de "giam finding", ma con de kiem chung va chuan hoa sink coverage.

No cung giu scope sach:

- benchmark V1 strict van la 3 family goc;
- SQLi duoc bao cao thanh extension sau V1, dung voi roadmap da chot truoc do.

# Benchmark Extension cho SSRF

## 1. Muc dich

Sau khi da co reviewed SSRF bundle va example rieng `vulnerable_ssrf.py`, can co mot benchmark manifest nho de:

- chay lai SSRF on dinh;
- giu benchmark V1 strict 3 family nguyen ven;
- va do duoc do lech giua `default` voi `reviewed bundle` tren 1 corpus SSRF ro rang.

Vi vay, SSRF duoc dat thanh **extension benchmark** rieng, giong SQLi.

## 2. Manifest moi

Manifest moi nam o:

- `datasets/benchmark/reviewed_bundle_v1/cases_ssrf_extension.json`

Case duy nhat hien tai:

- `python-ssrf-extension`

Target:

- `examples/vulnerable_ssrf.py`

Reviewed rules:

- `reports/rule_review/ssrf_seed/python_ssrf_semgrep_shape.legacy.yaml`

## 3. Cach chay

```powershell
python scripts/run_benchmark_v1.py `
  --manifest datasets/benchmark/reviewed_bundle_v1/cases_ssrf_extension.json
```

Neu chi muon chay dung case SSRF extension:

```powershell
python scripts/run_benchmark_v1.py `
  --manifest datasets/benchmark/reviewed_bundle_v1/cases_ssrf_extension.json `
  --case python-ssrf-extension
```

## 4. Cach doc ket qua

Moc mong doi cho extension nay la:

- `default findings` va `reviewed findings` bang nhau hoac rat gan nhau;
- `unique sink delta` khong tang vo ly;
- `mismatch delta` bang `0`.

Neu ket qua giu on dinh, co the xem SSRF da san sang cho:

- them vao bang benchmark mo rong cua khoa luan;
- hoac dung lam moc truoc khi sang family `XSS`.

## 5. Y nghia doi voi roadmap

Buoc nay giup chot 2 dieu:

1. reviewed bundle flow da mo rong duoc them 1 family network-oriented, khong chi file/db/command;
2. benchmark extension khong con phu thuoc vao mot minh SQLi nua.

No cung giu scope dep:

- benchmark V1 strict van la 3 family goc;
- SQLi va SSRF duoc bao cao thanh extension families sau V1.

# Mini Benchmark cho Reviewed Bundles V1

## 1. Muc dich

Sau khi da co 3 reviewed bundles V1:

- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`

buoc tiep theo hop ly nhat la gom chung vao mot benchmark mini co the chay lai duoc.

File nay chot benchmark mini giai doan dau:

- chi benchmark `Aegis default` vs `Aegis reviewed bundle`
- chi tren 3 example Python nho
- chua tich hop Semgrep baseline vao script nay

Y nghia:

- co artifact tong hop co so lieu that;
- co moc de viet bao cao thuc nghiem so bo;
- va co diem dat chan truoc khi noi them Semgrep baseline.

## 2. Dau vao can co

Can co 3 reviewed rule bundles da build xong:

1. `reports/rule_review/command_injection_seed/python_command_injection_semgrep_shape.legacy.yaml`
2. `reports/rule_review/path_traversal_seed/python_path_traversal_semgrep_shape.legacy.yaml`
3. `reports/rule_review/insecure_deserialization_seed/python_insecure_deserialization_semgrep_shape.legacy.yaml`

Can co 3 target demo:

1. `examples/vulnerable_rce.py`
2. `examples/vulnerable_path_traversal.py`
3. `examples/vulnerable_deserialization.py`

Manifest mac dinh nam o:

- `datasets/benchmark/reviewed_bundle_v1/cases.json`

## 3. Script benchmark moi

Script benchmark:

- `scripts/run_benchmark_v1.py`

No se:

1. doc manifest case benchmark;
2. chay `default scan` cho tung case;
3. chay `reviewed bundle scan` cho tung case;
4. luu lai `comparison_summary.json` cho tung case;
5. gom lai thanh:
   - `benchmark_summary.json`
   - `benchmark_summary.md`

## 4. Cach chay

### Chay full 3 case

```powershell
python scripts/run_benchmark_v1.py
```

### Chay 1 case rieng

```powershell
python scripts/run_benchmark_v1.py --case python-path-traversal
```

### Chon output dir rieng

```powershell
python scripts/run_benchmark_v1.py `
  --output-dir reports/benchmark/reviewed_bundle_v1/manual_run
```

## 5. Artifact mong doi

Script se tao:

- `reports/benchmark/reviewed_bundle_v1/<timestamp>/benchmark_summary.json`
- `reports/benchmark/reviewed_bundle_v1/<timestamp>/benchmark_summary.md`
- `reports/benchmark/reviewed_bundle_v1/<timestamp>/<case_id>/comparison_summary.json`

Moi case van giu lai:

- `default_scan/...`
- `reviewed_scan/...`

de sau nay con mo lai report goc khi can viet error analysis.

## 6. Cach doc ket qua

Can nhin 2 lop:

### Lop tong hop

- tong findings `default -> reviewed`
- tong `unique_delta`
- tong `mismatch_delta`

### Lop tung case

- case nao giam finding
- case nao giu nguyen
- case nao tang finding vi reviewed bundle bat sink that hon

Vi du:

- `COMMAND_INJECTION` co the giam finding neu reviewed bundle bo bot sink on;
- `PATH_TRAVERSAL` co the tang finding neu reviewed bundle doi tu `os.path.join(` sang `send_file(` / `os.listdir(`;
- `INSECURE_DESERIALIZATION` co the giu nguyen finding vi sink da ro san.

## 7. Gioi han hien tai

Script nay chua co:

- precision / recall / F1 that su
- Semgrep baseline tu dong
- ground truth labels

No moi la benchmark mini de tong hop:

- `default vs reviewed`
- tren corpus nho
- va de chot phase reviewed bundles

## 8. Buoc tiep theo sau benchmark mini nay

Sau khi script nay chay on, buoc tiep theo la:

1. them ground truth labels cho 3 case nho;
2. them slot `Semgrep baseline` mot cach co kiem soat;
3. tach ro:
   - `reviewed bundle only`
   - `reviewed bundle + triage`
4. viet error analysis cho top miss/FP patterns.

## 9. Ket luan ngan

Script benchmark nay danh dau moc:

- reviewed bundles khong con la artifact roi rac;
- team da co mot benchmark runner nho de chay lai duoc;
- va roadmap co the chuyen sang phase do tac dong cua reviewed bundles mot cach co he thong hon.

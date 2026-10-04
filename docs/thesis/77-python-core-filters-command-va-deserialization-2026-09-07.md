# Python core filters command va deserialization ngay 2026-09-07

## 1. Muc tieu

Sau patch `query_string + multiline sink span`, core Python 4-family da dat:

- `all = TP 101 / FP 11 / FN 0 / F1 0.9484`
- `visible = TP 101 / FP 1 / FN 0 / F1 0.9951`
- `high-confidence = TP 88 / FP 1 / FN 13 / F1 0.9263`

FP con lai tap trung vao 2 cum ro rang:

- `INSECURE_DESERIALIZATION`: 7 FP
- `COMMAND_INJECTION`: 4 FP

Dot nay chi lam them 2 filter nho o tang detector cho Python, khong sua triage heuristic.

## 2. File da sua

- `aegis_sast/analysis/python_deserialization_filter.py`
- `aegis_sast/analysis/python_command_injection_filter.py`
- `aegis_sast/analysis/vulnerability_detector.py`
- `tests/test_taint_analysis.py`

## 3. Filter deserialization

Filter moi cho `INSECURE_DESERIALIZATION` tai dung abstract execution dang co o lane Python de xem payload dua vao sink co thuc su con taint hay da tro thanh gia tri safe.

Pattern duoc suppress o tang core:

- `ifexp` constant chon nhanh safe
- `if` constant chon nhanh safe
- `match/case` constant chon nhanh safe
- dict overwrite ve key safe
- list shift roi chon slot safe

Patch nay co them regression giu TP cho cac case tung bi hu khi thu heuristic o triage:

- `BenchmarkTest00510`
- `BenchmarkTest00827`

## 4. Filter command injection

Filter moi cho `COMMAND_INJECTION` cung di theo huong detector-level, nhung danh gia argument thuc su dua vao shell/subprocess thay vi chi nhin thay luong taint da tung cham toi bien trung gian.

Patch nay xu ly duoc 2 pattern FP con lai:

- dict overwrite tra ve gia tri safe truoc khi build command
- `ConfigParser.get()` doc option safe truoc khi build command

## 5. Test da chay

```powershell
python -m pytest tests/test_taint_analysis.py -k "command_injection or deserialization" -q
python -m pytest tests/test_python_plugin.py tests/test_cross_file.py tests/test_detector_rule_propagation.py tests/test_repo_intake.py tests/test_python_flow_graph.py tests/test_orchestration_nodes.py -q
```

Ket qua:

- `9 passed, 20 deselected`
- `81 passed`

## 6. Spot-check tren benchmark that

Case FP muc tieu sau patch:

- `BenchmarkTest00349.py` -> khong con finding
- `BenchmarkTest00508.py` -> khong con finding
- `BenchmarkTest00513.py` -> khong con finding
- `BenchmarkTest00608.py` -> khong con finding
- `BenchmarkTest00658.py` -> khong con finding
- `BenchmarkTest00826.py` -> khong con finding
- `BenchmarkTest00995.py` -> khong con finding
- `BenchmarkTest00350.py` -> khong con finding
- `BenchmarkTest00512.py` -> khong con finding
- `BenchmarkTest00736.py` -> khong con finding
- `BenchmarkTest00900.py` -> khong con finding

TP guard sau patch:

- `BenchmarkTest00510.py` -> van con `INSECURE_DESERIALIZATION`
- `BenchmarkTest00827.py` -> van con `INSECURE_DESERIALIZATION`

## 7. Benchmark full moi nhat

### 7.1. Lenh da chay

```powershell
python -m aegis_sast.cli scan "D:\BenchmarkPython\testcode" `
  --no-ai `
  -o json `
  --output-dir "reports/manual_targets/benchmark_python_current_core_20260907_cmdi_deser_filters"
```

```powershell
python scripts/score_owasp_benchmark.py `
  --report "reports/manual_targets/benchmark_python_current_core_20260907_cmdi_deser_filters/aegis_sast_report_20260907_170334.json" `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --family COMMAND_INJECTION `
  --family PATH_TRAVERSAL `
  --family INSECURE_DESERIALIZATION `
  --family SQL_INJECTION `
  --output-dir "reports/benchmark/owasp/benchmark_python_current_core_20260907_cmdi_deser_filters_score4"
```

### 7.2. Ket qua chot

| Mode | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| all | 101 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| visible | 101 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| high-confidence | 88 | 0 | 13 | 1.0000 | 0.8713 | 0.9312 |

Per-family o mode `all`:

| Family | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| COMMAND_INJECTION | 13 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| PATH_TRAVERSAL | 65 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| INSECURE_DESERIALIZATION | 18 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| SQL_INJECTION | 5 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

Artifact tham chieu:

- report: `reports/manual_targets/benchmark_python_current_core_20260907_cmdi_deser_filters/aegis_sast_report_20260907_170334.json`
- score: `reports/benchmark/owasp/benchmark_python_current_core_20260907_cmdi_deser_filters_score4/owasp_score_summary.md`

## 8. Delta de doc nhanh

| Moc | all | visible | high-confidence |
|---|---|---|---|
| sau patch `query_string + multiline` | `101 / 11 / 0 / F1 0.9484` | `101 / 1 / 0 / F1 0.9951` | `88 / 1 / 13 / F1 0.9263` |
| sau filter deserialization | `101 / 4 / 0 / F1 0.9806` | `101 / 0 / 0 / F1 1.0000` | `88 / 0 / 13 / F1 0.9312` |
| sau filter command + deserialization | `101 / 0 / 0 / F1 1.0000` | `101 / 0 / 0 / F1 1.0000` | `88 / 0 / 13 / F1 0.9312` |

## 9. Con lai gi sau moc nay

Sau khi core 4-family da sach `all` va `visible`, bai toan con lai ro nhat khong con la precision nua ma la:

- nang `high-confidence` PATH_TRAVERSAL

13 FN con lai o `high-confidence`:

- `BenchmarkTest00008`
- `BenchmarkTest00087`
- `BenchmarkTest00089`
- `BenchmarkTest00180`
- `BenchmarkTest00357`
- `BenchmarkTest00444`
- `BenchmarkTest00445`
- `BenchmarkTest00523`
- `BenchmarkTest00742`
- `BenchmarkTest00834`
- `BenchmarkTest00835`
- `BenchmarkTest00918`
- `BenchmarkTest01181`

## 10. Chot ngan

Tinh den ngay 2026-09-07, core Python 4-family cua Aegis-SAST da dat moc benchmark rat manh tren OWASP Benchmark:

- `all = 101/0/0`
- `visible = 101/0/0`

Tu diem nay tro di, huong hop ly nhat la giu nguyen precision hien co, khong mo them heuristic tho, va chi tap trung cai thien recall cho `high-confidence` PATH_TRAVERSAL.

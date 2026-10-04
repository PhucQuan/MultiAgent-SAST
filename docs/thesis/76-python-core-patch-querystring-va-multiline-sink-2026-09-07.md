# Python core patch querystring va multiline sink ngay 2026-09-07

## 1. Muc tieu cua dot nay

Sau khi rerun benchmark Python core 4-family trong file `75`, diem dau ro nhat con lai la:

- PATH_TRAVERSAL con `13 FN`
- INSECURE_DESERIALIZATION con `3 FN`
- nhieu case FN roi vao kieu:
  - lay input tu `request.query_string` roi tu parse bang tay
  - sink nam ben trong statement nhieu dong, dac biet la `Path.read_text()` nam trong f-string

Dot nay chot 1 patch nho nhung danh dung goc:

1. Them `request.query_string` vao tap source mac dinh cua Python.
2. Lam cho flow graph match sink theo span line cua statement, khong chi bang mot line bat dau.

## 2. File da sua

- `rules/python.yaml`
- `aegis_sast/analysis/python_flow_graph.py`
- `tests/test_python_plugin.py`
- `tests/test_taint_analysis.py`

## 3. Y nghia ky thuat cua patch

### 3.1. Source moi: `request.query_string`

Truoc patch, cac case benchmark kieu:

- `query_string = request.query_string.decode('utf-8')`
- `paramLoc = query_string.find(...)`
- `param = query_string[...]`
- `param = urllib.parse.unquote_plus(param)`

khong duoc coi la source taint ngay tu dau.

Sau patch, `request.query_string` duoc nhan la `HTTP_PARAM`, nen loat case manual-parse nay bat dau vao duong dataflow binh thuong.

### 3.2. Match sink theo span line cua statement

Truoc patch, `PythonDataflowAnalyzer._matching_sinks()` chi match sink neu:

- `sink.location.line_number == node.location.line_number`

Dieu nay lam hut cac sink nam ben trong statement nhieu dong, vi AST call co the nam o line 47 nhung graph node assignment bat dau tu line 45.

Sau patch, moi node flow giu them:

- `end_line_number`
- `end_column_number`

va sink duoc match neu line cua sink nam trong span:

- `start_line <= sink_line <= end_line`

Patch nay dac biet quan trong cho cac case:

- `Path.read_text()` trong f-string
- cac expression nhieu dong co nested call

## 4. Kiem tra nhanh sau patch

### 4.1. Test da chay

```powershell
python -m pytest tests/test_python_plugin.py -k request_query_string_counts_as_source -q
python -m pytest tests/test_taint_analysis.py -k "query_string_manual_parse or nested_path_read_text" -q
python -m pytest tests/test_python_plugin.py tests/test_cross_file.py tests/test_detector_rule_propagation.py tests/test_repo_intake.py tests/test_python_flow_graph.py -q
```

Trang thai:

- test source moi pass
- test nested sink moi pass
- lane phu tro Python pass `72 passed`

### 4.2. Spot-check benchmark files da tung truot

Sau patch, cac file dai dien sau da co finding dung:

- `BenchmarkTest00914.py` -> PATH_TRAVERSAL
- `BenchmarkTest00992.py` -> INSECURE_DESERIALIZATION
- `BenchmarkTest01214.py` -> PATH_TRAVERSAL

## 5. Benchmark full sau patch

### 5.1. Lenh da chay

```powershell
python -m aegis_sast.cli scan "D:\BenchmarkPython\testcode" `
  --no-ai `
  -o json `
  --output-dir "reports/manual_targets/benchmark_python_current_core_20260907_patch_querystring_multiline"
```

```powershell
python scripts/score_owasp_benchmark.py `
  --report "reports/manual_targets/benchmark_python_current_core_20260907_patch_querystring_multiline/aegis_sast_report_20260907_163939.json" `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --family COMMAND_INJECTION `
  --family PATH_TRAVERSAL `
  --family INSECURE_DESERIALIZATION `
  --family SQL_INJECTION `
  --output-dir "reports/benchmark/owasp/benchmark_python_current_core_20260907_patch_querystring_multiline_score4"
```

### 5.2. Ket qua truoc va sau

| Mode | Truoc patch | Sau patch |
|---|---|---|
| all | `TP=85, FP=10, FN=16, F1=0.8673` | `TP=101, FP=11, FN=0, F1=0.9484` |
| visible | `TP=85, FP=0, FN=16, F1=0.9140` | `TP=101, FP=1, FN=0, F1=0.9951` |
| high-confidence | `TP=73, FP=0, FN=28, F1=0.8391` | `TP=88, FP=1, FN=13, F1=0.9263` |

Delta de doc nhanh:

- `all`: `TP +16`, `FP +1`, `FN -16`, `F1 +0.0811`
- `visible`: `TP +16`, `FP +1`, `FN -16`, `F1 +0.0811`
- `high-confidence`: `TP +15`, `FP +1`, `FN -15`, `F1 +0.0872`

### 5.3. Per-family sau patch

| Family | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| COMMAND_INJECTION | 13 | 4 | 0 | 0.7647 | 1.0000 | 0.8667 |
| PATH_TRAVERSAL | 65 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| INSECURE_DESERIALIZATION | 18 | 7 | 0 | 0.7200 | 1.0000 | 0.8372 |
| SQL_INJECTION | 5 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

Ket luan quan trong:

1. PATH_TRAVERSAL core 4-family da duoc keo len `65/0/0`.
2. INSECURE_DESERIALIZATION da het `FN`, nhung van con FP.
3. Recall tong the core 4-family da len `1.0000`.

## 6. Tinh hinh con lai sau patch

Patch nay mo them tong cong `45` findings trong report full, nhung trong 4-family benchmark thi gia tri that la:

- lay lai duoc `16` TP truoc day bi mat
- tra gia bang `1` FP moi trong scope 4-family

FP con lai hien tai:

- `COMMAND_INJECTION`: `BenchmarkTest00350`, `00512`, `00736`, `00900`
- `INSECURE_DESERIALIZATION`: `BenchmarkTest00349`, `00508`, `00513`, `00608`, `00658`, `00826`, `00995`

FP `visible` con lai chi con:

- `BenchmarkTest00995`

Case nay la false positive kieu:

- input di qua `request.query_string`
- nhung bien `bar` cuoi cung chon nhanh constant-safe qua `ifexp`
- sink van la `yaml.load(bar, Loader=yaml.Loader)`

## 7. Ke hoach tiep theo nen lam ngay

### Uu tien 1

Lam mot deterministic filter hoac abstract-eval nhe cho `INSECURE_DESERIALIZATION`, de loai cac case:

- constant if-branch safe
- constant match/case safe
- list/dict shift de cuoi cung chon gia tri constant-safe

Neu lam duoc lane nay, kha nang cao se:

- dua `visible` tu `101/1/0` len `101/0/0`
- giam them FP o mode `all`

### Uu tien 2

Audit 4 FP `COMMAND_INJECTION` con lai.

Day la lane precision cuoi cung cua core 4-family, va se tac dong truc tiep len `all`.

### Uu tien 3

Rerun lai:

- `--reviewed-rule-profile semgrep-python-core4`
- benchmark 6-family

de xac nhan patch source/sink moi co gay drift khong o breadth lane.

## 8. Chot ngan

Patch `query_string + multiline sink span` la mot dot cai thien co tac dong that:

- khong chi pass test nho
- ma con nang benchmark full core 4-family len muc ro rang hon han

Tinh den ngay 2026-09-07, day la mot trong nhung patch co gia tri benchmark lon nhat cua lane Python gan day.

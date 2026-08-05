# Bao cao tong hop hien trang Aegis-SAST, benchmark, demo runbook, va huong tiep theo

## 1. Muc tieu cua file nay

File nay dong vai tro la bao cao tong hop duy nhat de:

1. tom tat chinh xac Aegis-SAST dang lam gi trong repo hien tai;
2. ghi lai nhung thanh phan da lam xong trong codebase;
3. tong hop ket qua benchmark da chay that;
4. huong dan demo bang CLI va dashboard de quay video/gui giang vien;
5. chot cac claim an toan cho luan van va cac huong phat trien tiep theo.

Muc tieu la de khi can bao cao, demo, hoac viet luan van, chi can mo file nay la du.

## 2. Aegis-SAST dang lam gi

Aegis-SAST hien tai la mot he thong SAST hybrid huong thesis/demo, trong do:

- detector chinh la scanner AST/rule/taint co tinh xac dinh;
- AI duoc dat o lop triage/explanation/remediation seed, khong thay the detector;
- he thong ho tro da ngon ngu qua plugin;
- ket qua duoc dua ve mot schema finding thong nhat de phuc vu report, dashboard, va benchmark.

Noi ngan gon: day khong con la mot script quet loi don le nua, ma da la mot scanner core co benchmark, co product layer, va co dinh huong multi-agent ro rang.

## 3. Kien truc hien tai, map truc tiep vao code

### 3.1. View tong quan

Kien truc hien tai cua repo da map kha sat voi huong muc tieu trong `docs/thesis/04-kien-truc-muc-tieu.md`:

1. `Repo Intake`
2. `Detection Core`
3. `Finding Normalization`
4. `Workflow Triage`
5. `AI Overlay`
6. `Reporting and Product Layer`
7. `Evaluation and Benchmark`

### 3.2. Mapping theo module that

| Lop chuc nang | File/chinh sua quan trong | Trang thai |
|---|---|---|
| Entry point CLI | `aegis_sast/cli.py` | da co, CLI dep va chay on |
| Orchestration service | `aegis_sast/orchestration/service.py` | da tach khoi CLI |
| Repo intake | `aegis_sast/orchestration/repo_intake.py` | da co profile/language/framework hints |
| Detection core | `aegis_sast/analysis/vulnerability_detector.py` | da co detector chinh |
| Rule engine | `aegis_sast/analysis/rule_engine.py` | da co rule resolution |
| Normalized models | `aegis_sast/core/models.py` | da co finding schema va vulnerability families |
| Python plugin | `aegis_sast/plugins/python_plugin.py` | la lane manh nhat hien tai |
| Java plugin | `aegis_sast/plugins/java_plugin.py` | da co, nhung chua manh bang Python |
| JavaScript plugin | `aegis_sast/plugins/javascript_plugin.py` | da co intra-file lane |
| Workflow triage | `aegis_sast/orchestration/workflow.py` | da co auditor/skeptic/judge flow |
| Deterministic triage | `aegis_sast/triage/engine.py` | da co schema/status co cau truc |
| AI triage runner | `aegis_sast/triage/ai_runner.py` | da noi vao pipeline |
| Gemini client | `aegis_sast/ai/gemini_client.py` | da co, phu thuoc quota/runtime |
| JSON report | `aegis_sast/reporting/json_exporter.py` | da co |
| Markdown report | `aegis_sast/reporting/markdown_exporter.py` | da co |
| SARIF export | `aegis_sast/integrations/sarif_formatter.py` | da co |
| Dashboard | `apps/findings-dashboard` | da co local UI doc report JSON |
| Benchmark scorer | `scripts/score_owasp_benchmark.py` | da co harness TP/FP/FN |
| Semgrep baseline | `scripts/run_semgrep_owasp_python.py` | da co baseline runner |

### 3.3. Dieu quan trong nhat ve boundary claim

Can noi ro de tranh bi hoi nguoc khi bao ve:

- Aegis khong ke thua Semgrep/Bandit/PMD de quet runtime lam detector chinh;
- detector runtime hien tai la engine rieng cua repo, dua tren plugin AST, rules, va taint analysis;
- Semgrep hien tai duoc dung o lop baseline benchmark/so sanh, khong phai dependency quet mac dinh cua pipeline Aegis.

Day la mot boundary rat quan trong de claim khong bi lech.

## 4. Nhung gi da lam duoc trong codebase

### 4.1. Scanner core

He thong da co mot scanner core hoat dong that:

- parse source code bang Tree-sitter;
- xac dinh source, sink, sanitizer;
- track dataflow trong pham vi file va sau hon cho Python;
- dedupe finding;
- gan severity;
- xuat report JSON/Markdown/SARIF.

### 4.2. Kien truc plugin da ngon ngu

Repo hien tai da co plugin cho:

- Python
- Java
- JavaScript
- PHP

Dieu nay co gia tri rat lon trong luan van vi no cho thay he thong duoc thiet ke theo huong mo rong, khong dong cung vao mot ngon ngu duy nhat.

### 4.3. Python deep lane la diem sang chinh

Python hien la lane tot nhat trong codebase vi:

- co phan tich sau hon cac ngon ngu con lai;
- co evidence tot nhat tren OWASP Benchmark Python;
- co kha nang bat manh o cac family taint/injection chinh.

Day la ly do claim benchmark chinh nen dat vao Python, thay vi co gang claim deu cho tat ca ngon ngu ngay luc nay.

### 4.4. Orchestration da tach khoi CLI

Phan scan pipeline da duoc tach khoi CLI va dua vao service rieng. Viec nay rat co gia tri ve kien truc vi:

- CLI chi con vai tro parse args + in ket qua;
- pipeline co the duoc goi lai tu dashboard, script, test, hoac sau nay la API;
- boundary giua detector va product layer ro rang hon.

### 4.5. Triage co cau truc

Repo hien tai khong chi scan ra finding thuan, ma da co:

- workflow triage auditor/skeptic/judge;
- triage status;
- metadata de phuc vu explanation;
- route summary va workflow summary trong report.

Day la nen rat hop ly de sau nay dua AI vao dung lop.

### 4.6. Product layer da co dashboard local

`apps/findings-dashboard` hien tai doc report JSON da xuat, khong can can thiep truc tiep vao detector internals.

Dashboard dang co nhung gia tri demo tot:

- report explorer;
- finding queue;
- detail pane;
- local reviewer memory/feedback;
- import report JSON;
- local run scan panel;
- hien scan progress/log trong giao dien.

### 4.7. Evaluation layer da co benchmark that

Repo da co:

- scorer TP/FP/FN dua tren ground truth CSV;
- mapping family cho OWASP Benchmark Python;
- Semgrep baseline runner de so sanh cong bang;
- artifact markdown/json de dua thang vao thesis.

## 5. Phuong phap giai quyet bai toan

Huong giai quyet hien tai cua Aegis la hybrid va thesis-safe:

1. Dung deterministic AST/rule/taint scanner lam detector chinh.
2. Dua tat ca ket qua ve schema finding thong nhat.
3. Chay workflow triage de phan loai finding thay vi bao thang finding thuan.
4. Dat AI o lop re-review/explanation/remediation seed.
5. Dung benchmark co ground truth de cham TP/FP/FN that.
6. So sanh voi Semgrep baseline tren cung dataset/cung harness.

Y nghia cua huong nay:

- khong overclaim rang LLM thay duoc dataflow engine;
- giai bai toan false positive va product UX tu lop tren;
- de thuyet phuc hoi dong hon so voi viec dua ra mot "AI scanner" chung chung.

## 6. Families hien co trong he thong

Trong `aegis_sast/core/models.py`, he thong da co nhieu vulnerability families hon 4 family benchmark chinh, bao gom:

- `SQL_INJECTION`
- `COMMAND_INJECTION`
- `CODE_INJECTION`
- `PATH_TRAVERSAL`
- `XPATH_INJECTION`
- `LDAP_INJECTION`
- `XXE`
- `SSRF`
- `XSS`
- `NOSQL_INJECTION`
- `IDOR`
- `SSTI`
- `INSECURE_DESERIALIZATION`
- `MASS_ASSIGNMENT`
- `OPEN_REDIRECT`

Tuy nhien, co support trong model/rule khong dong nghia voi da co benchmark claim that. Trong luan van can tach ro:

- family da benchmark compare that;
- family co support trong code nhung chua benchmark-ready;
- family la future work.

## 7. Phuong phap benchmark da chot

### 7.1. Nguyen tac fairness

Benchmark Python duoc chot theo 4 nguyen tac:

1. cung dataset: `D:\BenchmarkPython\testcode`
2. cung ground truth: `D:\BenchmarkPython\expectedresults-0.1.csv`
3. cung scoring harness: `scripts/score_owasp_benchmark.py`
4. cung family selection giua Aegis va Semgrep

Vi vay, bang so sanh hien tai co gia tri hoc thuat hon viec dem finding tren mot repo that nhu PyTorch.

### 7.2. Scope benchmark chinh

Scope benchmark chinh cho thesis V1 la 4 family:

- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`
- `SQL_INJECTION`

Ly do chon:

- day la nhom taint/injection hop voi detector hien tai;
- Aegis co evidence coverage tot nhat o day;
- baseline Semgrep da duoc doi chieu sach;
- phu hop voi dinh huong false-positive filtering va triage.

### 7.3. Scope breadth mo rong

Ngoai 4 family chinh, benchmark Python da mo rong them 2 family:

- `CODE_INJECTION`
- `OPEN_REDIRECT`

Scope nay khong nen che mo scope chinh, nhung rat co gia tri de cho thay breadth cua scanner.

## 8. Ket qua benchmark Python

### 8.1. Scope A: 4 family chinh

Artifact:

- Aegis report: `D:\AegisBenchmarkArtifacts\BenchmarkPython_core\aegis_sast_report_20260805_161754.json`
- Aegis score: `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_score\owasp_score_summary.md`
- Semgrep score: `reports/benchmark/semgrep_owasp_python/BenchmarkPython_thesis_v1_semgrep_20260805\owasp_score_summary.md`

#### Aggregate

| He thong | TP | FP | FN | Precision | Recall | F1 | Runtime (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Aegis core | 85 | 56 | 16 | 0.6028 | 0.8416 | 0.7025 | 20.30 |
| Semgrep baseline | 27 | 14 | 74 | 0.6585 | 0.2673 | 0.3803 | 21.23 |

#### Theo tung family

| Family | Expected TP cases | Aegis TP | Aegis FP | Aegis FN | Aegis Recall | Aegis F1 | Semgrep TP | Semgrep FP | Semgrep FN | Semgrep Recall | Semgrep F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| COMMAND_INJECTION | 13 | 13 | 4 | 0 | 1.0000 | 0.8667 | 2 | 0 | 11 | 0.1538 | 0.2667 |
| PATH_TRAVERSAL | 65 | 52 | 46 | 13 | 0.8000 | 0.6380 | 2 | 2 | 63 | 0.0308 | 0.0580 |
| INSECURE_DESERIALIZATION | 18 | 15 | 6 | 3 | 0.8333 | 0.7692 | 18 | 12 | 0 | 1.0000 | 0.7500 |
| SQL_INJECTION | 5 | 5 | 0 | 0 | 1.0000 | 1.0000 | 5 | 0 | 0 | 1.0000 | 1.0000 |

#### Phan tich ngan

- Aegis dan truoc Semgrep ro rang ve recall tong the va F1 tong the.
- Semgrep giu precision tong the cao hon mot chut.
- `COMMAND_INJECTION`, `PATH_TRAVERSAL`, va `SQL_INJECTION` la diem manh ro cua Aegis trong Python lane.
- `PATH_TRAVERSAL` van la diem dau lon nhat vi FP con cao.

Neu can mot cau ket ngan de dua thang vao slide/bao cao:

`Tren OWASP Benchmark Python voi 4 family muc tieu, Aegis core vuot Semgrep community baseline ve recall va F1, trong khi Semgrep nhinh hon mot chut ve precision tong the.`

### 8.2. Scope B: mo rong thanh 6 family

Artifact:

- Aegis score 6 family: `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_score_6fam\owasp_score_summary.md`
- Semgrep score 6 family: `D:\AegisBenchmarkArtifacts\BenchmarkPython_semgrep_6fam\owasp_score_summary.md`

#### Aggregate

| He thong | TP | FP | FN | Precision | Recall | F1 | Runtime (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Aegis core | 107 | 83 | 27 | 0.5632 | 0.7985 | 0.6605 | 20.30 |
| Semgrep baseline | 48 | 48 | 86 | 0.5000 | 0.3582 | 0.4174 | 52.81 |

#### Theo tung family

| Family | Expected TP cases | Aegis TP | Aegis FP | Aegis FN | Aegis Recall | Aegis F1 | Semgrep TP | Semgrep FP | Semgrep FN | Semgrep Recall | Semgrep F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| COMMAND_INJECTION | 13 | 13 | 4 | 0 | 1.0000 | 0.8667 | 2 | 0 | 11 | 0.1538 | 0.2667 |
| PATH_TRAVERSAL | 65 | 52 | 46 | 13 | 0.8000 | 0.6380 | 2 | 2 | 63 | 0.0308 | 0.0580 |
| INSECURE_DESERIALIZATION | 18 | 15 | 6 | 3 | 0.8333 | 0.7692 | 18 | 12 | 0 | 1.0000 | 0.7500 |
| SQL_INJECTION | 5 | 5 | 0 | 0 | 1.0000 | 1.0000 | 5 | 0 | 0 | 1.0000 | 1.0000 |
| CODE_INJECTION | 20 | 10 | 13 | 10 | 0.5000 | 0.4651 | 20 | 33 | 0 | 1.0000 | 0.5479 |
| OPEN_REDIRECT | 13 | 12 | 14 | 1 | 0.9231 | 0.6154 | 1 | 1 | 12 | 0.0769 | 0.1333 |

#### Phan tich ngan

- Khi mo rong scope, Aegis van dan truoc Semgrep ve tong recall va tong F1.
- `OPEN_REDIRECT` la diem sang moi cua Aegis trong Python lane.
- `CODE_INJECTION` cho thay breadth tang thi can bang FP cung kho hon.
- Scope 6 family rat hop de dua vao phan "mo rong" hoac "breadth analysis" cua bao cao.

## 9. Java benchmark snapshot

Artifact:

- Aegis Java score: `D:\AegisBenchmarkArtifacts\BenchmarkJava_aegis_score_20260805\owasp_score_summary.md`
- Semgrep Java score: `D:\AegisBenchmarkArtifacts\BenchmarkJava_thesis_v1_semgrep_20260805\owasp_score_summary.md`

Tong hop hien tai:

| He thong | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Aegis core | 211 | 154 | 320 | 0.5781 | 0.3974 | 0.4710 |
| Semgrep baseline | 490 | 385 | 41 | 0.5600 | 0.9228 | 0.6970 |

Y nghia:

- Java da co benchmark that, khong con la "se lam sau" tren giay.
- Tuy nhien, Java hien tai van thua baseline community kha xa.
- Vi vay, Java nen duoc trinh bay trung thuc la mot lane da co implementation + benchmark, nhung chua phai diem manh nhat cua he thong.

Neu can mot cau noi an toan:

`Python hien la lane benchmark manh nhat de claim cho thesis V1, trong khi Java da co implementation va benchmark thuc nghiem nhung van can them modeling va source/sink coverage de canh tranh voi baseline community.`

## 10. Trang thai AI hien tai

### 10.1. Da noi vao pipeline

AI khong con nam tren giay. Trong codebase hien tai:

- `aegis_sast/triage/ai_runner.py` da noi AI vao triage flow;
- `aegis_sast/ai/gemini_client.py` da co Gemini client;
- workflow/report da co cho de ghi nhan AI triage summary.

### 10.2. Vi sao ket qua benchmark co AI va khong AI dang giong nhau

Lan benchmark AI gan day tren BenchmarkPython cho thay:

- AI verification duoc bat thanh cong o muc pipeline;
- nhung toan bo 190 finding deu fall back;
- `changed_status_count = 0`
- `changed_confidence_count = 0`

Nguyen nhan thuc te la quota/runtime Gemini hien tai bi `429 RESOURCE_EXHAUSTED`, nen AI overlay khong sua duoc score.

Ket luan trung thuc:

- AI da duoc wiring vao he thong;
- nhung chua duoc claim la da cai thien benchmark;
- deterministic core van la detector chinh va la nguon score chinh.

## 11. Gioi han can noi that trong bao cao

Day la nhung diem nen noi thang de report chac hon:

- cross-file analysis sau hien tai chu yeu manh o Python;
- AI hien tai chu yeu la triage/explanation seed, chua tao benchmark gain on dinh;
- `PATH_TRAVERSAL` van la family nhieu FP nhat trong Python lane;
- Java/JavaScript/PHP da co plugin, nhung muc do sau va benchmark maturity chua dong deu;
- dashboard la product layer doc report, khong phai detector UI goi thang internals;
- ho tro nhieu family trong model khong dong nghia da co benchmark claim cho tat ca family.

Noi that nhu vay se giup luan van manh hon, vi claim va implementation khop nhau.

## 12. Runbook demo cho giang vien

## 12.1. Demo nhanh, dep, ngan bang CLI

Neu can mot demo nhanh de quay:

```powershell
python -m aegis_sast.cli scan "examples\vulnerable_sqli.py" `
  --no-ai `
  -o json `
  -o markdown `
  --output-dir "D:\AegisBenchmarkArtifacts\demo_small_cli"
```

Khi demo, co the noi:

1. day la CLI chinh cua Aegis-SAST;
2. scanner thuc hien phan tich AST/rule/taint;
3. he thong xuat report JSON/Markdown sau scan;
4. neu ket thuc bang `Critical vulnerabilities found` thi do la exit code co finding, khong phai crash.

## 12.2. Demo benchmark thesis-safe bang CLI

### Buoc 1. Chay Aegis core-only tren BenchmarkPython

```powershell
python -m aegis_sast.cli scan "D:\BenchmarkPython\testcode" `
  --no-ai `
  -o json `
  -o markdown `
  --output-dir "D:\AegisBenchmarkArtifacts\BenchmarkPython_core"
```

### Buoc 2. Cham score cho 4 family chinh

```powershell
$report = Get-ChildItem "D:\AegisBenchmarkArtifacts\BenchmarkPython_core" -Filter "aegis_sast_report_*.json" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1 -ExpandProperty FullName

python scripts/score_owasp_benchmark.py `
  --report $report `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --family COMMAND_INJECTION `
  --family PATH_TRAVERSAL `
  --family INSECURE_DESERIALIZATION `
  --family SQL_INJECTION `
  --output-dir "D:\AegisBenchmarkArtifacts\BenchmarkPython_core_score"
```

### Buoc 3. Neu muon show breadth 6 family

```powershell
python scripts/score_owasp_benchmark.py `
  --report $report `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --family COMMAND_INJECTION `
  --family PATH_TRAVERSAL `
  --family INSECURE_DESERIALIZATION `
  --family SQL_INJECTION `
  --family CODE_INJECTION `
  --family OPEN_REDIRECT `
  --output-dir "D:\AegisBenchmarkArtifacts\BenchmarkPython_core_score_6fam"
```

### Buoc 4. Chay Semgrep baseline de so sanh

```powershell
$env:TEMP='D:\codex_temp'
$env:TMP='D:\codex_temp'
python scripts/run_semgrep_owasp_python.py `
  --profile benchmark-python `
  --family COMMAND_INJECTION `
  --family PATH_TRAVERSAL `
  --family INSECURE_DESERIALIZATION `
  --family SQL_INJECTION `
  --family CODE_INJECTION `
  --family OPEN_REDIRECT `
  --output-dir "D:\AegisBenchmarkArtifacts\BenchmarkPython_semgrep_6fam"
```

## 12.3. Demo dashboard

Chay dashboard:

```powershell
cd apps/findings-dashboard
npm.cmd run dev
```

Mo trinh duyet:

- `http://localhost:3000`

Co 2 cach demo:

1. import report JSON da xuat san;
2. hoac dung ngay `Run local scan` trong dashboard de chay scan va theo doi progress/log.

Report nen dung khi demo:

- report nho: `D:\AegisBenchmarkArtifacts\demo_small_cli\...json`
- report benchmark that: `D:\AegisBenchmarkArtifacts\BenchmarkPython_core\aegis_sast_report_20260805_161754.json`

Khi demo dashboard, co the noi:

1. dashboard la product layer o tren core scanner;
2. finding da duoc dua ve schema thong nhat;
3. reviewer co the loc, doc evidence, them note, va quan ly local feedback;
4. UI tach boundary voi detector, nen sau nay de mo rong sang PR flow hoac CI.

## 12.4. Neu muon demo co AI

Lenh scan co AI:

```powershell
python -m aegis_sast.cli scan "D:\BenchmarkPython\testcode" `
  -o json `
  -o markdown `
  --output-dir "D:\AegisBenchmarkArtifacts\BenchmarkPython_aegis_ai"
```

Can noi trung thuc truoc khi demo:

- neu quota Gemini dang het hoac API tra `429`, pipeline van chay nhung AI se fall back;
- khi do score benchmark se giong core-only;
- phan nay nen duoc demo nhu mot architecture lane da noi vao he thong, khong nen noi la da cai thien so lieu benchmark neu chua co artifact khac biet.

## 13. Goi y noi khi quay video/gui bao cao

Neu can mot mach noi 1-2 phut, co the noi theo thu tu sau:

1. Aegis-SAST la mot he thong SAST hybrid, trong do detector chinh la AST/rule/taint scanner da ngon ngu.
2. Scanner da duoc tach thanh orchestration service, reporting layer, va dashboard product layer.
3. He thong da duoc benchmark tren OWASP Benchmark Python va so sanh truc tiep voi Semgrep baseline bang cung harness.
4. Ket qua hien tai cho thay Aegis manh hon ve recall va F1 tren Python lane 4-family.
5. AI da duoc noi vao triage flow, nhung hien tai chua duoc claim la benchmark gain vi van phu thuoc quota/runtime.
6. Huong tiep theo la giam false positive, dac biet o `PATH_TRAVERSAL`, va lam cho AI triage thuc su tach duoc `all`, `visible`, va `high-confidence`.

## 14. Huong lam tiep theo

### P0: hoan thien lane hien tai

- giam FP cho `PATH_TRAVERSAL`;
- bien AI triage thanh lop filter/explanation that su;
- lam cho report co su khac nhau giua `all`, `visible`, va `high-confidence`;
- on dinh flow demo CLI/dashboard.

### P1: mo rong benchmark Python co kiem soat

- bo sung benchmark that cho `XSS`, `XXE`, `LDAP_INJECTION`, `XPATH_INJECTION`;
- chi claim family nao da co baseline compare sach.

### P2: nang Java lane

- bo sung source/sink modeling cho Java;
- cai thien detection cho `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `SQL_INJECTION`, `SSRF`;
- rut ngan khoang cach voi baseline community.

### P3: nang triage memory va reviewer feedback

- luu false positive patterns/reviewer notes;
- day local review memory tu dashboard nguoc lai triage layer;
- chuan bi nen cho PR scan/diff-aware workflow.

## 15. Ket luan chot hien trang

Den thoi diem hien tai, Aegis da co du 4 cot tru de bao cao voi giang vien:

1. mot scanner core hoat dong that;
2. mot kien truc tach lop hop ly giua detector, triage, report, va dashboard;
3. mot benchmark co ground truth va baseline Semgrep de so sanh;
4. mot huong AI tich hop dung lop, du chua nen claim gain benchmark.

Neu can mot cau ket cho slide/bao cao:

`Dong gop chinh cua Aegis hien tai khong nam o viec thay the hoan toan engine bang LLM, ma o viec xay dung mot scanner core da ngon ngu co benchmark ro rang, sau do dat AI vao dung lop triage va product workflow de giam false positive va tang gia tri su dung.`

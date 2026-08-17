# Tue lane: tach ro triage modes tren report that

## 1. Muc tieu cua lane nay

Sau khi lane Quan da ha false positive `PATH_TRAVERSAL`, diem nghẹn lon nhat con lai o lop triage la:

- report that 144 findings deu bi don vao `likely`
- `all`, `visible`, va `high-confidence` cho ra cung mot tap finding
- dashboard va benchmark scorer chua the hien duoc gia tri that cua triage layer

Muc tieu cua lane Tue trong dot nay la:

1. giu deterministic detector nhu hien tai
2. sua workflow triage de report that co nhieu lop trang thai hon
3. lam cho `all / visible / high-confidence` tach nhau ro tren du lieu benchmark that

## 2. Current implementation

### 2.1. Triage engine

Da sua `aegis_sast/triage/engine.py` theo huong:

- khong con auto day moi finding co `multi-step dataflow` len `likely`
- `OPEN_REDIRECT` mac dinh giu o `needs-review` cho toi khi co them bang chung context
- `PATH_TRAVERSAL` chi cham vao `.exists()` / `os.path.exists()` duoc giu o `needs-review`
- cac lane high-impact va co du source-to-sink evidence moi duoc len `likely`

Y nghia: `likely` gio khong con la nhan mac dinh cho tat ca finding co path.

### 2.2. Auditor + skeptic context

Da mo rong context window trong `aegis_sast/orchestration/context.py` tu 2 dong len 15 dong de skeptic nhin thay cac guard that su ton tai quanh sink.

Da bo sung heuristics trong `aegis_sast/orchestration/nodes.py` de skeptic nhan dien:

- redirect target validation bang `urlparse(...)` + host/scheme checks
- `exec(...)` literal guard bang `startswith(...)`, `endswith(...)`, va plain-string checks

Y nghia: mot so false positive benchmark khong can sua detector core van co the bi ha xuong `suppressed` neu context reviewer cho thay guard ro rang.

### 2.3. Judge promotion

Judge da duoc cap nhat de:

- promote SQLi co dynamic SQL + direct execution len `confirmed`
- giu `needs-review` cho cac lane con ambiguity ve exploitability

## 3. Ket qua tren report that

Report moi:

- `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_tue_triage_patch\aegis_sast_report_20260817_212254.json`

Tong triage summary:

- `confirmed = 5`
- `likely = 93`
- `needs-review = 30`
- `suppressed = 16`

Theo family:

- `SQL_INJECTION`: `confirmed = 5`
- `PATH_TRAVERSAL`: `likely = 40`, `needs-review = 12`
- `OPEN_REDIRECT`: `needs-review = 18`, `suppressed = 8`
- `CODE_INJECTION`: `likely = 15`, `suppressed = 8`
- `COMMAND_INJECTION`: `likely = 17`
- `INSECURE_DESERIALIZATION`: `likely = 21`

Nhan xet:

- report that da co day du 4 trang thai `confirmed / likely / needs-review / suppressed`
- `visible` khong con trung `all` tren report breadth 6-family
- `high-confidence` khong con trung `visible`

## 4. Benchmark effect

### 4.1. Python 6-family

Score artifact:

- `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_tue_triage_patch_score_6fam\owasp_score_summary.json`

Ket qua aggregate:

| Mode | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| all | 107 | 37 | 27 | 0.7431 | 0.7985 | 0.7698 |
| visible | 107 | 21 | 27 | 0.8359 | 0.7985 | 0.8168 |
| high-confidence | 83 | 15 | 51 | 0.8469 | 0.6194 | 0.7155 |

Y nghia:

- `visible` giam duoc mot luong FP dang ke so voi `all`
- `high-confidence` hien tai la tap uu tien review chat hon, doi lai recall giam

### 4.2. Python core 4-family

Score artifact:

- `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_tue_triage_patch_score_4fam\owasp_score_summary.json`

Ket qua aggregate:

| Mode | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| all | 85 | 10 | 16 | 0.8947 | 0.8416 | 0.8673 |
| visible | 85 | 10 | 16 | 0.8947 | 0.8416 | 0.8673 |
| high-confidence | 73 | 10 | 28 | 0.8795 | 0.7228 | 0.7935 |

Y nghia:

- trong core 4-family, `high-confidence` da tach khoi `all`
- nhung `visible` van trung voi `all` vi suppressions hien tai tap trung nhieu vao breadth families (`OPEN_REDIRECT`, `CODE_INJECTION`)

## 5. Engineering gaps

Nhung gi chua xong sau lane Tue dot nay:

- false positive core con lai chu yeu nam o `COMMAND_INJECTION` va `INSECURE_DESERIALIZATION`
- nhieu case FP kieu "safe constant overwrite" van can them heuristics hoac detector refinement moi suppress duoc
- `visible` tren core 4-family chua tach khoi `all`

Neu can lam tiep lane Tue, backlog hop ly nhat la:

1. them safe-overwrite heuristic co kiem soat cho `COMMAND_INJECTION` va `INSECURE_DESERIALIZATION`
2. kiem tra xem heuristic do nen dat o triage hay can dua nguoc ve detector/dataflow
3. rerun benchmark core 4-family de xem `visible` co bat dau tach khoi `all` hay khong

## 6. Research contribution

Gia tri hoc thuat cua dot sua nay nam o cho:

- triage layer khong con la lop annotation thu dong
- workflow reviewer co the tao ra nhieu "view" khac nhau cua cung mot detector output
- benchmark bay gio co the bao cao khong chi `all findings`, ma con bao cao `visible` va `high-confidence`

Dieu nay giup thesis co cau chuyen ro hon:

- detector core tao recall
- triage layer quan ly noise va uu tien reviewer attention

## 7. Demo value

Cho buoi demo hoac bao cao, ban nay tao duoc 3 diem noi thuyet phuc:

1. report JSON that da co 4 triage status, khong con "all likely"
2. benchmark scorer cho thay `all`, `visible`, `high-confidence` la 3 che do khac nhau that
3. triage layer co tac dong ro rang den reviewer experience ma khong can doi detector core

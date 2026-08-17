# Tue lane follow-up: tach `visible` khoi `all` cho core 4-family

## 1. Ly do can lam them sau ban 67

Ban `67-tue-triage-mode-separation-2026-08-17.md` da giai duoc viec:

- report that khong con bi don het vao `likely`
- `all`, `visible`, va `high-confidence` da tach nhau tren breadth 6-family

Nhung o thoi diem do, core 4-family van con mot diem nghẽn:

- `visible` van trung `all`
- false positive con lai nam chu yeu o `COMMAND_INJECTION` va `INSECURE_DESERIALIZATION`

Dot follow-up nay tap trung dung vao nhom FP con lai do.

## 2. Heuristic moi duoc bo sung

Da bo sung them deterministic skeptic heuristics trong
`aegis_sast/orchestration/nodes.py` cho cac mau local reasoning sau:

1. `safe constant lookup overwrite`
   - `bar` dau tien nhan tu `param`
   - sau do bi overwrite bang lookup an toan nhu `keyA-*`
   - ap dung cho cac mau dict/config lookup

2. `constant safe if-branch`
   - dieu kien `if` co the tinh duoc bang local constants
   - nhanh duoc chon gan `bar` bang literal an toan

3. `constant safe match-branch`
   - `match/case` duoc chon bang mot gia tri constant suy ra duoc
   - case duoc chon gan `bar` bang literal an toan

4. `safe list index selection`
   - danh sach co thao tac `append/pop`
   - phan tu cuoi cung duoc gan vao `bar` la constant, khong con la `param`

Y nghia cua dot nay:

- triage layer khong chi tim mitigation tokens
- no bat dau lam local deterministic reasoning tren context code
- nhung van giu pham vi hep, phuc vu false-positive reduction thay vi thay detector core

## 3. Ket qua report that sau follow-up

Report moi:

- `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_tue_triage_patch_v2\aegis_sast_report_20260817_214742.json`

Triage summary:

- `confirmed = 5`
- `likely = 83`
- `needs-review = 30`
- `suppressed = 26`

Theo family:

- `SQL_INJECTION`: `confirmed = 5`
- `PATH_TRAVERSAL`: `likely = 40`, `needs-review = 12`
- `COMMAND_INJECTION`: `likely = 13`, `suppressed = 4`
- `INSECURE_DESERIALIZATION`: `likely = 15`, `suppressed = 6`
- `OPEN_REDIRECT`: `needs-review = 18`, `suppressed = 8`
- `CODE_INJECTION`: `likely = 15`, `suppressed = 8`

## 4. Benchmark ket qua moi

### 4.1. Python core 4-family

Score artifact:

- `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_tue_triage_patch_v2_score_4fam\owasp_score_summary.json`

Ket qua aggregate:

| Mode | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| all | 85 | 10 | 16 | 0.8947 | 0.8416 | 0.8673 |
| visible | 85 | 0 | 16 | 1.0000 | 0.8416 | 0.9140 |
| high-confidence | 73 | 0 | 28 | 1.0000 | 0.7228 | 0.8391 |

Day la ket qua quan trong nhat cua dot follow-up:

- `visible` da tach han khoi `all`
- core 4-family khong con false positive trong tap `visible`
- `high-confidence` tiep tuc la tap review chat hon, doi lai recall giam

### 4.2. Python breadth 6-family

Score artifact:

- `D:\AegisBenchmarkArtifacts\BenchmarkPython_core_tue_triage_patch_v2_score_6fam\owasp_score_summary.json`

Ket qua aggregate:

| Mode | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| all | 107 | 37 | 27 | 0.7431 | 0.7985 | 0.7698 |
| visible | 107 | 11 | 27 | 0.9068 | 0.7985 | 0.8492 |
| high-confidence | 83 | 5 | 51 | 0.9432 | 0.6194 | 0.7477 |

Y nghia:

- `visible` breadth 6-family tiep tuc tot hon ban 67
- false positive giam tiep tu `21` xuong `11` tren tap `visible`

## 5. Nghien cuu va demo value

Sau dot follow-up nay, thesis co mot cau chuyen triage ro hon:

1. detector core tao recall
2. deterministic triage tach reviewer views
3. local reasoning tren context code giam false positive ma khong sua detector core

Cho demo va bao cao:

- co the mo report that va cho thay 4 triage statuses
- co the mo benchmark score va cho thay `all / visible / high-confidence`
- co the noi ro rang rang `visible` khong chi la "an findings suppressed", ma la ket qua cua local reasoning o skeptic stage

## 6. Gioi han con lai

Nhung diem van can noi that:

- `high-confidence` hien doi lai precision lay bang recall
- breadth 6-family van con FP o `OPEN_REDIRECT` va `CODE_INJECTION`
- heuristics local reasoning hien tap trung vao benchmark-like code motifs; neu muon product hoa rong hon, can tach thanh mot local symbolic evaluation layer ro rang hon

# Cong viec tiep theo cho Quan sau Phase A cleanup

## 1. Muc dich cua file nay

File nay khong thay the roadmap tong the o file `15`, `32`, `35`.
Muc dich cua no la chot ro:

- viec gi Quan can lam tiep ngay;
- viec gi du dieu kien moi chuyen phase;
- viec gi chua nen dung vao de tranh lech scope.

Tai lieu nay dung nhu mot checklist thao tac de moi lan mo lai repo la biet "gio lam gi tiep".

## 2. Trang thai hien tai

### Da xong trong nhanh cleanup

- exact-call matching de `open(` khong an nhem `urlopen`, `Popen`, `CodeTemplate`
- bo `open(` khoi source Python qua rong
- sua cross-file provenance de giu source type/pattern goc
- them scan exclude profile cho `.venv`, `tests`, `benchmarks`, codegen
- them detector-level dedupe cho finding trung sink
- chan synthetic cross-file source lookup theo ten ham khong duoc import that su

### Y nghia

Core scanner Python da sach hon truoc.
Luc nay viec hop ly nhat khong phai la them nhieu rule moi, ma la do lai noise sau cleanup de xem can sua tiep o engine hay da du on de chuyen sang rule ingestion.

## 3. Viec can lam ngay tiep theo

### Task 1 - Rerun PyTorch sau cleanup

Muc tieu:

- do lai so finding that sau khi da co dedupe va cross-file fix
- kiem tra xem report con bi duplicate hay source attribution lech nhieu khong

Cach lam:

- chay lai `python scripts/scan_target.py "D:\\CVE Target\\pytorch" --format json --format markdown --format sarif`
- sau khi co report moi, chay them:
  - `python scripts/analyze_scan_report.py <report-cu>.json <report-moi>.json`
  - hoac `python scripts/analyze_scan_report.py <report-moi>.json --show-mismatches`
- luu duong dan report moi
- ghi lai 6 so:
  - files scanned
  - total findings
  - critical
  - high
  - medium
  - errors

Can doi chieu voi moc truoc:

- moc cu la `107 findings`
- trong do co projection dedupe xuong khoang `85` neu chi tinh theo sink-level duplicate

Dieu kien xong task:

- co report moi
- co bang so sanh `truoc -> sau`
- co top 5 family/noisy hotspot moi nhat

### Task 2 - Kiem tra residual false positives sau scan moi

Muc tieu:

- xac dinh finding con on la do rule hay do flow attribution

Tap trung xem 3 nhom:

- `PATH_TRAVERSAL` voi sink `open(`
- `PATH_TRAVERSAL` voi sink `os.path.join(`
- `CODE_INJECTION` voi sink `eval(`

Can tra loi ro cho moi nhom:

- finding nay bi on vi source qua rong?
- hay vi sink qua rong?
- hay vi path attribution/graph path chua dung?

Ket qua mong doi:

- co 1 note ngan cho tung nhom:
  - giu nguyen
  - sua engine
  - hay doi sang rule seed Semgrep sau

### Task 3 - Neu van con source attribution lech thi sua not

Chi lam task nay neu scan moi van lo ro finding co:

- `source_pattern` khong xuat hien hop ly trong source snippet
- source line nam o cho khong lien quan
- cung 1 sink bi gan nhieu source vo nghia

Cho uu tien doc:

- `aegis_sast/analysis/python_flow_graph.py`
- path builder
- cach chon `source_node` va `matching_sinks`

Khong lam qua rong:

- chua nang full graph semantics
- chua dung vao multi-language path reasoning

### Task 4 - Chot "push gate" cho cleanup branch

Khi nao duoc xem la cleanup on de push:

- PyTorch finding giam ro so voi moc `107`
- duplicate group lon nhat khong con lap vo ly
- khong con case ro rang kieu `list(...)` bi gan source `input(`
- test hoi quy cho dedupe va cross-file fix van pass

Neu 4 diem nay on thi co the push len GitHub voi message theo huong:

- `phase-a cleanup`
- `dedupe findings`
- `tighten cross-file source attribution`

## 4. Viec lam ngay sau khi cleanup on

### Task 5 - Import Semgrep subset local cho 1 family truoc

Muc tieu:

- khong import ca registry
- chi chot 1 family dau tien de test flow normalize

Thu tu uu tien:

1. `COMMAND_INJECTION`
2. `PATH_TRAVERSAL`
3. `INSECURE_DESERIALIZATION`

Artifact da co san:

- `rules/schema/normalized_rule.example.yaml`
- `scripts/import_semgrep_subset.py`
- `tests/test_semgrep_importer.py`
- `docs/thesis/34-rule-ingestion-va-normalized-schema-v1.md`

Viec can lam:

- chon 10-20 rule Python seed tu local Semgrep subset
- import sang normalized schema cua Aegis
- human-review output
- ghi ro provenance/license

Khong lam:

- khong copy wholesale raw rules vao repo public
- khong nap thang tat ca rule vao detector runtime

### Task 6 - Review normalized output sau import

Muc tieu:

- dam bao Semgrep seed sau normalize con doc duoc va map dung contract Aegis

Can check:

- `rule_id`
- `language`
- `family`
- `cwe`
- `owasp`
- `source_patterns`
- `sink_patterns`
- `sanitizers`
- `provenance`

Dieu kien xong:

- co 1 tap normalized rule nho
- co danh sach rule nao giu, rule nao bo

## 5. Viec tiep theo sau rule ingestion

### Task 7 - Benchmark mini voi Semgrep

Can so sanh:

1. `Aegis core`
2. `Aegis core + triage`
3. `Semgrep subset baseline`

Metric giu nho nhung do duoc:

- precision
- recall
- F1
- finding count sau triage
- top FP families

Corpus V1:

- synthetic mini cases
- PyTorch subset hoac repo that da co noise

## 6. Viec chua nen dung vao luc nay

De tranh lech scope, tam thoi chua uu tien:

- Dynamic RAG runtime
- debate loop 3 luot
- Local LLM lam detector chinh
- import full Semgrep registry
- mo rong da ngon ngu truoc khi Python V1 on

Nhung thu nay chi nen vao sau khi:

- cleanup Python on
- rule ingestion subset on
- benchmark mini co so lieu

## 7. Thu tu uu tien thuc thi

Thu tu nen giu trong 1-2 luot tiep theo:

1. rerun PyTorch
2. phan tich residual FP
3. neu can thi sua not attribution
4. push cleanup branch
5. import Semgrep subset cho 1 family
6. review normalized rules
7. benchmark mini voi Semgrep

## 8. Tieu chi de noi la "lam dung huong"

Quan dang di dung huong neu dat duoc 4 diem nay:

1. khong co xu huong "tu viet het rules"
2. core scanner sach hon truoc khi ingest seed
3. rule open-source duoc normalize co kiem soat
4. benchmark voi Semgrep la trung tam de chung minh gia tri

## 9. Ket luan

Buoc tiep theo gan nhat khong phai la them tinh nang AI moi.
Buoc tiep theo gan nhat la:

- do lai PyTorch sau cleanup;
- chot scanner Python da bot on;
- roi moi ingest Semgrep subset cho 1 family.

Neu giu dung thu tu nay thi repo se khong bi roi vao tinh trang:

- detector chua sach ma da nap them rule;
- benchmark chua co ma da pitch AI nang;
- roadmap dai qua nhung khong co moc thao tac cu the.

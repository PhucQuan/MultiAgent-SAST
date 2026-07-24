# Roadmap V1 cho Python rule ingestion va triage nang cao

## 1. Muc tieu cua roadmap nay

### Trang thai cap nhat

Da xong trong Phase A:

- exact-call matching de giam match nham `open(` / `Popen` / `urlopen`
- bo `open(` khoi source Python qua rong
- them exclude profile cho scan wrapper
- sua cross-file provenance de giu source type/pattern goc
- them detector-level dedupe cho finding trung sink
- chan synthetic cross-file source lookup theo ten ham khong duoc import that su

Con lai truoc khi chuyen sang benchmark:

- rerun PyTorch de do finding count moi sau dedupe
- kiem lai residual source-attribution mismatch neu con
- chot benchmark mini voi Aegis core / Aegis + triage / Semgrep

Roadmap nay chot phase tiep theo ngay sau cac moc:

- Python graph core da co;
- workflow-state da co;
- report va SARIF da co;
- scan thuc te tren repo lon da bat dau lo ro false positives.

Muc tieu cua roadmap nay la:

1. giam noise cua scanner Python;
2. dat nen cho rule ingestion co provenance;
3. nang evidence cho triage;
4. co benchmark nho voi baseline cong nghiep.

## 2. Scope V1 rat nho

Chi chot:

- ngon ngu: `python`
- families:
  - `COMMAND_INJECTION`
  - `PATH_TRAVERSAL`
  - `INSECURE_DESERIALIZATION`
- baseline:
  - `Semgrep subset`
- AI:
  - chi triage
  - khong lam detector runtime

## 3. Phase A - Scanner cleanup truoc khi import rule

### Muc tieu

Khien report bot on ao truoc khi them coverage moi.

### Viec can lam

1. exact-call matching de:
   - `open(` khong match `urlopen`
   - `open(` khong match `Popen`
   - `Template(` khong match `CodeTemplate`
2. bo `open(` khoi source qua rong
3. sua cross-file provenance de khong gan bua `CROSS_FILE_HTTP_PARAM`
4. giu scan profile/exclude hop ly cho:
   - `.venv`
   - `test/tests`
   - `benchmarks`
   - codegen

### Deliverables

- report sach hon tren repo lon
- top FP families giam ro

## 4. Phase B - Rule schema va importer subset

### Muc tieu

Chot contract rule truoc khi mo rong baseline.

### Viec can lam

1. tao `normalized rule schema`
2. viet importer subset cho `Semgrep taint-mode`
3. import thu 10-20 rule Python
4. review rule da normalize truoc khi can detector

### Deliverables

- schema example
- importer script
- tests importer
- tai lieu ingestion

## 5. Phase C - Graph-slicing verification

### Muc tieu

Bien graph core thanh evidence bundle gon de triage bot ton token.

### Viec can lam

1. trich `mini-DFG slice` cho finding:
   - source
   - 1-3 buoc trung gian
   - sink
   - sanitizer/guard
2. dua graph summary ngan vao finding
3. giu schema on dinh cho Auditor/Skeptic/Judge

### Deliverables

- evidence bundle gon hon
- co the benchmark `full snippet` vs `graph slice`

## 6. Phase D - Benchmark nho nhung do duoc

### Muc tieu

Do chat luong thay vi chi demo.

### Can so sanh

1. `Aegis core`
2. `Aegis core + graph-slice triage`
3. `Semgrep baseline`

### Metrics

- precision
- recall
- F1
- finding count sau triage
- top FP families
- latency
- token cost

### Corpus

- synthetic mini set
- repo that da co nhieu noise nhu PyTorch subset

## 7. Phase E - Debate loop sau khi evidence da sach

### Muc tieu

Nang workflow len muc phan bien that su.

### Cach lam

1. `Auditor` lap luan lan 1
2. `Skeptic` bat loi va tim mitigation
3. `Auditor` phan hoi toi da 1 lan nua
4. `Judge` chot final status

### Nguyen tac

- toi da 2-3 luot
- chi bat sau khi graph-slice da on
- khong de token cost vo tran

## 8. Phase F - Knowledge layer V2

### Muc tieu

Nang triage knowledge ma khong dap detector.

### Cach lam

1. tao `KnowledgeProvider` abstraction
2. giu `static cards` la baseline
3. them `offline snapshot retrieval` cho triage
4. chua dung `live crawl`

### Deliverables

- static provider
- hybrid provider
- snapshot builder

## 9. Thu tu uu tien can giu

Neu thoi gian gap, thu tu uu tien la:

1. Phase A
2. Phase B
3. Phase C
4. Phase D
5. Phase E
6. Phase F

Thu tu nay co y nghia:

- scanner phai sach truoc;
- rule contract phai on truoc;
- evidence phai gon truoc;
- benchmark phai co truoc khi pitch AI nang;
- debate loop va retrieval la nang cap sau.

## 10. Tieu chi thanh cong cua V1

V1 co the xem la thanh cong neu dat duoc:

1. report Python giam noise ro rang tren repo lon;
2. co importer subset chay duoc va co provenance;
3. co graph-slice evidence cho triage;
4. co benchmark nho voi Semgrep baseline;
5. co tai lieu du de noi day la phase co gia tri nghien cuu va khong overclaim.

## 11. Ket luan

Roadmap nay giu scope gon nhung dung:

- lam sach core truoc;
- mo rong baseline sau;
- nang evidence truoc khi nang AI;
- va giu benchmark lam trung tam de chung minh gia tri.

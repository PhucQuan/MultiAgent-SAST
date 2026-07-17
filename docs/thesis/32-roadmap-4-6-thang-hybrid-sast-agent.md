# Roadmap 4-6 thang tiep theo cho Aegis-SAST

## 1. Muc tieu cua roadmap nay

Roadmap nay chot huong nang cap Aegis-SAST tu:

- mot scanner AST/taint co huong hybrid;

thanh:

- mot nen tang Hybrid SAST co:
  - detection core da ngon ngu;
  - Python deep lane co gia tri nghien cuu ro;
  - AI triage va agent workflow;
  - benchmark va baseline cong nghiep;
  - output/SARIF/CI de trinh bay nhu mot san pham ky thuat nghiem tuc.

Muc tieu khong phai la "them that nhieu tinh nang" mot cach dan trai, ma la lam ro 4 truc lon:

1. **Chieu sau nghien cuu**: Python graph reasoning, evidence slicing, false-positive reduction.
2. **Chieu rong he thong**: JavaScript va Java phai scan duoc that, co demo va benchmark mini.
3. **Lop AI hien dai**: LangGraph workflow, Local LLM, RAG, remediation planning.
4. **Chung minh khoa hoc**: benchmark, ablation, baseline voi tool lon, so lieu dinh luong.

## 2. Nguyen tac chot scope

De tai nay nen chot theo 5 nguyen tac:

### 2.1. Python la deep lane

Python la ngon ngu duoc dau tu sau nhat va la noi dat dong gop nghien cuu chinh:

- AST + rule-based detection;
- explicit CFG/DFG;
- function summary;
- evidence slicing / CPG-lite;
- benchmark false-positive reduction.

### 2.2. JavaScript va Java la breadth lane

JavaScript va Java khong nhat thiet phai dat do sau ngang Python trong dot dau, nhung bat buoc phai:

- duoc detect trong repo intake;
- scan ra finding that;
- co examples, smoke tests, benchmark mini;
- duoc viet ro la `intra-file` hoac `DFG-lite`.

### 2.3. Semgrep la baseline cong nghiep uu tien so 1

Khong nen chi noi "Aegis-SAST tot hon scanner thu cong". Phai co baseline thuc te:

- Semgrep adapter;
- mapping ket qua ve `NormalizedFinding`;
- benchmark doi chieu voi Aegis native engine.

### 2.4. LangGraph va Local LLM la lop AI hien dai

Agent va AI phai dua tren evidence da du manh, khong lam theo kieu:

- lay ca file text roi prompt free-form.

Huong dung hon la:

- workflow state;
- node contracts;
- evidence slicing;
- local/private inference;
- RAG theo CWE/OWASP/remediation patterns.

### 2.5. Benchmark la thanh phan bat buoc

Neu khong co benchmark, de tai de bi danh gia la:

- demo AI;
- wrapper cua rule engine;
- y tuong tot nhung chua co bang chung.

## 3. Kien truc dich can dat trong 4-6 thang

Kien truc dich nen duoc chot thanh 7 lop:

1. `Repo Intake and Planning`
2. `Detection Layer`
3. `Finding Normalization and Evidence`
4. `Context Extractor / Evidence Slicing`
5. `AI Triage and Agent Workflow`
6. `Remediation and Reporting`
7. `Benchmark, Baseline, CI/CD, Feedback Loop`

Trong do:

- `Detection Layer` gom ca Aegis native engine va external adapters;
- `Evidence Layer` la noi noi AST/CFG/DFG voi AI triage;
- `Benchmark Layer` la noi bien de tai thanh nghien cuu khoa hoc.

## 4. Must-have cho ban khoa luan manh

Day la nhom viec nen xem la bat buoc:

1. Hien thi ro `enabled analyzers` va `missing analyzers` trong CLI.
2. Hoan thien demo scan da ngon ngu that cho Python, JavaScript, Java.
3. Nang `Python graph core` thanh `evidence slicing / CPG-lite`.
4. Tich hop `Semgrep adapter` va baseline runner.
5. Map workflow hien tai sang `LangGraph` that.
6. Co `Local LLM + RAG` cho triage.
7. Co benchmark co so lieu: `Precision`, `Recall`, `F1`, `FP reduction`, `Latency`.
8. Co `SARIF + CI` de output di vao quy trinh san pham.

## 5. Strong contribution neu muon de tai rat manh

Day la nhom lam de an diem cao hon:

1. `JavaScript DFG-lite` thay vi chi assignment heuristic.
2. `Java JDBC-focused reasoning` thay vi chi method invocation heuristic.
3. `Remediation planner` sinh secure alternative va patch suggestion.
4. `Feedback store` luu quyet dinh reviewer de tao du lieu triage.
5. `Ablation study` ro rang:
   - heuristic baseline;
   - graph core;
   - graph + summary;
   - graph + AI triage;
   - Semgrep + AI triage.

## 6. Stretch goals neu con du thoi gian

Khong nen coi day la muc tieu bat buoc, nhung day la nhom giup de tai rat "xinh":

1. `LoRA / fine-tuning` cho triage classifier hoac remediation assistant.
2. `CodeQL overlap benchmark` tren mot tap mini.
3. Dashboard web de upload project, xem finding, duyet patch.
4. Human review gate cho autofix.
5. Export chart/CSV cho phan ket qua trong luan van.

## 7. Roadmap theo giai doan

## Phase 0: Lam sach runtime, intake, va claim (1-2 tuan)

### Muc tieu

Khien repo khong con roi vao tinh trang "nhin nhu chi co Python" khi thuc te da co plugin JS/Java/PHP.

### Viec can lam

1. Bo sung analyzer availability trong CLI.
2. Bao ro khi plugin nao do khong load duoc vi thieu dependency.
3. Cap nhat README va docs de tach ro:
   - `Python = deep`;
   - `JavaScript/Java/PHP = breadth`.
4. Tao `polyglot_demo` co it nhat:
   - 1 file Python;
   - 1 file JavaScript;
   - 1 file Java.
5. Them smoke test cho repo intake va scan profile polyglot.

### Deliverables

- CLI hien duoc analyzer status;
- README khong overclaim;
- co demo project da ngon ngu nho.

### Dieu kien qua phase

- Khi scan repo polyglot, output phai hien ro ngon ngu duoc phat hien;
- Neu plugin JS/Java khong kha dung, user phai thay ly do.

## Phase 1: JavaScript va Java tu "co plugin" thanh "co gia tri demo" (3-4 tuan)

### Muc tieu

Bien hai ngon ngu nay thanh breadth lane that su.

### Viec can lam

1. Ra soat lai `rules/javascript.yaml` va `rules/java.yaml`.
2. Them examples co tinh dai dien:
   - JavaScript command injection;
   - Java JDBC SQL injection;
   - Java path traversal hoac XSS neu kip.
3. Them smoke tests va unit tests cho:
   - source extraction;
   - sink extraction;
   - sanitizer detection;
   - finding generation.
4. Co report JSON/Markdown/SARIF cho example JS/Java.
5. Tao benchmark mini synthetic cho JS va Java.

### Deliverables

- examples cho JS/Java;
- tests cho JS/Java;
- mini benchmark breadth lane.

### Dieu kien qua phase

- Repo khong con bi danh gia la "chi scan duoc Python".

## Phase 2: Python deep lane -> evidence slicing / CPG-lite (4-5 tuan)

### Muc tieu

Day Python len muc dong gop nghien cuu ro rang hon.

### Viec can lam

1. Chuan hoa graph evidence trong `NormalizedFinding`.
2. Them `evidence slicing`:
   - source slice;
   - sink slice;
   - sanitizer slice;
   - path summary;
   - local helper summary.
3. Nang kha nang path reasoning:
   - sanitizer co nam tren duong toi sink hay khong;
   - nested branch / loop case;
   - try/finally case can thiet.
4. Mo rong benchmark synthetic Python.
5. Viet tai lieu tong hop y nghia `CPG-lite` hoac `graph-enhanced evidence`.

### Deliverables

- structured evidence tot hon cho triage;
- benchmark Python sau hon;
- tai lieu khoa hoc cho dong gop graph layer.

### Dieu kien qua phase

- Co the trich mot finding thanh mot evidence bundle gon, khong can dua ca file vao AI.

## Phase 3: Semgrep adapter va baseline cong nghiep (3-4 tuan)

### Muc tieu

Dat Aegis-SAST vao vi tri "native engine + industrial baseline", khong chi la scanner doc lap.

### Viec can lam

1. Tao adapter doc ket qua Semgrep JSON.
2. Map ve `NormalizedFinding`.
3. Giu metadata:
   - tool origin;
   - rule id;
   - severity;
   - evidence;
   - triage status.
4. Tao benchmark runner:
   - Aegis native;
   - Semgrep raw;
   - Semgrep + AI triage;
   - Aegis + AI triage.
5. So sanh overlap finding va phan loai.

### Deliverables

- Semgrep adapter;
- baseline benchmark;
- du lieu de viet phan so sanh voi tool cong nghiep.

### Dieu kien qua phase

- Co bang ket qua benchmark co baseline that, khong chi noi ve Aegis mot minh.

## Phase 4: LangGraph + Local LLM + RAG (4-5 tuan)

### Muc tieu

Bien workflow-state seed hien tai thanh agent workflow that su.

### Viec can lam

1. Map workflow hien tai sang LangGraph:
   - `RepoIntake`;
   - `Normalizer`;
   - `Auditor`;
   - `SkepticValidator`;
   - `Judge`;
   - `Reporter`;
   - `FixPlanner`.
2. Them `Local LLM` qua Ollama hoac vLLM.
3. Them `RAG`/knowledge retrieval tu:
   - CWE;
   - OWASP;
   - secure coding notes;
   - remediation examples.
4. Chuan hoa prompt dau vao:
   - metadata finding;
   - evidence slice;
   - framework hints;
   - knowledge snippets.
5. Ghi log route, decision, confidence.

### Deliverables

- LangGraph workflow that;
- local/private inference option;
- triage prompt co cau truc.

### Dieu kien qua phase

- Mot finding phai di qua luong node co nghia, khong chi "goi verify()" mot lan.

## Phase 5: Evaluation, remediation, CI/CD, va luan van (4-6 tuan)

### Muc tieu

Dong goi ket qua thanh mot de tai khoa luan/NCKH hoan chinh.

### Viec can lam

1. Hoan thien benchmark:
   - synthetic;
   - subset SARD neu kha thi;
   - mini real-world corpus.
2. Do chi so:
   - Precision;
   - Recall;
   - F1;
   - false-positive reduction;
   - latency.
3. Hoan thien remediation layer:
   - remediation hint;
   - secure alternative;
   - patch suggestion.
4. Tich hop GitHub Actions + SARIF upload.
5. Chot hinh ve, bang so lieu, bang so sanh cho khoa luan.
6. Neu con thoi gian:
   - dashboard;
   - LoRA/fine-tuning;
   - human review gate.

### Deliverables

- bo so lieu cuoi ky;
- SARIF/CI demo;
- remediation plan;
- tai lieu bao cao day du.

### Dieu kien ket thuc roadmap

- Co the demo luong hoan chinh:
  - intake -> scan -> normalize -> triage -> report -> remediation hint -> benchmark evidence.

## 8. Cach chia trong 4-6 thang

Neu co 4 thang:

- Phase 0 + 1 + 2 + 3 la bat buoc;
- Phase 4 lam ban rut gon;
- Phase 5 tap trung benchmark va luan van.

Neu co 5 thang:

- Lam day du Phase 0 den 5;
- Local LLM va RAG nen co ban chay duoc.

Neu co 6 thang:

- Them stretch goals:
  - LoRA/fine-tuning;
  - dashboard;
  - CodeQL overlap benchmark;
  - patch draft co human review.

## 9. Mapping sang phan cong Quan va Tue

Roadmap nay phu hop voi cach chia viec da chot trong file `15`:

### Quan

- detection core;
- Python graph core;
- JavaScript/Java breadth lane;
- Semgrep adapter;
- benchmark va CI/SARIF.

### Tue

- LangGraph orchestration;
- Local LLM;
- RAG/knowledge;
- AI triage;
- remediation planner;
- feedback store/fine-tuning huong sau.

## 10. Tieu chi thanh cong cua de tai

De tai co the duoc xem la manh neu dat duoc 8 diem sau:

1. Repo scan duoc Python, JavaScript, Java mot cach ro rang.
2. Python co deep lane co bang chung graph/evidence that.
3. AI triage dua tren evidence slice, khong dua ca file text mot cach may moc.
4. Co workflow node ro rang, co log va route metadata.
5. Co baseline voi Semgrep.
6. Co benchmark va so lieu thuc nghiem.
7. Co output SARIF/CI de the hien tinh san pham.
8. Co phan trinh bay duoc dong gop nghien cuu va khong overclaim.

## 11. Ket luan

Neu di theo roadmap nay, Aegis-SAST se khong dung lai o muc:

- scanner AST co AI verify.

No se tien len muc:

- nen tang Hybrid SAST da ngon ngu;
- co Python deep lane co dong gop nghien cuu;
- co AI triage/agent workflow hien dai;
- co baseline cong nghiep;
- co benchmark, SARIF, CI, remediation;
- va du suc dat muc khoa luan tot nghiep/NCKH rat manh.

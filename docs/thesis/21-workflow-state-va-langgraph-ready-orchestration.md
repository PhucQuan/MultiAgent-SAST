# Workflow State va LangGraph-Ready Orchestration

## 1. Muc dich

Tai lieu nay mo ta buoc nang cap moi cua Aegis-SAST o tang `orchestration`.

Muc tieu cua buoc nay khong phai la "gan LangGraph cho co", ma la xay dung truoc:

- state model ro rang cho workflow
- trace cua tung node
- route tom tat cho tung finding
- diem noi de sau nay thay bang LangGraph that

Noi cach khac, day la buoc chuyen tu:

> scan xong roi goi triage truc tiep

sang:

> scan xong -> dua vao workflow state -> triage -> report

---

## 2. Thanh phan da duoc bo sung

## 2.1. `ScanWorkflowState`

Da mo rong `aegis_sast/orchestration/state.py` de co:

- `RepoProfile`
- `WorkflowStepTrace`
- `ScanWorkflowState`

Trang thai nay giu du lieu cho ca pipeline:

- repo profile
- normalized findings
- triage records
- knowledge refs
- trace tung buoc
- metadata tong hop
- errors

Da bo sung `to_dict()` de sau nay co the:

- debug workflow
- export workflow snapshot
- dua state vao LangGraph node state

## 2.2. `WorkflowRoute`

Da bo sung `route_id` trong `WorkflowRoute`.

Hien tai co 2 route seed:

- `direct-judge`
- `skeptic-review`

Y nghia:

- finding co confidence cao, khong co sanitizer -> co the bo qua skeptic validator
- finding co sanitizer hoac evidence chua manh -> can route bao thu hon

## 2.3. `ScanWorkflow`

Da them `aegis_sast/orchestration/workflow.py`.

Lop nay dong vai tro workflow runner giai doan 1, gom cac buoc:

1. planner
2. normalize
3. knowledge_loader
4. auditor
5. judge
6. reporter

Day chua phai multi-agent day du, nhung da co:

- state dung chung
- trace cho tung node
- route summary
- triage summary

---

## 3. Tich hop vao CLI

CLI khong con goi triage theo kieu "thuc thi thang" nua.

Thay vao do:

1. scanner tao `ScanResult`
2. `ScanWorkflow` nhan `ScanResult`
3. workflow sinh `triage_records`
4. CLI hien:
   - triage summary
   - workflow route summary
5. reporter xuat JSON, Markdown, SARIF

Loi ich cua cach nay:

- CLI bat dau co dang cua mot workflow engine
- co so lieu de viet vao bao cao do an
- de thay node deterministic bang node agent sau nay

---

## 4. Gia tri doi voi khoa luan

Buoc nay co gia tri lon hon viec "them framework agent" mot cach hinh thuc.

No giup de tai tra loi duoc 3 cau hoi:

### 4.1. Agent nam o dau trong he thong?

Khong phai o parser AST.
Khong phai o rule engine.

Agent hop ly nhat o tang:

- routing
- triage
- skeptic validation
- remediation planning
- reporting

### 4.2. Vi sao can workflow state?

Neu khong co state model ro:

- khong luu duoc bang chung
- khong debug duoc node nao lam gi
- khong benchmark duoc truoc va sau triage
- khong co co so cho human-in-the-loop

### 4.3. Vi sao chua nhay thang sang LangGraph?

Vi neu evidence va state chua ro, LangGraph chi la lop vo orchestration.

Lam state va trace truoc giup:

- giam risk khi tich hop framework
- de test hon
- de bao ve hon truoc hoi dong

---

## 5. Quan he voi bo skill local

Thu muc `skills/` dang giu bo skill local cho cac nhom cong viec:

- architecture
- agent orchestration
- rule authoring
- triage
- remediation
- benchmark

Tang `orchestration/` trong code va `skills/` trong tai lieu can di cung nhau:

- `orchestration/` tra loi "he thong chay ra sao"
- `skills/` tra loi "agent nen lam viec theo quy trinh nao"

Day la cach xay dung hop ly cho de tai nghien cuu:

- code co workflow state that
- tai lieu co operational procedure ro

---

## 6. Han che hien tai

Phan orchestration vua them van con o muc giai doan 1:

- chua co LangGraph dependency that
- chua co persistence state qua nhieu lan chay
- chua co human-in-the-loop review gate
- chua co node retrieval ranking nang cao
- chua co task planner dong cho benchmark hoac remediation

Tuy nhien, day la muc nang cap dung va can thiet truoc khi di tiep.

---

## 7. Buoc tiep theo de thanh agent that su

## Phase tiep theo o tang orchestration

### Buoc 1. Repo intake node that

- detect ngon ngu tu repository thay vi tu finding
- them framework hints
- them scan profile

### Buoc 2. Auditor va Skeptic tach rieng

- auditor: tong hop bang chung co loi cho finding
- skeptic: tim sanitizer, guard clause, false positive pattern

### Buoc 3. Judge node co chinh sach ro hon

- severity-aware
- language-aware
- policy-aware

### Buoc 4. Human review gate

- chi cho phep autofix voi finding du dieu kien
- cac finding high risk can manual approval

### Buoc 5. LangGraph integration

Luc nay moi nen map:

- state -> LangGraph state
- trace -> node log
- route -> edge condition

---

## 8. Ket luan

Tang `workflow-state` la buoc nang cap ky thuat dung cho Aegis-SAST.

No chua phai agent hoan chinh, nhung no bien repo tu:

- scanner co triage

thanh:

- scanner co workflow state, route metadata, va orchestration seed cho agent

Day la mot moc rat hop ly de dua project tu muc portfolio len muc khoa luan va nghien cuu khoa hoc.

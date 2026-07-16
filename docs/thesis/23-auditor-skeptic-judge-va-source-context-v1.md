# Auditor, Skeptic, Judge va Source Context v1

## 1. Muc dich

Tai lieu nay mo ta buoc nang cap tiep theo sau:

- `21-workflow-state-va-langgraph-ready-orchestration.md`
- `22-repo-intake-va-scan-profile-v1.md`

Muc tieu cua buoc nay la bien cac node trong workflow thanh thanh phan co hanh vi that, thay vi chi la trace ten node.

Cu the, he thong da bo sung:

- `AuditorNode`
- `SkepticValidatorNode`
- `JudgeNode`
- `SourceContextReader`

Day la buoc rat quan trong de bam sat de cuong trong file `15`, `16`, `17`, vi no dua workflow tien gan hon toi mo hinh agent co state va co trach nhiem ro rang.

---

## 2. Van de cua trang thai truoc

Truoc buoc nang cap nay, `ScanWorkflow` da co:

- `repo_intake`
- `planner`
- `knowledge_loader`
- `auditor`
- `judge`
- `reporter`

Nhung phan lon van o muc:

- `TriageEngine` lam phan lon quyet dinh
- trace chi ghi ten node
- workflow chua co output hop dong rieng cho tung node
- finding chua duoc doc them nguu canh file xung quanh source va sink

Dieu nay co nghia la he thong da co huong agent, nhung chua co node-level contracts ro rang.

---

## 3. Thanh phan da duoc bo sung

## 3.1. `SourceContextReader`

Da them file:

- `aegis_sast/orchestration/context.py`

Lop nay doc cua so ma nguon xung quanh:

- `source`
- `sink`

Moi cua so context gom:

- `file_path`
- `focus_line`
- `start_line`
- `end_line`
- danh sach dong da danh so

Tac dung:

- cung cap ngu canh dep hon cho node auditor
- chuan bi du lieu cho prompt agent sau nay
- tao bang chung de viet vao report va benchmark

## 3.2. Hop dong node

Da them file:

- `aegis_sast/orchestration/contracts.py`

Trong do co 3 contract chinh:

- `AuditorReview`
- `SkepticReview`
- `JudgeReview`

Y nghia cua viec tach contract:

- moi node co dau vao/ra ro rang
- de thay the bang LangGraph node that su ve sau
- de log, test va benchmark tung node rieng

## 3.3. Node implementation

Da them file:

- `aegis_sast/orchestration/nodes.py`

### `AuditorNode`

Node nay:

- doc `TriageRecord`
- lay route hien tai
- tinh `evidence_score`
- nap source context
- ghi notes va metadata cho finding

No dong vai tro node danh gia vong dau:

- finding dang manh den muc nao
- finding duoc route theo nhanh nao
- finding co du context de triage hay chua

### `SkepticValidatorNode`

Node nay chi chay khi finding o route:

- `skeptic-review`

No tim:

- mitigation signals trong code context
- ambiguity cua evidence
- dau hieu can ha muc hoac suppress

Phien ban v1 dang dung deterministic heuristics cho mot so nhom lo hong:

- SQL Injection
- Command Injection
- Path Traversal
- XSS
- SSRF

Day chua phai LLM skeptic that, nhung da la node phan bien co hanh vi that.

### `JudgeNode`

Node nay:

- nhan ket qua tu auditor va skeptic
- chap nhan hoac ha muc trang thai
- cap nhat `TriageDecision`
- ghi `auditor_review`, `skeptic_review`, `judge_review` vao metadata

No giup quyet dinh cuoi cung khong con nam het trong mot ham triage don.

---

## 4. Tich hop vao `ScanWorkflow`

`ScanWorkflow` da duoc cap nhat de:

1. triage finding bang `TriageEngine`
2. chay `AuditorNode` cho tung finding
3. chay `SkepticValidatorNode` neu route can skeptic
4. chay `JudgeNode` de chot status cuoi

Workflow metadata hien tai co them:

- `auditor_summary`
- `skeptic_summary`
- `judge_summary`

Workflow trace hien tai da co node:

- `repo_intake`
- `planner`
- `normalize`
- `knowledge_loader`
- `auditor`
- `skeptic_validator`
- `judge`
- `reporter`

Noi cach khac, workflow da co "xu ly tren tung finding", khong con chi la mot trace tang tong quat.

---

## 5. Gia tri doi voi file 15, 16, 17

## 5.1. Phu hop voi file 15

Trong `15-phase-3-thang-va-phan-cong-quan-tue.md`, Phase 3 yeu cau:

- co luong lai ghep scan -> normalize -> AI triage -> report
- co conditional routing
- co vai tro Auditor, SkepticValidator, Judge

Buoc nang cap nay chua phai LangGraph day du, nhung da dat duoc:

- role separation
- route-aware execution
- data contract cho moi node

## 5.2. Phu hop voi file 16

Trong `16-de-cuong-bao-cao-de-tai-ban-giang-vien.md`, AI Triage Layer duoc mo ta bang:

- Planner
- Auditor
- Skeptic Validator
- Judge

Hien tai phan nay da co implementation seed that su, nen khi viet bao cao co the noi:

- he thong da co node deterministic de mo phong va kiem chung workflow truoc khi gan LLM hoan chinh

Day la cach noi trung thuc va co gia tri ky thuat.

## 5.3. Phu hop voi file 17

Trong `17-lo-trinh-ast-dfg-cfg-va-agent.md`, agent chi nen vao sau khi evidence da du manh.

Node `SourceContextReader` va `AuditorNode` chinh la buoc bo sung evidence va ngu canh de:

- agent sau nay khong phai "doan giup"
- skeptic co code context that de phan bien

---

## 6. Gia tri ky thuat thuc su

Buoc nang cap nay co 4 gia tri thuc te:

1. **Workflow khong con phang:** finding di qua node co nghia, khong chi qua mot ham triage.
2. **Context tro thanh first-class data:** code xung quanh source/sink duoc nap va luu lai.
3. **De benchmark tung node:** sau nay co the do critic/skeptic impact rieng.
4. **De thay the bang LangGraph that:** contracts da ro, state da ro, route da ro.

---

## 7. Han che hien tai

Phien ban v1 van con gioi han:

- `SkepticValidatorNode` moi la deterministic heuristic, chua dung LLM
- mitigation pattern chua phu het moi framework
- source context moi doc cua so dong, chua co AST slice hay CFG slice
- `JudgeNode` chua tinh CVSS hay policy phuc tap

Tuy nhien, day la buoc can thiet de di tiep ma khong vo scope.

---

## 8. Buoc tiep theo hop ly

Sau buoc nay, huong tiep theo nen la:

1. Them helper doc them context file lien quan cho finding cross-file.
2. Dua `SourceContextReader` vao prompt layer cho LangGraph sau nay.
3. Mo rong `SkepticValidatorNode` de dung knowledge card va structured output sau hon.
4. Dua metadata node vao SARIF properties va benchmark logs.

---

## 9. Ket luan

`AuditorNode`, `SkepticValidatorNode`, `JudgeNode` va `SourceContextReader` la buoc chuyen quan trong tu:

- workflow co trace

thanh:

- workflow co node-level contracts va hanh vi that

No giup Aegis-SAST tien gan hon toi mot agentic hybrid SAST dung nghia, dong thoi van giu duoc tinh kiem chung, tinh benchmark va tinh ky thuat can co cho khoa luan.

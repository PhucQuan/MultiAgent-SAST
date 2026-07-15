# Tai cau truc repo Aegis-SAST theo huong khoa luan va nghien cuu

## 1. Muc dich

Tai lieu nay giai thich vi sao can cai thien cau truc thu muc cua Aegis-SAST, va viec tai cau truc nay dong gop gi cho gia tri khoa luan tot nghiep va nghien cuu khoa hoc.

Muc tieu cua viec tai cau truc khong phai chi de repo "dep" hon. Muc tieu chinh la:

- tach ro phan code san pham va phan tai lieu nghien cuu
- tach ro du lieu demo, du lieu benchmark va du lieu test
- chuan bi cho cac module agent, knowledge, triage, va CI integration
- lam cho repo de bao ve hon truoc giang vien vi kien truc ro rang hon

---

## 2. Van de cua cau truc cu

Truoc khi cai thien, repo da co nen tang code rat tot, nhung con mot so diem chua on neu dung duoi goc nhin khoa luan:

### 2.1. Thu muc root con mang tinh workspace

Tai root co nhieu thu muc phuc vu cac muc dich khac nhau:

- code san pham
- test fixtures
- sample app
- tai lieu thesis
- reference repo
- skill pack

Dieu nay khong sai, nhung neu khong dinh nghia ro vai tro tung thu muc thi nguoi doc repo se kho nhin ra:

- dau la source code chinh
- dau la du lieu benchmark
- dau la demo
- dau la reference clone

### 2.2. Sample code chua tach ro theo muc dich

Truoc khi bo sung tai lieu cau truc, `examples/`, `test_projects/`, va `refs/` de gay nham lan:

- `examples/` vua la demo cho user, vua giong sample test
- `test_projects/` la noi scan thu cong nhung co the bi nham la benchmark fixture
- `refs/` la tai lieu tham khao ben ngoai nhung neu khong chu thich se de bi nham la mot phan cua san pham

### 2.3. Package code chua phan anh kien truc dich

Repo hien tai da co:

- `analysis/`
- `core/`
- `plugins/`
- `ai/`
- `reporting/`

Day la cau truc hop ly cho scanner portfolio. Tuy nhien, voi de tai Agentic Hybrid SAST thi cau truc nay chua the hien ro cac lop:

- triage
- orchestration
- knowledge loading
- CI/security integrations
- provider layer cho LLM

### 2.4. Cau truc repo chua that su "research-grade"

Mot repo nghien cuu khoa hoc thuong can co nhung vung du lieu va workflow ro:

- `benchmarks/`
- `datasets/`
- `scripts/`
- `results/` hoac mot cho rieng cho output benchmark

Neu thieu nhung phan nay, project de bi nhin nhu mot scanner co them AI hon la mot de tai co evaluation pipeline.

---

## 3. Nguyen tac tai cau truc

Vieic cai thien repo duoc thuc hien theo 4 nguyen tac:

### 3.1. Khong lam vo code hien tai

Khong doi cau truc theo kieu di chuyen lon ngay lap tuc. Thay vao do:

- bo sung package dich truoc
- giu package cu de tuong thich nguoc
- doi import tung phan mot

### 3.2. Tang do ro nghia cua tung thu muc

Moi thu muc o root phai tra loi duoc:

- thu muc nay dung de lam gi
- duoc dung boi ai
- co phai code san pham hay khong

### 3.3. Chuan bi cho kien truc dich

Repo phai co cho cho cac module se duoc xay tiep:

- triage
- orchestration
- knowledge
- integrations
- llm provider layer

### 3.4. Tien toi benchmark va CI

Tach rieng benchmark, dataset, va integration som giup:

- de lam ablation study
- de xuat SARIF
- de doi chieu Semgrep, CodeQL
- de giai thich de tai theo van phong ky thuat

---

## 4. Cac cai tien da duoc ap dung

## 4.1. Cai thien hygiene cua repo

`.gitignore` duoc dieu chinh lai de:

- khong con ignore toan bo file `.md`
- khong con gay mat dau bo thesis markdown
- ignore `.venv/`
- chi ignore output sinh ra nhu `reports/`, `*.sarif`, `benchmarks/results/`, `datasets/generated/`

Day la buoc nho nhung rat quan trong vi no tac dong truc tiep toi viec quan ly tai lieu khoa luan.

## 4.2. Bo sung cac thu muc mang tinh nghien cuu

Da bo sung:

- `benchmarks/`
- `benchmarks/baselines/`
- `benchmarks/fixtures/`
- `datasets/`
- `datasets/synthetic/`
- `scripts/`

Moi thu muc deu co file `README.md` mo ta vai tro va pham vi.

## 4.3. Lam ro y nghia cua cac thu muc cu

Da bo sung `README.md` cho:

- `refs/`
- `test_projects/`

Muc dich la tach ro:

- `refs/` chi la reference ben ngoai
- `test_projects/` la local scan targets cho smoke test

## 4.4. Scaffold cac package dich trong code

Da bo sung cac package moi trong `aegis_sast/`:

- `triage/`
- `orchestration/`
- `knowledge/`
- `llm/`
- `integrations/`

Day la buoc chuyen tu scanner portfolio sang repo co huong kien truc dich ro rang.

### `triage/`

Chua schema cho:

- `TriageDecision`
- `TriageRecord`

### `orchestration/`

Chua state scaffolding cho workflow agent:

- `RepoProfile`
- `WorkflowStepTrace`
- `ScanWorkflowState`

### `knowledge/`

Chua:

- `KnowledgeCard`
- `KnowledgeLoader`

### `llm/`

Tach provider layer moi, nhung van giu `ai/` de tuong thich nguoc.

### `integrations/`

Chua `SARIFFormatter` de dua repo tien gan hon voi quy trinh CI/CD va code scanning.

---

## 5. Cau truc repo de xuat sau cai thien

```text
SAST_toolAI/
  aegis_sast/
    analysis/
    core/
    integrations/
    knowledge/
    llm/
    orchestration/
    plugins/
    reporting/
    triage/
    utils/
  benchmarks/
    baselines/
    fixtures/
  datasets/
    synthetic/
  docs/
    thesis/
  examples/
  refs/
  scripts/
  skills/
  test_projects/
  tests/
```

Day la cau truc hop ly hon cho de tai vi:

- code san pham nam tap trung trong `aegis_sast/`
- tai lieu khoa luan nam rieng trong `docs/thesis/`
- benchmark va dataset co vung rieng
- sample demo va local debug sample khong con bi tron vai tro

---

## 6. Danh gia muc do phu hop voi khoa luan va nghien cuu

## 6.1. Voi khoa luan tot nghiep

Cau truc moi da dat muc tot hon ro ret vi:

- de mo ta kien truc module
- de chia cong viec giua hai nguoi
- de giai thich luong du lieu scan -> normalize -> triage -> export
- de trinh bay roadmap phat trien tiep

## 6.2. Voi nghien cuu khoa hoc

Cau truc moi chua phai muc cuoi, nhung da duoc chuan bi dung huong vi:

- da co cho cho benchmark
- da co cho cho dataset
- da co triage schema
- da co orchestration state scaffold
- da co SARIF integration seed

Muon len muc nghien cuu manh hon nua, buoc tiep theo can la:

- xay benchmark harness that su
- dua knowledge cards vao file YAML that su
- hoan thien LangGraph workflow
- nang DFG-lite va CFG-lite cho Python, JavaScript, Java

---

## 7. Ket luan

Tai cau truc repo la buoc can thiet de dua Aegis-SAST tu mot scanner co kha nang rat tot len mot de tai khoa luan va nghien cuu co tinh he thong.

Gia tri cua buoc nay khong nam o viec tao them thu muc. Gia tri that su nam o cho:

- kien truc repo ro hon
- vai tro tung module ro hon
- duong nang cap len agent, benchmark, va CI ro hon
- viec bao ve de tai truoc giang vien de hieu va thuyet phuc hon

Noi ngan gon, sau buoc tai cau truc nay, Aegis-SAST da gan hon voi mot `thesis-grade security analysis platform` hon la mot `portfolio scanner`.

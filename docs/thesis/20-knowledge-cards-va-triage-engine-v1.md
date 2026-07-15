# Knowledge Cards va Triage Engine v1

## 1. Muc dich

Tai lieu nay mo ta phan nang cap moi cua Aegis-SAST: bo sung lop `knowledge-assisted triage` thay vi chi dung scanner deterministic va AI verification roi xuat report.

Muc tieu cua buoc nay la:

- bien finding thanh doi tuong de triage co cau truc ro rang
- bo sung tri thuc cuc bo ve nguon, sink, sanitizer, va false positive pattern
- chuan bi cho LangGraph workflow sau nay

---

## 2. Han che cua trang thai cu

Truoc khi nang cap:

- scanner tao `Vulnerability`
- AI verification gan `AIVerification`
- report xuat ra JSON va Markdown

Nhung he thong chua co:

- kho tri thuc noi bo de tham chieu
- quyet dinh triage tach rieng khoi raw finding
- route goi y cho workflow agent
- co che thong nhat de giai thich vi sao finding bi giu, ha muc, hay suppress

Dieu nay lam AI verification van mang tinh "annotate finding" nhieu hon la "triage finding".

---

## 3. Thanh phan da duoc bo sung

## 3.1. Knowledge card library

Da them thu muc:

- `aegis_sast/knowledge/library/`

Trong do co hai nhom the tri thuc:

### Nhom generic theo lo hong

- SQL Injection
- Command Injection
- Path Traversal
- XSS
- SSRF

Moi card generic ghi:

- CWE / OWASP lien quan
- source pho bien
- sink pho bien
- sanitizer pho bien
- false positive patterns
- remediation notes

### Nhom language-specific

- Python web and database
- JavaScript Node/Express
- Java web/JDBC

Moi card language-specific bo sung:

- framework hints
- sanitizer quen dung trong he sinh thai do
- false positive pattern mang tinh ngon ngu / framework

## 3.2. Knowledge loader

Da them:

- `KnowledgeLoader`

Chuc nang:

- tu dong doc YAML cards tu kho built-in
- co the loc theo `language`
- co the loc theo `finding_type`

Day la co so de sau nay router va knowledge loader node cua agent co du lieu that, khong phai mock.

## 3.3. Triage engine

Da them:

- `TriageEngine`

Chuc nang:

- nhan `Vulnerability`
- chuyen sang `NormalizedFinding`
- tim `KnowledgeCard` phu hop
- dua ra `TriageDecision`
- tao `TriageRecord`

Trang thai triage van theo 4 nhan:

- `confirmed`
- `likely`
- `needs-review`
- `suppressed`

## 3.4. Workflow route seed

Da them:

- `route_finding()`
- `WorkflowRoute`

Y nghia:

- finding evidence manh va khong co sanitizer -> co the di truc tiep Auditor -> Judge
- finding yeu hon hoac co sanitizer -> can qua SkepticValidator

Day la buoc dem de sau nay thay router don gian bang LangGraph state graph that su.

---

## 4. Logic triage v1

Phien ban v1 dang su dung logic bao thu, khong overclaim:

### 4.1. Neu co sanitizer hieu luc tren path

- neu finding truoc do o muc `confirmed` thi ha xuong `needs-review`
- neu finding o muc `likely` hoac `needs-review` thi co the `suppressed`

Ly do:

- co sanitizer la mot dau hieu manh cho false positive
- nhung voi finding nguy hiem va AI rat tu tin, van nen giu cho con nguoi review

### 4.2. Neu khong co sanitizer va co intermediate steps ro rang

- finding tu `needs-review` co the duoc nang len `likely`

Ly do:

- intermediate steps cho thay bang chung luong du lieu ro hon

### 4.3. Neu khong co AI

- triage van van hanh dua tren:
  - severity
  - sanitizer
  - intermediate steps
  - knowledge card matching

Dieu nay giup he thong khong phu thuoc tuyet doi vao LLM.

---

## 5. Tich hop vao CLI va reporting

Da bo sung triage vao pipeline CLI:

1. scan deterministic
2. AI verification
3. knowledge-assisted triage
4. export report

Da cap nhat:

- JSON exporter
- Markdown exporter
- SARIF formatter

Deu co kha nang nhan `triage_records` va xuat:

- triage status cuoi cung
- confidence cuoi cung
- knowledge cards da match
- suggested route cho workflow

---

## 6. Gia tri doi voi khoa luan

Buoc nang cap nay rat quan trong vi no chuyen huong de tai tu:

> scanner co AI giai thich

thanh:

> hybrid SAST co knowledge-assisted triage subsystem

Day la diem rat de viet trong khoa luan, vi co the tach thanh mot module nghien cuu rieng:

- normalized findings
- knowledge cards
- triage decision
- route suggestion

No cung la diem de lam ablation study sau nay:

- deterministic only
- deterministic + AI
- deterministic + AI + knowledge cards

---

## 7. Han che hien tai

Phien ban v1 chua phai muc cuoi:

- knowledge cards con nho
- chua co YAML knowledge cho tat ca CWE
- logic triage van rule-based don gian
- chua co LangGraph orchestration that su
- chua co retrieval ranking nang cao

Nhung day la nen tang dung de di tiep sang:

- knowledge card mo rong
- LangGraph router / auditor / skeptic / judge
- benchmark false-positive reduction

---

## 8. Ket luan

Knowledge Cards va Triage Engine v1 la buoc chuyen quan trong cua Aegis-SAST.

No khong chi them mot vai file YAML. No dat nen cho:

- triage subsystem
- workflow routing
- explanation co can cu
- evaluation theo huong nghien cuu

Noi ngan gon, sau buoc nay Aegis-SAST khong con chi la scanner + AI verification, ma da bat dau co dang cua mot `agent-ready hybrid SAST pipeline`.

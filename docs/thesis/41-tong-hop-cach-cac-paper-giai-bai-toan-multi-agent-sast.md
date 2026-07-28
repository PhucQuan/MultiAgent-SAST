# Tong hop cach cac paper giai bai toan Multi-Agent SAST va y nghia cho Aegis-SAST

## 1. Muc dich cua file nay

File nay khong phai la literature review day du theo van phong hoc thuat.
Muc dich cua no la:

- tong hop nhanh cach cac paper gan day giai bai toan Multi-Agent SAST;
- rut ra nhung y tuong co the ap dung that cho Aegis-SAST;
- tranh tinh trang doc nhieu paper nhung khong chot duoc huong build.

Tai lieu nay tap trung vao cau hoi rat thuc te:

- ho giai bai toan `rules/specs` nhu the nao;
- ho giai bai toan `false positives` nhu the nao;
- ho dung `agent` o lop nao;
- va nhung gi hop scope cho Aegis V1, nhung gi nen de sau.

## 2. 4 kieu giai bai toan lon ma cac paper dang di theo

Sau khi doi chieu cac paper 2025-2026, co 4 huong giai bai toan ro rang:

### 2.1. Scan truoc, agent loc false positives sau

Y tuong:

- dung mot cong cu SAST hay rule engine deterministic de phat hien candidate findings;
- sau do moi cho multi-agent hoac LLM doc context va quyet dinh finding nao nen giu, finding nao nen suppress.

Loi ich:

- giu scanner core don gian va reproducible;
- dung agent dung cho bai toan ma agent lam tot hon, do la danh gia ngu canh;
- de benchmark hon vi co baseline truoc va sau triage.

### 2.2. Static analysis dung khung, LLM sinh hoac bo sung taint specification

Y tuong:

- khong de AI ket luan lo hong truc tiep ngay;
- cho AI ho tro xac dinh:
  - source
  - sink
  - propagator
  - library flow summary
  - call edges kho resolve bang static thuong

Loi ich:

- tranh phai tu viet tay het rules/specs;
- dung duoc uu diem suy luan cua LLM o cho dynamic APIs va third-party libraries;
- van giu detector runtime la static analysis.

### 2.3. LLM-centered orchestration

Y tuong:

- dung multi-agent workflow, retrieval va reasoning loop lam trung tam;
- scanner hay cac static tool khong bien mat, nhung tro thanh cong cu phuc vu workflow agent.

Loi ich:

- mo rong duoc sang supply-chain, dependency, context retrieval, reasoning phuc hop hon;
- co kha nang tao he thong tong the "agentic SAST platform".

Han che:

- token cost cao;
- kho benchmark neu core va evidence chua sach;
- scope de bi to neu dua vao V1 qua som.

### 2.4. Ensemble/voting de tang recall

Y tuong:

- dung nhieu agent co goc nhin khac nhau;
- gom ket qua qua bo phieu union hoac mot co che aggregation.

Loi ich:

- co the tang recall;
- de lam ablation trong paper.

Han che:

- precision de giam;
- neu khong co benchmark tot thi rat de bien thanh he thong "bao dong nhieu hon".

## 3. Tung paper dang giai bai toan ra sao

## 3.1. QASecClaw

### Bai toan ho nham toi

- SAST tools bao qua nhieu false positives;
- nguoi dung met moi vi report on;
- can mot lop loc thong minh sau scanner.

### Cach ho lam

Kien truc cua paper nay theo dung huong:

- SAST engine quet truoc;
- Mission Orchestrator dieu phoi cac agent;
- co cac thanh phan:
  - test planning
  - security validation
  - evidence correlation
  - SAST filter
  - reporting

Y nghia ky thuat:

- AI khong thay scanner;
- AI dong vai tro bo loc va ngu canh hoa finding.

### Cai hay de hoc

1. Dung scanner deterministic truoc, agent vao sau.
2. Dat false positive reduction thanh bai toan trung tam thay vi "AI tim moi thu".
3. Dung benchmark co ground truth de chung minh gia tri.

### Cai hop voi Aegis

Rat hop voi:

- `ScanWorkflow`
- `Auditor`
- `SkepticValidator`
- `Judge`

No cung ung ho huong:

- reviewed bundle -> scan -> triage -> report

chu khong ep Aegis phai bo scanner core.

### Cai khong nen copy nguyen si

- khong nen pitch nhu da giai quyet duoc moi ngon ngu sau nhu nhau;
- khong nen day multi-agent loc FP truoc khi benchmark reviewed bundles on dinh.

## 3.2. SemTaint

### Bai toan ho nham toi

- static taint analysis, nhat la voi JavaScript va npm ecosystem, kho vi:
  - dynamic features
  - external libraries
  - thieu taint specifications

### Cach ho lam

Huong di cua paper nay rat quan trong:

- dung static analysis de dung call graph va framework chung;
- agent/LLM chi xu ly nhung phan static khong giai quyet dep;
- LLM phan loai source/sink theo tung CWE;
- sinh ra taint specification roi nap lai vao SAST tool.

Nghia la:

- AI sinh `spec`;
- static engine dung `spec` de detect.

### Cai hay de hoc

1. Khong tu viet tay het rules/specs.
2. AI nen sinh ra artifact co cau truc, khong nen sinh ket luan lo hong ngay.
3. `spec extraction` la bai toan hop ly va hoc thuat hon "AI scan tat ca code".

### Cai hop voi Aegis

Day la paper gan nhat voi huong:

- natural language/docs/example
  ->
- AI draft normalized rule/spec
  ->
- validator
  ->
- human review
  ->
- export bridge/runtime use

Neu can chot 1 paper de bien ho y tuong `mieu ta bang loi -> AI viet rule` thanh dong gop khoa hoc hop ly, thi day la paper sat nhat.

### Cai khong nen copy nguyen si

- khong can nhay ngay vao JavaScript/npm dynamic case neu Python V1 chua xong;
- khong nen overclaim rang reviewed rule YAML cua Aegis tuong duong full taint specification system nhu paper.

## 3.3. Argus

### Bai toan ho nham toi

- LLM-assisted SAST don gian thuong hallucinates;
- static tool truyen thong bi gioi han context;
- can mot workflow lon hon cho full-chain security detection.

### Cach ho lam

Argus theo huong:

- collaborative multi-agent workflows;
- supply-chain analysis;
- RAG de truy hoi tri thuc;
- ReAct de reasoning va giam hallucination.

No la mo hinh:

- LLM-centered workflow

hon la:

- scan core co them 1 chut AI.

### Cai hay de hoc

1. Agent khong chi dung cho triage, ma con cho retrieval va reasoning.
2. RAG/knowledge retrieval nen o lop orchestration, khong chen vao detector runtime.
3. Neu muon di den mot he thong lon, can kiem soat hallucination bang retrieval + stepwise reasoning.

### Cai hop voi Aegis

Hop cho roadmap dai han:

- `KnowledgeProvider` abstraction
- offline snapshot retrieval
- LangGraph orchestration that
- dependency/supply-chain phase sau

### Cai khong nen copy nguyen si

- scope qua lon cho V1;
- khong nen dua RAG va ReAct vao truoc khi rule workbench, reviewed bundles va benchmark mini chot xong.

## 3.4. MultiVer

### Bai toan ho nham toi

- vulnerability detection trong zero-shot setting;
- muon tang recall ma khong can fine-tuning.

### Cach ho lam

Paper nay dung:

- 4 agents
  - security
  - correctness
  - performance
  - style
- union voting de quyet finding.

### Cai hay de hoc

1. Multi-agent khong nhat thiet la chuoi tuyen tinh;
2. voting la mot co che evaluation hay cho phan experiment;
3. co the viet ablation ro hon: single-agent vs ensemble.

### Cai hop voi Aegis

Hop cho phase sau neu muon nghien cuu:

- `single reviewer` vs `auditor + skeptic`
- `single prompt` vs `multi-node workflow`
- `reviewed bundle only` vs `reviewed bundle + skeptical triage`

### Cai khong nen copy nguyen si

- union voting de tang recall thuong doi precision;
- neu dua vao scanner V1 qua som se lam report on hon.

Do do, paper nay hop de hoc:

- evaluation design
- ablation design

hon la hop de lam detector chinh cho Aegis ngay.

## 3.5. Blog "Static Code Analysis with a Local LLM"

### Bai toan ho nham toi

- dung local LLM de lap prototype agentic SAST gon nhe;
- chia he thong thanh cac agent don gian de code nhanh.

### Cach ho lam

Theo mo ta, he thong chia thanh cac agent kieu:

- file fetcher
- secrets detector
- insecure code analyzer
- merger

### Cai hay de hoc

1. Cach cat he thong thanh module de prototype nhanh.
2. Cach dung local LLM neu muon demo offline.
3. Cach dong goi mot ban proof-of-concept de de trinh bay.

### Cai khong nen dung lam xuong song hoc thuat

- day la blog, khong phai paper nghien cuu chuan;
- hop de lay cam hung implementation, khong hop de lam co so hoc thuat chinh.

## 3.6. Sifting the Noise

### Bai toan ho nham toi

- SAST output qua on;
- can mot cach danh gia xem cac `agent frameworks` nao loc false positive tot hon;
- can benchmark ro rang thay vi chi demo 1 workflow duy nhat.

### Cach ho lam

Paper nay rat thuc dung:

- khong co gang thay scanner core;
- lay finding tu SAST truoc;
- cho cac agent frameworks vao giai doan FP filtering;
- so sanh truc tiep giua nhieu framework tren cung bo du lieu.

Gia tri cua paper nay nam o cho:

- no bien `agent triage` thanh mot bai toan evaluation ro rang;
- no dung benchmark va repo that;
- no chi ra rang kien truc agent khac nhau co the cho chat luong loc nhieu khac biet.

### Cai hay de hoc

1. Benchmark `framework A vs framework B` la hop ly, khong can vo tinh tranh luan prompt.
2. Neu muon dua LangGraph sau nay vao Aegis, phai xem no nhu mot `triage policy` co the benchmark.
3. FP reduction nen do tren cung corpus co ground truth, khong chi tren 1 repo scan thu.

### Cai hop voi Aegis

Rat hop cho phase sau khi Aegis da co:

- reviewed bundles;
- benchmark mini;
- triage evidence on dinh.

Luc do minh moi co the so sanh:

- no-agent
- single reviewer
- auditor + skeptic
- debate loop

### Cai khong nen copy nguyen si

- khong nen nhay vao benchmark nhieu agent frameworks khi reviewed rules con chua sach;
- khong nen coi `agent framework` la dong gop chinh neu detector va evidence chua vung.

## 3.7. Towards Effective Complementary Security Analysis using LLMs

### Bai toan ho nham toi

- SAST co nhieu false positives;
- can dung LLM de danh gia lai finding nhung khong lam mat true positives.

### Cach ho lam

Huong di cua paper nay rat quan trong vi no kha "tinh":

- SAST van tao finding truoc;
- LLM dong vai tro bo sung de danh gia lai finding;
- evaluation dua tren benchmark co ground truth va du lieu thuc te.

Noi ngan gon:

- LLM la `complementary assessor`
- khong phai detector chinh

### Cai hay de hoc

1. Day la bang chung rat tot de bao ve quyet dinh "AI triage sau scan".
2. Co the dung no de giai thich vi sao Aegis khong de AI scan ca repo ngay tu dau.
3. Rat hop de viet phan `related work` cho huong FP reduction.

### Cai hop voi Aegis

Rat hop voi:

- triage labels `likely`, `needs-review`, `suppressed`
- evidence summary
- graph slice
- reviewed bundle + post-scan assessment

### Cai khong nen copy nguyen si

- khong nen chi dua vao 1 prompt va goi do la multi-agent;
- khong nen overclaim neu Aegis chua co ground truth bench ro rang.

## 3.8. VulAgent

### Bai toan ho nham toi

- repository-level vulnerability detection kho vi can vua localize, vua xay dung gia thuyet, vua verify ngu canh;
- prompt mot phat thuong bo sot context hoac suy luan khong vung.

### Cach ho lam

Paper nay dua ra huong:

- tim diem nhay cam;
- hinh thanh `hypothesis` ve lo hong;
- trich xuat duong kich hoat/co che kich hoat;
- validate gia thuyet do tren context rong hon.

No giong cach auditor nguoi that lam viec:

- thay dau hieu
- dat nghi van
- tim bang chung
- bac bo hoac xac nhan

### Cai hay de hoc

1. Day la khung ly thuyet dep cho `Auditor -> Skeptic -> Judge`.
2. Thich hop de mo ta phan triage cua Aegis nhu mot qua trinh `hypothesis validation`.
3. Co the tai su dung cho phan `evidence-centered review` thay vi prompt free-form.

### Cai hop voi Aegis

Hop voi roadmap sau khi:

- graph slice gon hon;
- source/sink/intermediate edges ro hon;
- triage co them stated hypothesis va counter-evidence.

### Cai khong nen copy nguyen si

- khong nen dua thang vao detect runtime cho V1;
- khong nen pitch nhu repository-level reasoning cua Aegis da sau nhu paper neu evidence layer chua day.

## 4. Tong hop nhanh: paper nao tra loi dung bai toan nao

| Bai toan | Paper gan nhat |
|---|---|
| Giam false positives sau scan | `QASecClaw` |
| AI sinh source/sink/spec cho engine | `SemTaint` |
| Kien truc dai han voi RAG/ReAct/multi-agent | `Argus` |
| Ensemble/voting va ablation | `MultiVer` |
| So sanh framework agent cho FP filtering | `Sifting the Noise` |
| LLM danh gia bo sung sau SAST | `Towards Effective Complementary Security Analysis using LLMs` |
| Hypothesis-validation cho repo-level review | `VulAgent` |
| Prototype local LLM gon nhe | Blog `Static Code Analysis with a Local LLM` |

## 5. Rut ra cho Aegis-SAST: nen hoc gi, nen bo gi

## 5.1. Nhung gi nen hoc va ap dung ngay

### Huong A - Giu scanner core deterministic

Day la diem chung manh nhat giua cac huong co gia tri:

- static engine van la lop detect chinh;
- AI khong nen la detector runtime duy nhat.

### Huong B - Dung AI de sinh artifact co cau truc

Hoc tu `SemTaint`:

- AI sinh rule/spec co cau truc;
- khong de AI ket luan lo hong truc tiep tren toan repo.

Trong Aegis, artifact do chinh la:

- normalized rule YAML
- provenance
- notes
- source/sink/sanitizer set

### Huong C - Dung multi-agent de triage, khong de detect

Hoc tu `QASecClaw`:

- scan truoc;
- agent triage sau;
- benchmark FP reduction ro rang.

Bo sung tu `Sifting the Noise` va `Towards Effective Complementary Security Analysis using LLMs`:

- triage phai do duoc bang benchmark;
- agent/LLM la lop loc bo sung, khong thay the scanner;
- can theo doi tradeoff giua FP reduction va TP retention.

### Huong D - Retrieval de trong knowledge layer

Hoc tu `Argus`:

- retrieval va reasoning la lop sau;
- khong chen thang vao detector V1.

## 5.2. Nhung gi khong nen lam luc nay

1. Khong de AI viet finding runtime cho ca repo.
2. Khong import full registry truoc khi reviewed bundles on.
3. Khong nhay vao RAG/React/LangGraph that khi benchmark chua co.
4. Khong lay blog implementation lam dong gop hoc thuat chinh.

## 6. Cach chot de tai cho dung huong nghien cuu

Neu chot lai theo nhung paper tren, cau chuyen dep nhat cho Aegis la:

### Lop 1 - Deterministic scan core

- AST / parser
- source/sink matching
- taint/evidence
- report

### Lop 2 - Rule/spec governance

- seed rule tu Semgrep subset
- normalized schema
- validator
- review bundle
- legacy bridge

### Lop 3 - AI-assisted rule/spec authoring

- docs/snippet/natural language
  ->
- AI draft normalized rule/spec
  ->
- human review

### Lop 4 - Multi-agent triage

- Auditor
- Skeptic
- Judge
- sau nay co the them `hypothesis` va `counter-evidence`

### Lop 5 - Benchmark

- so sanh voi Semgrep
- do FP reduction
- do precision/recall/F1
- dung corpus co ground truth nhu OWASP Benchmark va corpus repo that co review

Noi ngan gon:

- `SemTaint` giai bai toan tao spec/rule
- `QASecClaw` giai bai toan loc FP
- `Argus` goi y huong agent layer dai han
- `MultiVer` goi y cach lam ablation va ensemble

## 7. Thu tu uu tien hop ly cho project

Neu bam sat cac paper ma van giu scope khoa luan dung, thu tu hop ly nhat cho Aegis la:

1. Hoan tat reviewed bundles cho 1-3 family nho
2. Benchmark `default rules` vs `reviewed bundle`
3. Them `natural language -> AI draft rule/spec`
4. Sau do moi benchmark `bundle only` vs `bundle + triage`
5. Cuoi cung moi map workflow sang LangGraph that va retrieval layer

## 8. Cach doc paper de khong bi "loan huong"

Neu doc tiep paper ve agentic SAST, nen chia ve 4 cau hoi:

1. AI dang nam o `detect`, `spec generation`, `triage`, hay `retrieval`?
2. Paper co benchmark va ground truth ro khong?
3. Ho co artifact trung gian co cau truc khong, hay chi prompt free-form?
4. Precision/FP reduction co duoc danh doi bang recall hay token cost qua lon khong?

Neu 1 paper khong tra loi ro 4 cau hoi nay, thi nen xem no la y tuong tham khao chu khong nen dua thang vao roadmap chinh.

## 9. Ket luan

Cac paper gan day khong ung ho huong:

- bo static analysis
- cho AI scan bua
- hay de LLM tu viet ket luan khong co artifact trung gian

Nguoc lai, huong co gia tri nhat la:

- scanner core co kiem soat;
- AI sinh artifact co cau truc;
- multi-agent triage o lop sau;
- benchmark voi bo du lieu va baseline ro rang.

Day la huong phu hop nhat de Aegis-SAST tu mot scanner portfolio-scale di len mot prototype khoa luan/NCKH co gia tri thuc nghiem ro rang.

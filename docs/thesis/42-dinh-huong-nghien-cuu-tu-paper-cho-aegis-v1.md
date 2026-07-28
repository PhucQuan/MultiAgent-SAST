# Dinh huong nghien cuu tu cac paper gan day cho Aegis-SAST V1

## 1. Muc dich cua file nay

File nay dung de tra loi cau hoi rat thuc te:

- cac paper gan day dang giai bai toan SAST nhu the nao;
- giai phap nao hop voi scope khoa luan cua Aegis;
- giai phap nao hay nhung chua nen lam ngay;
- va thu tu ap dung nao giup project tien nhanh ma khong bi to scope.

File nay khong thay the literature review day du.
No la ban "chot huong build" de tranh truong hop doc nhieu paper nhung cuoi cung khong quyet duoc buoc tiep theo.

## 2. 5 bai toan lon ma cong dong dang giai

Qua doi chieu cac paper va tai lieu chinh thong, co 5 bai toan lon lap di lap lai:

### 2.1. Giam false positives sau khi da scan

Y tuong:

- detector van chay truoc;
- AI/agent chi vao sau de danh gia finding;
- muc tieu la giam bao dong nham ma khong lam rot qua nhieu true positives.

Day la bai toan hop voi Aegis nhat o giai doan hien tai.

### 2.2. Sinh source/sink/spec thay vi bat AI "doan lo hong"

Y tuong:

- AI khong nen ket luan lo hong runtime tren toan repo;
- AI nen sinh ra artifact co cau truc:
  - rule
  - taint specification
  - source/sink set
  - sanitizer hints

Day la huong dep hon ve mat hoc thuat va de benchmark hon.

### 2.3. Dung benchmark co ground truth thay vi scan thu vai repo

Y tuong:

- can co dataset co nhan dung/sai;
- can co baseline ro;
- can tinh duoc precision, recall, F1 va FP reduction.

Neu khong co buoc nay thi rat kho viet phan thuc nghiem cho khoa luan.

### 2.4. Agent workflow chi co gia tri khi evidence da sach

Y tuong:

- them nhieu agent khong tu dong lam he thong tot hon;
- neu finding dau vao on va evidence mo ho thi multi-agent chi lam token cost tang;
- debate loop, ensemble, RAG chi nen vao sau khi scanner core va reviewed rules on dinh.

### 2.5. Rule governance quan trong khong kem detector

Y tuong:

- cong cu tot khong chi la cong cu quet;
- no con can mot quy trinh:
  - lay seed rules
  - normalize
  - validate
  - human review
  - bridge sang runtime

Day chinh la khoang trong ma Aegis dang lam dung huong.

## 3. Cac paper cho minh hoc dieu gi

## 3.1. QASecClaw

Dieu dang hoc:

- SAST engine chay truoc;
- multi-agent vao sau de loc false positives;
- evaluation dua tren benchmark co ground truth.

Y nghia cho Aegis:

- `Auditor -> Skeptic -> Judge` la huong dung;
- AI nen dung o lop triage;
- claim chinh nen la `FP reduction after scan`, khong phai `AI thay the scanner`.

## 3.2. SemTaint

Dieu dang hoc:

- static analysis va taint analysis van la lop detect chinh;
- multi-agent dung de trich xuat `taint specification`;
- artifact sinh ra duoc nap lai vao detector.

Y nghia cho Aegis:

- huong `natural language/docs/example -> AI draft normalized rule/spec -> validator -> human review` la hop ly;
- rule workbench cua Aegis co co so hoc thuat that, khong phai y tuong tu nghi ra.

## 3.3. Argus

Dieu dang hoc:

- multi-agent workflow co retrieval, ReAct va full-chain reasoning;
- pham vi khong chi co source code ma con mo rong sang supply-chain va context retrieval.

Y nghia cho Aegis:

- day la roadmap dai han;
- hop de dat trong phan `future work`;
- khong nen dua thang vao V1 neu benchmark core chua xong.

## 3.4. MultiVer

Dieu dang hoc:

- dung ensemble nhieu agent;
- toi uu recall bang bo phieu union.

Y nghia cho Aegis:

- rat hop de hoc cach lam ablation;
- co the so sanh `single reviewer` voi `multi-agent`;
- nhung khong nen dua vao detector V1 vi de tang report on.

## 3.5. Sifting the Noise

Dieu dang hoc:

- so sanh nhieu agent frameworks cho bai toan FP filtering;
- khong coi agent la "phep mau", ma coi no la mot policy can benchmark.

Y nghia cho Aegis:

- sau nay neu dua LangGraph that vao thi phai benchmark nhu mot triage policy;
- can do tradeoff giua FP reduction va TP retention.

## 3.6. Towards Effective Complementary Security Analysis using Large Language Models

Dieu dang hoc:

- LLM co the bo sung cho SAST o giai doan danh gia finding;
- muc tieu la giam FP nhung van giu TP.

Y nghia cho Aegis:

- rat hop de bao ve huong `AI la complementary assessor`;
- giong tinh than current triage layer cua repo.

## 3.7. VulAgent

Dieu dang hoc:

- thay vi prompt mot phat, he thong di theo cach:
  - localize
  - dat gia thuyet
  - tim bang chung
  - validate

Y nghia cho Aegis:

- day la khung ly thuyet rat dep cho `Auditor -> Skeptic -> Judge`;
- co the dung de nang cap evidence-centered triage o phase sau.

## 4. Chot lai: Aegis nen hoc gi ngay bay gio

Neu chi duoc chon 3 dieu de hoc ngay, thi nen chot:

### 4.1. Giu detector runtime deterministic

- AST
- source/sink matching
- taint/evidence
- report exporter

AI khong nen la detector runtime chinh trong V1.

### 4.2. Dung AI de sinh artifact co cau truc

- draft normalized rule
- draft source/sink set
- notes/provenance
- triage explanation

Tuc la AI ho tro authoring va review, khong phai thay detector.

### 4.3. Dung benchmark chuan de chung minh gia tri

- OWASP Benchmark
- synthetic cases
- repo that co review mau

Khong co benchmark thi kho bien project thanh bai khoa luan manh.

## 5. Nhung gi khong nen lam luc nay

1. Khong cho AI scan bua ca repo roi tu ket luan finding.
2. Khong import full Semgrep registry vao runtime ngay.
3. Khong dua LangGraph/RAG that vao truoc khi reviewed bundles va benchmark mini on.
4. Khong pitch da-ngon-ngu-sau-nhu-nhau khi Python van la lane sau nhat.
5. Khong doi "them agent" voi "them gia tri nghien cuu".

## 6. Mapping truc tiep vao Aegis hien tai

| Thanh phan Aegis | Bai toan nghien cuu tuong ung |
|---|---|
| Detection core | deterministic scan core |
| Normalized schema | structured rule/spec artifact |
| Rule workbench | governed authoring + review |
| Reviewed bundle | curated runtime bridge |
| Auditor/Skeptic/Judge | post-scan FP reduction |
| Graph slice/evidence | hypothesis validation support |
| Benchmark scripts | empirical proof |

## 7. Thu tu hop ly nhat cho phase tiep theo

### Phase 1

- hoan tat reviewed bundles cho `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `INSECURE_DESERIALIZATION`
- moi family chi can mot seed subset gon, khong can nhieu

### Phase 2

- dung OWASP Benchmark va synthetic cases de lap benchmark mini
- so sanh:
  - default rules
  - reviewed bundle
  - reviewed bundle + triage
  - Semgrep baseline

### Phase 3

- them `natural language -> AI draft normalized rule/spec`
- validator + human review van bat buoc

### Phase 4

- neu benchmark da on, moi nang cap triage theo huong:
  - graph slice gon hon
  - stated hypothesis
  - counter-evidence
  - debate loop

## 8. Cau chuyen khoa luan dep nhat cho Aegis

Neu viet cho dung tam, cau chuyen dep nhat khong phai:

- "em xay 1 AI quet duoc moi lo hong"

ma la:

- "em xay mot hybrid SAST workflow co scanner deterministic, governance cho reviewed rules, va AI triage/rule authoring co kiem soat; sau do do thuc nghiem kha nang giam false positives tren benchmark va corpus nho"

Cau chuyen nay:

- de benchmark hon;
- de bao ve hon;
- it overclaim hon;
- va sat voi nhung gi cong dong nghien cuu dang lam that.

## 9. Ket luan ngan

Neu hoi "cac paper dang giai bai toan nay theo cach nao", thi cau tra loi ngan nhat la:

- scan truoc, AI loc sau;
- AI sinh spec/rule co cau truc thay vi doan lo hong tu do;
- benchmark voi ground truth;
- multi-agent chi co gia tri khi evidence va rule governance da sach.

Do do, huong dung nhat cho Aegis V1 van la:

- reviewed rule bundles truoc;
- benchmark nho nhung sach;
- roi moi them AI drafting va triage nang cao.

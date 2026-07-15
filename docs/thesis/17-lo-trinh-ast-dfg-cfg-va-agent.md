# Lo trinh nang cap Aegis-SAST tu AST len DFG/CFG-lite va Agent

## 1. Muc dich cua tai lieu

Tai lieu nay duoc viet de chot mot van de ky thuat rat quan trong cua de tai: neu muon dua Aegis-SAST tu muc scanner AST-based len muc do an lon va co gia tri nghien cuu, thi co can them CFG va DFG hay khong, va neu co thi nen trien khai theo thu tu nao de khong vo scope.

Tai lieu nay khong mo ta nhung gi he thong "da co" theo kieu overclaim. Muc tieu la tach ro:

- he thong hien tai dang co gi
- AST hien tai giai quyet duoc den dau
- vi sao can bo sung tu duy CFG/DFG
- lo trinh thuc thi nao phu hop voi 3 thang va 2 nguoi

---

## 2. Danh gia nhanh file 15 va 16

### 2.1. Diem hop ly

Hai file `15-phase-3-thang-va-phan-cong-quan-tue.md` va `16-de-cuong-bao-cao-de-tai-ban-giang-vien.md` hien tai nhin chung la hop ly hon truoc rat nhieu, vi da chot duoc cac diem dung:

- Bai toan duoc nang tu scanner portfolio thanh Agentic Hybrid SAST.
- Scope da theo huong depth-first: Python la ngon ngu trong tam, JavaScript/Java/PHP la ngon ngu mo rong.
- Da dua LangGraph vao dung vai tro workflow co state, khong mo ta agent theo kieu noi chuyen tu do.
- Da co benchmark, SARIF, triage statuses, knowledge loading va ablation study.
- Phan cong Quyet/AI va Core/Benchmark da ro hon, khong con bi chong cheo qua nhieu.

### 2.2. Dieu can giu cach dien dat dung

Tuy nhien, khi viet bao cao va bao ve, can giu cach dien dat sau:

- `15` va `16` la kien truc dich va ke hoach nghien cuu, khong phai mo ta implementation da hoan thanh.
- Cac thanh phan nhu `LangGraph multi-agent`, `Knowledge Loader`, `SARIF`, `benchmark harness`, `triage confirmed/likely/needs-review/suppressed` phai duoc viet theo kieu "se xay dung", "de xuat", "muc tieu trien khai".
- Khong nen viet nhu the repo hien tai da co day du CFG, DFG, multi-agent loop hoan chinh, vi dieu do khong dung voi code hien tai.

Noi ngan gon: `15` va `16` dang o muc tot de dung cho do an va nghien cuu, nhung phai bao ve no nhu target architecture, khong bao ve no nhu current implementation.

---

## 3. Hien trang ky thuat cua repo

Duoc doi chieu truc tiep tu code hien tai:

- He thong da co AST parsing da ngon ngu bang Tree-sitter.
- Da co plugin scanner cho Python, JavaScript, Java va PHP.
- Da co rule engine du tren YAML.
- Da co taint-style source -> sink tracking.
- Da co cross-file cho Python thong qua `FunctionIndex` va `ImportResolver`.
- Da co AI verification seed qua Gemini.
- Da co output JSON va Markdown.

Nhung he thong hien tai chua co:

- chua co module CFG rieng
- chua co module DFG rieng
- chua co triage subsystem day du
- chua co LangGraph orchestration that su
- chua co SARIF
- chua co benchmark harness dung nghia

Vi vay, cach mo ta dung nhat cho repo hien tai la:

> Aegis-SAST dang la mot scanner AST-based co taint propagation va Python cross-file analysis o muc thuc dung, chua phai mot graph-based SAST engine day du.

---

## 4. AST, DFG, CFG va Call Graph khac nhau the nao

### 4.1. AST

AST tra loi cau hoi: "doan ma nay duoc viet nhu the nao theo cau truc cu phap?"

AST giup:

- nhan dien ham, bien, lenh goi ham, assignment
- xac dinh source, sink, sanitizer theo pattern cau truc
- xay dung rule parsing on dinh hon regex

AST la lop nen bat buoc. Neu khong co AST thi he thong se rat kho di xa.

### 4.2. DFG

DFG tra loi cau hoi: "du lieu di tu bien nao sang bien nao?"

DFG huu ich cho:

- lan dau vet assignment va propagation
- theo doi bien trung gian
- xac dinh luong taint qua cac phep gan, return, tham so ham
- giam false positive khi chi AST nhin thay source va sink nhung khong biet du lieu co that su truyen den hay khong

Trong de tai nay, DFG khong nhat thiet phai la mot graph hoc thuat day du ngay tu dau. Muc tieu hop ly hon la lam `DFG-lite` phuc vu taint propagation va evidence.

### 4.3. CFG

CFG tra loi cau hoi: "chuong trinh co the di theo nhanh nao?"

CFG huu ich cho:

- biet sink co reachable hay khong
- biet sanitizer xay ra truoc hay sau sink
- xu ly `if/else`, `return`, `loop`, `try/except`
- cai thien path sensitivity

CFG rat quan trong neu muon giam false positive nghiem tuc. Tuy nhien no cung la phan ton cong nhieu effort neu lam full-scale cho da ngon ngu.

Trong pham vi do an nay, hop ly nhat la `CFG-lite`, nghia la khong can dung full graph engine voi moi node/co canh phuc tap, ma uu tien:

- branch-aware evidence
- sanitizer reachability
- dead-path filtering

### 4.4. Call Graph

Call Graph tra loi cau hoi: "ham nao goi ham nao?"

No rat quan trong de:

- di xuyen ham
- di xuyen file
- noi source o file A voi sink o file B

Repo hien tai da co buoc dau cua huong nay cho Python trong `aegis_sast/analysis/call_graph.py`. Day la tai san rat quy cua project va nen giu lam trong tam phat trien tiep.

---

## 5. Tra loi truc tiep: AST co du khong?

Tra loi ngan gon: khong du neu muon lam do an manh va co gia tri nghien cuu.

Tra loi day du hon:

- Neu muc tieu chi la lam scanner demo, AST + rules da du de phat hien nhieu pattern co ban.
- Neu muc tieu la do an nghien cuu ve giam false positive, benchmark va AI triage co bang chung, thi AST mot minh se som cham tran.
- Vi ly do do, Aegis-SAST nen di theo huong:
  - AST la lop nen
  - DFG-lite la buoc nang cap dau tien
  - CFG-lite la buoc nang cap tiep theo
  - Call Graph tiep tuc la lop lien ket xuyen ham/xuyen file
  - LangGraph Agent la lop triage va dieu phoi sau cung

Noi cach khac: muon xay de tai "xinh, kho, co nghien cuu" thi dung la nen co tu duy CFG/DFG, nhung khong nen lao vao viet full CFG/DFG engine cho 4 ngon ngu cung luc.

---

## 6. Huong trien khai phu hop nhat cho Aegis-SAST

### 6.1. Nguyen tac chot scope

- Python la ngon ngu phan tich sau.
- JavaScript, Java, PHP giu vai tro chung minh kien truc da ngon ngu.
- Khong theo duoi full semantic engine cho tat ca ngon ngu trong 3 thang.
- Uu tien gia tri nghien cuu: giam false positive, triage, benchmark, SARIF.

### 6.2. Thu tu nang cap hop ly

#### Giai doan 1: AST + schema + evidence

Can lam truoc:

- chuan hoa `NormalizedFinding`
- them `EvidenceBundle`
- tach ro source, sink, sanitizers, path summary
- bo sung triage statuses vao data model

Neu chua co schema va evidence ro rang thi agent va benchmark deu yeu.

#### Giai doan 2: DFG-lite cho Python

Can lam tiep theo:

- theo doi assignment tu bien sang bien
- theo doi argument -> parameter
- theo doi return value -> variable nhan
- gom duoc path bang chung dep hon cho AI triage

Muc tieu khong phai ve do thi dep ve hoc thuat, ma la lam cho finding co du lieu luong du lieu ro hon.

#### Giai doan 3: CFG-lite cho Python

Chi bo sung nhung gi tac dong truc tiep den false positive:

- branch-aware path
- kiem tra sanitizer co nam tren duong di toi sink hay khong
- loai bo path khong reachable ro rang
- xu ly som `return`/`guard clause`

Day la buoc giup project tu "co taint" sang "co path reasoning" tot hon.

#### Giai doan 4: LangGraph workflow cho triage

Luc nay agent moi that su co gia tri, vi finding da co evidence tot hon:

- Planner/Router
- KnowledgeLoader
- Auditor
- SkepticValidator
- Judge
- Reporter

Neu dung agent qua som, khi core evidence con yeu, thi AI chi dang "doan gium" chu khong triage duoc mot cach thuyet phuc.

#### Giai doan 5: SARIF va benchmark

Khi da co scanner + triage on dinh:

- xuat SARIF
- so sanh voi Semgrep
- neu kip thi so sanh them scope hep voi CodeQL
- lam ablation study

Day moi la lop chung minh gia tri khoa hoc.

---

## 7. De xuat cu the theo tung ngon ngu

### 7.1. Python

Python nen la ngon ngu duy nhat duoc dau tu day du cac lop sau:

- AST
- taint propagation
- DFG-lite
- CFG-lite
- call graph
- LangGraph triage day du
- benchmark chinh

Ly do: repo da co nen Python manh nhat, nen day la noi co kha nang ra dong gop nghien cuu thuc su.

### 7.2. JavaScript

Giu o muc:

- AST parsing
- rule-based detection
- pattern-level evidence
- AI triage o muc co ban

Khong nen dat muc tieu CFG/DFG sau cho JavaScript trong dot do an chinh.

### 7.3. Java

Giu o muc:

- AST/rule-based scanning
- benchmark mo rong co chon loc
- uu tien bo sample co nhan hon la full graph analysis

Neu can benchmark voi Juliet/OWASP Benchmark, Java nen duoc coi la nguon du lieu doi chung, khong phai ngon ngu de xay full engine trong 3 thang.

### 7.4. PHP

Giu o muc:

- AST parsing
- rule matching
- finding normalization
- triage muc co ban

Khong nen day PHP len muc cross-file graph analysis trong scope hien tai.

---

## 8. Mapping vao phan cong Quyet va Tue

### 8.1. Phan cua Quyet

Quyet phu hop phu trach:

- scanner core
- finding schema
- evidence bundle
- DFG-lite Python
- CFG-lite Python
- call graph refinement
- SARIF
- benchmark harness
- baseline comparison voi Semgrep

Day la khoi cong viec co tinh cyber/backend va rat khop voi huong ban da chot.

### 8.2. Phan cua Tue

Tue phu hop phu trach:

- LangGraph orchestration
- knowledge cards
- knowledge loader
- AI triage prompts
- structured outputs
- skeptical validation loop
- ablation study lien quan den agent/knowledge

Day la khoi cong viec AI/agent ro rang, khong bi mo ho.

---

## 9. Kien nghi cap nhat cach bao ve de tai

Khi trinh bay voi giang vien, nen su dung cach noi sau:

1. He thong hien tai da co AST parsing, taint-style analysis, plugin da ngon ngu va Python cross-file.
2. Han che lon nhat hien tai la chua co mo hinh triage day du va chua mo ta data/control flow mot cach ro rang.
3. Dong gop ky thuat cua de tai la nang cap he thong theo huong:
   - Evidence-aware SAST
   - DFG-lite + CFG-lite cho Python
   - LangGraph AI Triage
   - SARIF + benchmark
4. Dong gop nghien cuu nam o cho giam false positive, giai thich finding, va danh gia bang ablation study.

Neu noi theo cach nay, de tai vua "kho", vua "xinh", vua khong overclaim.

---

## 10. Ket luan

Aegis-SAST khong nen dung lai o AST-only neu muc tieu la do an tot nghiep lon hoac nghien cuu khoa hoc. Tuy nhien, huong dung khong phai la xay full CFG/DFG engine cho moi ngon ngu ngay lap tuc.

Huong hop ly nhat la:

- giu AST lam lop nen
- nang Python len DFG-lite va CFG-lite
- giu Call Graph lam tru truc xuyen ham/xuyen file
- dua LangGraph vao lop triage sau khi evidence du manh
- su dung benchmark va SARIF de chung minh gia tri he thong

Do day, cau tra loi thuc te cho cau hoi "ngoai AST co can CFG va DFG khong?" la:

> Co, neu muon de tai manh hon thi nen co. Nhung can trien khai co thu tu, uu tien Python truoc, va chi lam muc `lite` du de giam false positive va tao evidence tot cho AI triage.

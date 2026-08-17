# Giai thich ngan: kien truc Aegis hien tai on o dau, va no refactor o dau

## 1. Muc dich

File nay dung de lam ro mot diem de bi hieu nham:

- vi sao co the noi kien truc Aegis hien tai **on de tiep tuc lam thesis/demo**
- nhung dong thoi van co the noi project **chua du sach de mo rong dashboard/API/PR scan ma khong refactor**

Hai nhan dinh nay khong mau thuan nhau.

## 2. Ket luan cuc ngan

Noi ngan gon:

- **scanner core va huong kien truc tong the dang dung**
- **ranh gioi giua cac lop chua du sach**
- **UI/dashboard vua roi bi roi la van de implementation cua product layer, khong phai bang chung rang core kien truc sai**

## 3. Cai gi dang on that su

### 3.1. Da co scanner core that

Aegis khong con la mot demo "grep + regex".
Repo da co:

- plugin da ngon ngu
- Tree-sitter AST parsing
- rule engine
- taint tracking
- Python cross-file lane
- AI verification / triage seed
- reporting JSON / Markdown / SARIF

Day la ly do project da vuot muc "tool portfolio don gian".

### 3.2. Dinh huong hybrid la dung

Huong di dung cua Aegis la:

- deterministic detection la detector chinh
- AI dung cho triage, explanation, prioritization, remediation draft

Huong nay hop voi:

- thesis scope
- benchmark scope
- product demo scope

### 3.3. Da co normalized finding seed

Du chua sach hoan toan, repo da co huong:

- finding normalization
- evidence bundle
- workflow triage
- reporting layer

Day la nen rat quan trong de sau nay:

- lam dashboard
- lam benchmark
- lam PR mode
- lam SARIF / CI

### 3.4. Product layer co the tach khoi core

Dashboard local doc report JSON la mot quyet dinh dung.
No cho thay product layer co the dung tren:

- exported report
- normalized finding
- local review memory

ma khong can cham truc tiep vao detector internals.

## 4. Cai gi chua on va can refactor

## 4.1. CLI dang om qua nhieu orchestration

Hien tai CLI dang gan nhu vua la:

- intake layer
- service layer
- workflow runner
- reporting trigger
- exit-code controller

Neu de nguyen, sau nay dashboard/API/PR mode rat de:

- goi nguoc vao CLI
- copy logic ra noi khac

Ca hai cach deu xau.

### 4.2. Detector generic dang tron voi Python deep lane

`VulnerabilityDetector` hien tai khong chi la detector generic.
No dang kiem luon:

- project-level orchestration
- post-processing
- Python-specific cross-file handling

Dieu nay lam boundary kho sach khi sau nay muon co:

- Java deep lane
- JavaScript deep lane
- detector service doc lap hon

### 4.3. Models dang song song nhieu shape

Project dang co dau hieu "hai doi song":

- model cu
- model moi / normalized model

Khi workflow, triage, exporter, dashboard cung phai hieu nhieu shape cung luc,
schema se de vo va kho version hoa.

### 4.4. Triage va reporting dang trao doi qua metadata ad-hoc

Day la diem no refactor ro nhat.

Neu triage/workflow/exporter tiep tuc:

- tu ghi key vao metadata
- tu moc key ra o exporter
- tu suy dien status / evidence / route

thi sau nay dashboard va API se rat met de giu on dinh.

Can co contract ro hon, vi du:

- `DetectionFinding`
- `TriageRecord`
- `ReportFinding`

### 4.5. Chua co triage memory seam

Hien tai co triage logic, nhung chua co cho bam on dinh cho:

- reviewer memory
- suppression history
- diff-aware PR review
- reviewed bundle persistence

Noi ngan gon:

- co "triage"
- chua co "triage store"

## 5. Vi sao dashboard roi khong co nghia la kien truc core te

Day la diem can tach rat ro.

Dashboard vua roi bi roi vi:

- bo cuc qua nhieu cot
- findings queue chua du sach
- review actions bi tach thanh cot rieng
- visual hierarchy chua tot

Day la loi cua:

- layout
- information density
- component composition
- UX decision

Khong phai loi cua:

- huong hybrid scanner
- plugin architecture
- normalized finding direction

Noi cach khac:

- **core kien truc co the tiep tuc dung**
- **UI implementation co the viet lai gan nhu doc lap**

Neu boundary giua report va dashboard duoc giu dung, ban co the thay toan bo frontend ma khong can dap scanner core.

## 6. Cach dinh vi trung thuc trong thesis

Noi cho dung va an toan:

### Co the claim

- Aegis la hybrid AI-assisted SAST
- da co deterministic scanner core
- da co evidence-first finding workflow
- da co triage / workflow / reporting seed
- da du de demo reviewable security workflow

### Khong nen claim som

- enterprise-ready platform
- multi-user review platform hoan chinh
- AI thay the detector / taint engine
- autonomous security agent end-to-end

## 7. Muc truong thanh hop ly hien tai

Neu chia maturity thanh 4 muc:

1. toy demo
2. tool portfolio tot
3. thesis/demo-grade system
4. product/platform-ready system

Thi Aegis hien tai hop ly nhat dang o giua:

- cuoi muc 2
- dau muc 3

Nghia la:

- hon tool portfolio don gian
- du lam thesis/demo co chieu sau
- chua phai san pham sach de mo rong dai han ma khong refactor

## 8. Thu tu refactor dung

Neu muon giu dung huong nghien cuu va giam no ky thuat, nen refactor theo thu tu nay:

1. Tach `ScanService` hoac `PipelineService` khoi CLI
2. Tach detector generic khoi `PythonAnalysisContext`
3. Chot contract canonical:
   - `DetectionFinding`
   - `TriageRecord`
   - `ReportFinding`
4. Them `TriageStore` interface, ban dau co the chi la JSON/SQLite
5. Sau do moi day manh:
   - dashboard moi
   - diff-aware PR scan
   - validator second pass
   - remediation validation

Thu tu nay quan trong vi neu lam dashboard hoanh trang truoc khi co contract sach,
frontend sau nay se lai bi dinh vao mot data shape khong on dinh.

## 9. Cau noi ngan co the dung khi bao ve

Co the trinh bay ngan gon nhu sau:

`Kien truc hien tai cua Aegis da du manh de lam mot he thong thesis/demo co scanner core, triage workflow, va product review layer. Tuy nhien, cac boundary giua CLI, detector, triage, va reporting van can duoc lam sach hon de san sang cho dashboard/API/PR scan o cac giai doan tiep theo.`

## 10. Ket luan

Dieu can nho la:

- minh khong danh gia Aegis "te"
- minh dang danh gia no la **co nen rat tot nhung chua du refactor**

Va day la mot danh gia tich cuc, vi no co nghia:

- khong can dap di lam lai
- chi can tach boundary dung cho de mo rong
- dashboard xau hoac roi hien tai khong pha vo gia tri cua scanner core

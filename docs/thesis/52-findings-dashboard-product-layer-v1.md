# Findings Dashboard Product Layer V1 cho Aegis-SAST

## 1. Tai sao can tai lieu nay

Sau khi bo sung dashboard local theo huong `Node.js + React + Next.js + Tailwind`, can chot ro no dung o dau trong kien truc chung cua Aegis-SAST.

Neu khong chot ro, dashboard rat de bi lam theo huong:

- goi truc tiep detector internals;
- gom scan, triage, va review vao mot khoi UI lon;
- kho sua khi schema finding thay doi;
- kho giai thich trong khoa luan rang day la product layer, khong phai mot scanner moi.

Tai lieu nay dung de chot dashboard nhu mot lop san pham phia tren finding normalization va reporting.

## 2. Vi tri cua dashboard trong kien truc dich

Kien truc muc tieu trong file `04-kien-truc-muc-tieu.md` da co 6 lop:

1. `Repo Intake`
2. `Detection Core`
3. `Finding Normalization`
4. `AI Triage`
5. `Remediation and Reporting`
6. `Evaluation and CI`

Dashboard moi nen duoc dat **sau lop 5**, cu the hon la:

- no khong thuoc `Detection Core`;
- no khong can AST parser, taint tracker, hay plugin registry de render UI;
- no nhan input la exported report JSON da duoc normalize/triage;
- no dong vai tro `review console` va `product surface` cho lop reporting.

Noi ngan gon:

- scanner sinh finding
- triage gan status/confidence/evidence
- report exporter ghi JSON
- dashboard doc JSON do de phuc vu con nguoi review

Huong nay giup scanner va dashboard co the tien hoa doc lap.

## 3. Quyet dinh kien truc da chot

### 3.1. Tach app rieng

Dashboard duoc dat trong:

- `apps/findings-dashboard`

Thay vi chen vao CLI hoac mo rong tu `apps/rule_workbench`.

Ly do:

- role khac nhau;
- rule workbench tap trung author/review rule;
- findings dashboard tap trung review finding/report;
- tach ra thi de doi UI, stack frontend, va demo flow hon.

### 3.2. Chi doc report da export

Dashboard khong duoc goi truc tiep vao:

- detector pipeline
- rule engine internals
- taint propagation internals

Thay vao do, dashboard chi doc:

- file JSON ben trong `reports/`
- file JSON import thu cong tu user

Ly do:

- giam coupling voi core;
- cho phep schema duoc version hoa;
- de test bang report snapshot;
- de demo ma khong can scan lai moi lan.

### 3.3. Dung adapter thay vi bind cung mot schema duy nhat

Report trong repo hien tai co nhieu dang:

- workflow/rich report moi
- triage smoke report
- legacy report co `ai_verification`

Vi vay, dashboard da co:

- `report-types.ts` cho schema UI
- `report-adapter.ts` cho bridge tu report that sang schema do

Day la diem rat quan trong cho maintainability:

- core co the cai tien report sau nay;
- adapter duoc sua cuc bo;
- UI component khong can biet report den tu phien ban nao.

### 3.4. Reviewer memory la local lane truoc

Feedback hien tai duoc luu bang:

- `localStorage`

Gom:

- `disposition`
- `note`
- `muted`

Day la chon lua P0 hop ly vi:

- khong can database ngay;
- cho duoc demo feedback loop;
- khong lam ban finding report goc;
- co the export JSON de noi voi reviewed bundles sau.

### 3.5. API route phai co boundary an toan

Route `app/api/reports/route.ts` chi doc trong:

- `reports/`

Va co check path traversal khi nap report cu the.

Day la chon lua dung ve kien truc:

- UI co data access layer ro rang;
- route nay co the thay bang DB/service sau nay;
- frontend khong can biet workspace absolute path.

## 4. Thanh phan hien tai cua dashboard

### 4.1. Data layer

- `src/lib/report-types.ts`
- `src/lib/report-adapter.ts`
- `src/lib/report-loader.ts`
- `src/lib/review-store.ts`

Vai tro:

- normalize finding
- map severity/status/confidence
- bridge legacy report
- luu reviewer feedback local

### 4.2. Server access layer

- `src/app/api/reports/route.ts`

Vai tro:

- list report summaries
- tra selected report detail
- khoa truy cap trong `reports/`

### 4.3. UI layer

- `report-sidebar`
- `filter-toolbar`
- `metric-strip`
- `finding-queue`
- `finding-detail`
- `status-badge`
- `dashboard-shell`

Cach chia nay on vi:

- component theo responsibility ro;
- detail pane khong can biet logic load report;
- queue khong can biet route API;
- shell giu vai tro ghep state va workflow review.

## 5. Danh gia kien truc hien tai: on chua

Ket luan ngan:

- **on cho V1 va rat de mo rong hon cach lam chen vao CLI**

Nhung can noi that:

- day chua phai production multi-user dashboard;
- reviewer memory moi o local;
- chua co auth, DB, hay workflow team review;
- chua co grouping/root-cause lane;
- chua co remediation workflow thuc su.

Tuy nhien, voi scope khoa luan va product demo, kien truc nay la hop ly vi no:

1. ton trong ranh gioi giua core va product UX;
2. dung report schema lam contract;
3. cho phep mo rong dan ma khong phai dap scanner core;
4. phu hop huong hybrid: deterministic detection + AI triage/filtering + UI review.

## 6. Diem manh ky thuat de neu trong khoa luan

### 6.1. Product layer tach khoi detector

Day la y quan trong nhat de thuyet phuc:

- Aegis khong dung dashboard de "ve giao dien cho vui"
- ma dung dashboard de bien finding triage thanh workflow review that

### 6.2. Backward compatibility

Viec adapter ho tro ca report moi va report legacy la bang chung rang:

- architecture co tinh tien hoa;
- repo co the giu duoc du lieu benchmark cu;
- UX layer khong bi vo moi khi doi report version.

### 6.3. Reviewer memory la buoc dem hop ly

Vendor patterns nhan manh feedback loop.

V1 cua Aegis chua can DB ngay, nhung da co:

- schema cho reviewer feedback
- export lane
- cho dung de noi voi reviewed bundles sau nay

## 7. Khoang trong ky thuat can uu tien tiep

### P0

- them reviewed-bundle export/import cho feedback local
- chi hien finding `confirmed` va `likely` trong lane share/comment
- refine normalized `TriageDecision` de UI khong can suy dien qua nhieu

### P1

- diff-aware PR scan
- validator second pass
- chi comment finding high-confidence

### P2

- remediation draft
- rescan validation
- status `resolved` co bang chung

### P3

- finding grouping theo root cause/source/sink
- reviewer/team memory tap trung
- workflow orchestration sau hon

## 8. Dieu khong nen lam ngay

Khong nen:

- bien dashboard thanh noi goi thang detector internals
- tron rule workbench va findings dashboard vao cung mot app
- nhay thang sang multi-user auth/database lon neu chua can
- claim dashboard nay da la "enterprise platform"

Scope an toan va dung hon la:

- local review console
- evidence explorer
- feedback loop lane dau tien
- product surface cho report da normalize

## 9. Demo value

Voi dashboard nay, demo cua Aegis manh hon CLI thuan o 4 diem:

1. thay duoc finding queue co su uu tien
2. thay duoc confidence va explanation cua AI triage
3. thay duoc evidence path, source/sink context, agent reviews
4. thay duoc reviewer feedback loop thay vi chi xem JSON tho

Day la phan rat hop de trinh bay voi giang vien vi no noi duoc:

- he thong da khong chi "scan ra finding"
- ma da co huong den "reviewable security workflow"

## 10. Ket luan

Kien truc project sau khi them dashboard la **on hon truoc** neu giu dung 3 nguyen tac:

1. detector va dashboard tach nhau
2. report schema la contract trung gian
3. feedback loop duoc them dan tren product layer, khong chen nguoc vao core

Neu giu dung huong nay, viec sua va mo rong sau nay se de hon nhieu so voi cach lam mot khoi monolithic scan + triage + UI.

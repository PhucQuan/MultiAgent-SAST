# Dashboard Redesign Spec V2 cho Aegis Findings Desk

## 1. Muc tieu cua tai lieu nay

Tai lieu nay dung de tach rieng phan **thiet ke UI/UX** cua findings dashboard khoi phan code hien tai.

Muc tieu:

- giai thich vi sao ban dashboard vua roi trong bi chan chit;
- chot lai mot huong thiet ke gon, de mo rong, va hop voi Aegis-SAST;
- cho phep giao viec code lai cho AI khac hoac frontend dev ma khong can doc toan bo implementation cu;
- giu dung boundary kien truc: dashboard la `product layer`, khong goi detector internals.

## 2. Chan doan: vi sao ban hien tai bi roi

Ban dang xem co cam giac "chan chit" chu khong phai "enterprise dashboard" vi 6 ly do chinh:

### 2.1. Qua nhieu cot hien cung luc

Layout vua co:

- app rail;
- report explorer;
- metric strip;
- findings queue;
- detail pane;
- reviewer actions pane.

Tat ca deu mo cung luc tren mot viewport ngang, lam mat khong gian cho noi dung quan trong nhat la findings table va finding detail.

### 2.2. Khong co mot truc uu tien ro rang

Trang dang co qua nhieu khoi co visual weight ngang nhau:

- metrics;
- queue;
- detail;
- actions;
- report summary.

Nguoi dung khong duoc "dan mat" vao lan luot:

1. chon report
2. loc finding
3. chon finding
4. review finding
5. ghi feedback

### 2.3. Findings queue chua la mot bang review dung nghia

Phan giua dang o giua card list va table:

- dong cao;
- badge nhieu;
- title xuong dong nhieu;
- location bi cat xau;
- cot review qua hep.

Ket qua la no khong co cam giac "security workbench" ma giong mot demo layout.

### 2.4. Review actions bi tach thanh mot cot rieng

Day la nguyen nhan rat lon lam UI bi roi.

Reviewer actions la **hanh dong tren finding dang duoc chon**, vi vay no nen nam trong detail pane hoac la tab ben trong detail, khong nen la mot cot doc lap luon luon mo.

### 2.5. Qua nhieu pill, badge, border, va bo goc

Ban vua roi co rat nhieu:

- pills cho title;
- pills cho summary;
- pills cho language/family/status;
- border card lap di lap lai;
- panel bo goc nhieu.

Neu dung qua tay, light theme se rat de bi "noi gi cung quan trong".

### 2.6. Chua toi uu theo loai san pham

Dashboard nay khong phai landing page.
No la mot cong cu review finding cho SAST.

Voi loai san pham nay, nen uu tien:

- bang;
- sidebar gon;
- detail pane ro rang;
- visual hierarchy nghiem tuc;
- mat do thong tin vua phai;
- it trang tri, nhieu kha nang scan bang mat.

## 3. Dinh huong thiet ke moi can chot

### 3.1. Cam hung san pham

Huong can theo:

- Datadog Code Security
- Snyk Code
- GitHub Security / alerts table

Khong theo:

- AI glassmorphism
- marketing SaaS hero
- dashboard "du mau, du badge"
- layout co qua nhieu box ngang nhau

### 3.2. Tinh cach giao dien

Giao dien can:

- nghiem tuc;
- sach;
- goc canh vua phai;
- enterprise;
- light theme;
- uu tien kha nang review hon la "wow effect".

### 3.3. Nhanh gon ve thong diep

Thong diep cua trang khong phai:

- "Aegis co AI"

Ma la:

- "Day la noi review static code findings co triage va evidence"

## 4. Nguyen tac UX phai giu

1. `Queue first`: trung tam la bang finding, khong phai metric card.
2. `One selected item at a time`: moi hanh dong deu gan voi finding dang duoc chon.
3. `Detail belongs to selection`: actions phai nam trong detail pane.
4. `Filters stay compact`: filter la thanh cong cu, khong phai mot section hoanh trang.
5. `Badges are supporting, not dominant`: badge de scan nhanh, khong de lam nois.
6. `Explorer is secondary`: report explorer chi la bo dieu huong, khong duoc tranh do noi bat voi queue.
7. `The scanner stays separate`: UI chi doc normalized report JSON va review memory.

## 5. Layout de xuat moi

## 5.1. Desktop

Bo cuc desktop nen chuyen thanh **3 cot chinh**, khong phai 4 cot lon:

1. `Left explorer` - 260px den 280px
2. `Main review queue` - chiem rong nhat
3. `Right detail pane` - 420px den 500px

App rail co the giu neu muon, nhung nen rat nhe va co the bo hoan toan o V2 neu chua can.

### 5.2. Thanh top bar

Chi nen co 1 top bar gon:

- ten module: `Static Code Findings`
- report dang mo
- 2 den 3 KPI ngan: `Actionable`, `Needs review`, `Reports loaded`
- nut `Import report` hoac `Refresh`

Khong dung hero header cao.

### 5.3. Explorer ben trai

Explorer can co 3 khoi:

1. `Reports`
2. `Quick actions`
3. `Saved reports list`

Khong can metric lon trong explorer.
`Reviewer memory` co the la mot dong thong tin nho, khong can card to.

### 5.4. Khu vuc trung tam

Khu vuc giua phai la:

1. summary strip gon
2. filter toolbar mot hang
3. findings table chiem phan lon chieu cao

Day la khu vuc quan trong nhat.

### 5.5. Detail pane ben phai

Detail pane nen gom cac tab hoac section theo thu tu:

1. `Overview`
2. `Evidence`
3. `Review`

Neu khong muon dung tab, co the dung mot pane doc voi section ro rang.
Nhung `Review actions` phai nam trong pane nay, khong tach thanh cot doc lap.

## 6. Cau truc man hinh de xuat

## 6.1. Top bar

Noi dung:

- Module title: `Static Code Findings`
- Subtitle: `Local review console for exported Aegis reports`
- Active report:
  - `shortName`
  - `scanProfile`
  - `timestamp`
  - `totalFindings`
- Quick stats:
  - `Actionable`
  - `Needs review`
  - `Suppressed or muted`

Hanh dong:

- `Import JSON`
- `Refresh reports`
- tuy chon `Export feedback`

## 6.2. Report explorer

Moi report item nen hien:

- short name
- target path rut gon
- report kind
- total findings
- actionable count
- timestamp

Trang thai chon report:

- vien trai xanh hoac background xanh rat nhat
- khong dung glow
- khong dung shadow manh

## 6.3. Summary strip

Thay vi 4 card to, dung 1 strip ngang chia ngan:

- Visible
- Actionable
- Needs review
- Reviewed locally

Tat ca cung style, cung chieu cao, dung mat do gon.

## 6.4. Filter toolbar

Filter toolbar can rat compact:

- search
- status
- severity
- language
- family
- include muted

Search placeholder nen thuc te:

- `Search by file, family, reason code, or note`

Khong nen dung text kieu search DSL neu backend chua ho tro.

## 6.5. Findings table

Can chuyen thanh **table-like review queue**.

Cot de xuat:

1. `Severity`
2. `Title`
3. `Location`
4. `Family`
5. `Status`
6. `Confidence`
7. `Reviewer state`

Neu thieu chieu rong, co the gom lai thanh:

1. `Risk`
2. `Finding`
3. `Location`
4. `Review`

Moi dong finding:

- dong cao vua phai
- title 1 den 2 dong
- location 1 dong
- chi giu 1 den 2 tag phu
- selected row co left border ro
- row hover nhe

Khong de finding card cao nhu card marketing.

## 6.6. Detail pane

Detail pane can co:

### Overview

- title
- severity
- status
- confidence
- language
- file path + line
- explanation
- recommendation
- manual review flag

### Evidence

- evidence path
- source context
- sink context
- graph slice
- workflow route
- reason codes

### Review

- reviewer disposition
- mute/unmute
- reviewer note
- clear/reset state
- last updated

Neu co `agentReviews`, cho vao `Evidence` hoac `Analysis`.

## 7. Chuc nang can co trong V2

1. List report JSON trong `reports/`
2. Import report JSON thu cong
3. Refresh report list
4. Chon mot report
5. Hien report summary
6. Search finding
7. Loc theo status
8. Loc theo severity
9. Loc theo language
10. Loc theo family
11. Toggle `include muted`
12. Chon mot finding
13. Hien detail finding
14. Gan reviewer disposition
15. Mute / unmute finding
16. Ghi reviewer note
17. Reset local review state
18. Export feedback local

## 8. Mapping du lieu hien tai vao giao dien moi

Dashboard moi van phai chi doc du lieu tu cac schema da co:

### Tu `NormalizedReport`

- `shortName`
- `target`
- `timestamp`
- `scanProfile`
- `frameworkHints`
- `reportKind`
- `totalFindings`
- `severitySummary`
- `triageSummary`

### Tu `NormalizedFinding`

- `message`
- `family`
- `severity`
- `status`
- `confidence`
- `language`
- `filePath`
- `line`
- `explanation`
- `recommendation`
- `evidencePath`
- `sourceContext`
- `sinkContext`
- `graphSlice`
- `knowledgeCards`
- `reasonCodes`
- `workflowRoute`
- `agentReviews`
- `reasoningNotes`
- `manualReviewRequired`

### Tu `ReviewerFeedback`

- `disposition`
- `note`
- `muted`
- `updatedAt`

## 9. Ngon ngu giao dien can doi lai

Nen doi copy cho ngan, de hieu, va enterprise hon:

- `Aegis Findings Desk` -> `Static Code Findings`
- `Next steps` -> `Review`
- `Reviewer touched` -> `Reviewed locally`
- `Pulling the normalized finding bundle` -> `Loading report details`
- `This vulnerability was assessed by the Aegis triage layer` -> `AI triage summary`

## 10. He thong visual can chot

### 10.1. Typography

- Font: IBM Plex Sans hoac Inter deu duoc
- Heading rat tiet che
- Body text 14px den 15px
- Table text 13px den 14px
- Monospace chi cho code context

### 10.2. Mau sac

Base:

- background xam rat nhat
- surface trang
- border xam xanh nhat
- text xanh den dam
- accent xanh duong enterprise

Severity:

- critical: do nhat
- high: cam nhat
- medium: vang nhat
- low/info: xanh nhat

Status:

- confirmed: xanh dam hon
- likely: xanh nhat
- needs-review: vang/cam nhat
- suppressed: xam

### 10.3. Bo goc va border

- panel: 8px den 10px
- input: 6px den 8px
- table row: vuong hon card
- border la chinh, shadow rat tiet che

### 10.4. Khoang cach

- dung he 4/8px
- giam padding ngang o nhung panel phu
- uu tien them rong cho findings table

## 11. Responsive behavior

### 11.1. Laptop/desktop

- explorer trai
- queue giua
- detail phai

### 11.2. Tablet

- explorer thu gon
- detail co the mo thanh drawer ben phai

### 11.3. Mobile

- bo app rail
- explorer thanh sheet/drawer
- queue thanh list
- detail mo full screen khi chon finding
- review actions nam o trong detail, khong tach panel

## 12. Nhung dieu tuyet doi nen tranh

Khong lam:

- hero header cao
- glassmorphism
- gradient trang tri lon
- qua nhieu badge tren moi dong
- 4 cot chinh deu quan trong nhu nhau
- tach reviewer actions thanh cot doc lap
- text placeholder kieu "AI copilot"
- tu "agent" xuat hien qua nhieu trong UX chinh

## 13. Pham vi implementation hop ly cho AI khac

AI khac chi nen code:

- page layout
- reusable components
- mock data hoac adapter boundary
- local review state
- compact table + detail pane

Khong nen tu y code lai:

- detector core
- rule engine
- triage engine
- AST logic
- report generation logic

## 14. Acceptance criteria cho ban redesign

Ban redesign duoc xem la on khi:

1. Khong con cam giac chan chit tren viewport 1366px.
2. Findings queue la khu vuc noi bat nhat.
3. Reviewer actions nam trong detail pane, khong tach thanh cot rieng.
4. Mot row finding co the scan trong 1 den 2 giay.
5. Khong qua 2 dong badge/tag cho moi finding.
6. Active report va filters de hieu trong 5 giay dau.
7. Light theme nhin nghiem tuc, khong "AI slop".
8. Van giu dung architecture: UI chi doc exported JSON va local feedback.

## 15. Ket luan

Huong dung cho V2 khong phai la "them design cho dep hon", ma la:

- giam bot so cot;
- dua review action vao detail;
- bien queue thanh mot bang review that su;
- giu dashboard o dung vai tro product layer cho finding workflow.

Neu AI khac code lai theo dung spec nay, kha nang cao la UI se sach va hop ly hon ban implementation vua roi.

# Dashboard Functional Content Checklist cho Aegis

## 1. Muc dich

Tai lieu nay la danh sach **noi dung va chuc nang phai co** de AI khac hoac frontend dev co the implement dashboard ma khong can suy doan.

No dung nhu mot `handoff checklist`.

## 2. Pham vi man hinh

Dashboard nay la:

- local review console cho exported Aegis report JSON;
- khong phai scanner engine;
- khong phai rule authoring app;
- khong phai CI portal;
- khong phai autonomous agent console.

## 3. Data source duoc phep dung

Chi dung:

- report JSON trong `reports/`
- report JSON do user import thu cong
- local reviewer feedback store

Khong dung:

- detector internals
- AST internals
- taint engine internals
- direct call vao CLI process moi lan user click

## 4. Danh sach module tren man hinh

## 4.1. Top bar

Phai co:

- page title
- active report summary
- quick stats ngan
- import report
- refresh reports

Co the co:

- export feedback

## 4.2. Report explorer

Phai co:

- report tabs hoac section labels
- danh sach saved reports
- selected report state
- report metadata co ban

Moi report item toi thieu hien:

- shortName
- target
- reportKind
- totalFindings
- actionable count
- timestamp

## 4.3. Summary strip

Phai co 4 gia tri:

- visible queue
- actionable
- needs review
- reviewed locally

## 4.4. Filter toolbar

Phai co:

- text search
- status filter
- severity filter
- language filter
- family filter
- include muted checkbox

## 4.5. Findings queue

Phai co:

- selected row state
- hover state
- severity
- finding title
- location
- status
- confidence
- reviewer override state neu co

Nen co:

- family
- 1 hoac 2 secondary tags

Khong nen:

- qua 3 tag phu tren moi row

## 4.6. Detail pane

Phai co:

- finding title
- severity
- triage status
- confidence
- file path
- line
- language
- explanation
- recommendation
- evidence path
- source context
- sink context
- manual review flag neu co

Neu co du lieu thi hien them:

- graph slice
- workflow route
- reason codes
- knowledge cards
- agent reviews

## 4.7. Review section

Phai co:

- set disposition:
  - confirmed
  - needs-review
  - false-positive
  - suppressed
- mute/unmute
- textarea note
- save note
- reset local state
- last updated

## 5. Empty / loading / error states

Phai co:

### 5.1. Chua co report

Noi dung:

- thong bao khong co report
- goi y import JSON hoac chay CLI scan

### 5.2. Dang load report detail

Noi dung:

- loading detail state ro rang
- khong lam mat layout

### 5.3. Khong co finding theo filter

Noi dung:

- thong bao queue rong
- goi y clear filter hoac include muted

### 5.4. Loi doc report

Noi dung:

- banner error ngan
- noi ro file nao loi neu co

## 6. Cau truc noi dung chi tiet

## 6.1. Copy de xuat cho top bar

Title:

- `Static Code Findings`

Subtitle:

- `Review exported Aegis reports with AI triage context`

Quick stats labels:

- `Actionable`
- `Needs review`
- `Muted hidden`
- `Reports loaded`

## 6.2. Copy de xuat cho report explorer

Section title:

- `Reports`

Actions:

- `Import JSON`
- `Refresh`
- `Export feedback`

Memory box:

- `Reviewer memory`
- `Local suppressions, notes, and overrides`

## 6.3. Copy de xuat cho findings queue

Section title:

- `Review queue`

Column labels:

- `Risk`
- `Finding`
- `Location`
- `Review`

Search placeholder:

- `Search by file, family, reason code, or note`

## 6.4. Copy de xuat cho detail pane

Sections:

- `Overview`
- `Evidence`
- `Review`
- `AI triage summary`
- `Recommendation`
- `Source context`
- `Sink context`
- `Evidence path`

## 7. Mapping field du lieu -> UI label

### Report level

- `shortName` -> report title
- `target` -> target path
- `timestamp` -> scan time
- `scanProfile` -> profile badge
- `reportKind` -> report type badge
- `totalFindings` -> finding count
- `triageSummary.confirmed + triageSummary.likely` -> actionable count
- `triageSummary["needs-review"]` -> needs review count

### Finding level

- `message` -> row title
- `severity` -> risk badge
- `status` -> triage badge
- `confidence` -> confidence badge or text
- `filePath + line` -> location
- `family` -> secondary tag
- `reasonCodes` -> optional secondary tags
- `explanation` -> triage summary body
- `recommendation` -> recommendation block
- `evidencePath` -> source to sink list
- `sourceContext` -> source code panel
- `sinkContext` -> sink code panel
- `workflowRoute` -> workflow info
- `graphSlice` -> evidence metrics
- `agentReviews` -> supporting analysis
- `manualReviewRequired` -> warning state

### Review memory level

- `disposition` -> reviewer override
- `note` -> note textarea value
- `muted` -> muted state
- `updatedAt` -> last updated

## 8. Uu tien implementation

### P0 bat buoc

- 3-column layout
- compact filters
- dense findings table
- detail pane co review actions ben trong
- import/export feedback
- local review memory

### P1 nen co

- tabs trong detail pane
- keyboard-friendly row selection
- sticky detail pane
- empty/error polish

### P2 co the de sau

- sort controls
- grouping theo root cause
- reviewed bundle import/export
- diff-aware PR mode

## 9. Tieu chi danh gia sau khi code xong

1. Nguoi xem hieu layout trong 5 giay.
2. Khong con cam giac moi panel dang "la trung tam".
3. Findings table scan duoc nhanh.
4. Khong co chong cheo text va badge.
5. Detail pane de doc hon queue.
6. Reviewer actions nam dung cho: trong detail.
7. Dashboard van dung duoc voi report legacy va report rich.

## 10. Ket luan

Neu AI khac can mot checklist thuc thi, chi can dua file nay va file spec V2 la du.
Hai file do da tach ro:

- giao dien can trong nhu the nao
- man hinh phai co nhung gi
- du lieu nao duoc phep dung
- nhung gi khong duoc code lech scope

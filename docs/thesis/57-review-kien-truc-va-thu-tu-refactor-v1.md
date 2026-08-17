# Review kien truc va thu tu refactor V1 cho Aegis-SAST

## 1. Muc dich

File nay quy doi nhan dinh kien truc thanh mot tai lieu on dinh de dung trong thesis va de lam moc ky thuat cho refactor.

Muc tieu:

- chot Aegis hien tai manh o dau;
- chot seam nao chua sach;
- chot thu tu refactor hop ly truoc khi day manh dashboard, API, va PR scan.

## 2. Ket luan ngan

Kien truc hien tai cua Aegis:

- da vuot muc mot tool portfolio don gian;
- du tot de tiep tuc lam thesis/demo;
- nhung chua du sach de mo rong dashboard/API/PR scan ma khong refactor.

Noi ngan gon:

- diem manh la detection core va huong normalized finding;
- diem yeu la boundary giua `CLI -> detector -> triage/workflow -> reporting`.

## 3. Diem manh hien tai

### 3.1. Da co scanner core that

Repo da co:

- plugin da ngon ngu;
- Tree-sitter AST parsing;
- rule engine;
- taint tracking;
- Python cross-file lane;
- JSON / Markdown / SARIF export;
- AI verification / triage seed.

Day la nen tang du de claim Aegis la mot scanner co chieu sau, khong chi la rule matcher don gian.

### 3.2. Huong hybrid la dung

Aegis dang di theo huong hop ly:

- deterministic scanner la detector chinh;
- AI dung de triage, explanation, prioritization, va remediation draft.

Huong nay hop voi:

- thesis scope;
- benchmark scope;
- product demo scope.

### 3.3. Da co huong normalized finding

Repo da co seed rat quan trong cho cac buoc sau:

- finding normalization;
- evidence bundle;
- workflow triage;
- reporting layer.

Day la nen de:

- lam dashboard;
- lam benchmark export;
- lam diff-aware PR lane;
- lam reviewed bundles va triage memory.

## 4. Cac seam chua sach can chot

## 4.1. CLI dang om qua nhieu orchestration

`aegis_sast/cli.py` hien tai dang om gan nhu toan bo orchestration:

- sua config;
- khoi tao registry;
- repo intake;
- detector run;
- AI verify;
- triage workflow;
- export report;
- exit code policy.

Dieu nay lam CLI tro thanh mot "service layer an trong command entrypoint".

He qua:

- kho tai su dung cho web/API/dashboard;
- de roi vao the copy logic ra noi khac;
- hoac dashboard/API se phai goi nguoc vao CLI, la mot huong xau.

## 4.2. Detector generic dang tron voi Python deep lane

`aegis_sast/analysis/vulnerability_detector.py` hien tai khong chi la generic detector.
No dang tron nhieu vai tro:

- file/project analysis orchestration;
- rule resolution;
- post-processing;
- dedupe;
- severity / renumbering;
- Python-specific cross-file handling.

Cung luc do, contract plugin trong `aegis_sast/core/plugin_interface.py` dang co dau hieu "generic tren giay, Python-centric trong thuc te", vi Python plugin moi la noi that su can:

- `call_graph`
- `import_resolver`
- `visited_funcs`

He qua:

- boundary plugin de vo neu sau nay muon co `Java deep lane` hoac `JS deep lane`;
- detector generic bi dinh chat vao Python lane hien tai;
- kho tach thanh service phan tich da ngon ngu sach hon.

## 4.3. Models dang song song giua shape cu va shape moi

`aegis_sast/core/models.py` hien tai dang giu ca:

- `NormalizedFinding`
- `Vulnerability`

Huong normalized finding la dung, nhung `Vulnerability` van con:

- AI verification;
- triage status suy dien;
- evidence bundling;
- conversion logic;
- data cho exporter.

He qua:

- workflow phai song chung voi hai shape du lieu;
- contract giua detection, triage, va reporting chua that su canonical;
- de sinh bug schema khi them dashboard, API, hoac benchmark exporter.

## 4.4. Triage/workflow/reporting dang trao doi qua metadata ad-hoc

Day la seam no refactor ro nhat.

Cac thanh phan hien tai dang trao doi bang cach:

- ghi key vao nested metadata;
- ghi lai o top-level metadata;
- exporter tu moc tung key ra.

Cac noi gay no ky thuat ro nhat:

- `aegis_sast/triage/engine.py`
- `aegis_sast/orchestration/nodes.py`
- `aegis_sast/triage/ai_runner.py`
- `aegis_sast/reporting/json_exporter.py`
- `aegis_sast/reporting/markdown_exporter.py`
- `aegis_sast/integrations/sarif_formatter.py`

He qua:

- report contract kho version hoa;
- API/dashboard phai hieu metadata shape phuc tap;
- benchmark export kho on dinh;
- moi lan doi workflow se de vo exporter.

## 4.5. Workflow hien tai stateless va chua co triage memory seam

Workflow layer da co shape tuong doi tot:

- `ScanWorkflow`
- `ScanWorkflowState`
- `TriageEngine`

Nhung hien tai no van la mot flow in-memory cho tung lan scan.

Chua co seam on dinh cho:

- reviewer memory;
- suppression history;
- reviewed bundle persistence;
- diff-aware PR decisions;
- remediation validation state.

Noi ngan gon:

- co triage logic;
- chua co triage store.

## 5. Thu tu refactor dung

Refactor nen di theo thu tu nay, de tranh lam frontend som trong khi data contract chua sach.

### Buoc 1. Tach `ScanService` hoac `PipelineService` khoi CLI

Muc tieu:

- CLI chi con parse args + render output + exit code;
- service layer chiu trach nhiem orchestration.

Ket qua mong muon:

- web/API/dashboard co the goi service cung mot contract;
- tranh copy logic tu CLI.

### Buoc 2. Tach detector thanh 3 lop ro hon

Nen tach ra:

1. `repo/file intake`
2. `language analysis context`
3. `post-processing`

Va dua Python deep analysis vao mot `PythonAnalysisContext` rieng thay vi nhat trong generic detector.

Ket qua mong muon:

- generic detector sach hon;
- Python lane sau van manh;
- de mo rong sang JS/Java deep lane.

### Buoc 3. Chot contract canonical

Nen chot mot chain ro rang:

- `DetectionFinding`
- `TriageRecord`
- `ReportFinding`

Tu do:

- detection khong tuom luon triage metadata;
- exporter chi consume `ReportFinding`;
- dashboard/API chi consume report contract on dinh.

### Buoc 4. Them `TriageStore` interface som

Ban dau co the rat don gian:

- JSON
- SQLite

Nhung can co interface ro de cam duoc:

- reviewer memory;
- suppression history;
- reviewed bundle provenance;
- diff-aware state.

### Buoc 5. Sau do moi day manh productization

Chi sau khi 4 buoc tren on hon moi nen day manh:

- dashboard moi;
- PR mode;
- diff-aware scan;
- validator second pass;
- remediation validation loop.

## 6. Mapping theo 4 nhom de viet thesis

## 6.1. Current implementation

Aegis da co:

- scanner core;
- plugin da ngon ngu;
- Python graph lane;
- AI triage seed;
- reporting seed;
- normalized finding direction.

## 6.2. Engineering gaps

Can uu tien:

1. service boundary tach khoi CLI;
2. generic detector sach hon;
3. canonical finding contract;
4. triage metadata thoi ad-hoc;
5. triage store / memory seam.

## 6.3. Research contribution

Dong gop hop ly nhat hien tai la:

- evidence-first hybrid SAST;
- deterministic detection + AI triage;
- workflow triage tren finding da normalize;
- Python deep lane cho cac family uu tien.

## 6.4. Demo value

Demo dep nhat se la:

1. scan target
2. triage workflow
3. dashboard doc report da normalize
4. reviewer feedback
5. remediation draft + rescan

## 7. Nhung gi khong nen lam truoc

Khong nen uu tien som hon cac seam tren:

- dashboard hoanh trang nhung report contract chua sach;
- API schema versioning khi exporter con moc metadata ad-hoc;
- multi-language deep lane moi khi detector generic chua duoc tach boundary;
- reviewer memory that su khi chua co `TriageStore`.

## 8. Gia tri cua nhan dinh nay

Nhan dinh "kien truc on nhung chua du sach" la mot nhan dinh tich cuc va trung thuc.

No co nghia:

- khong can dap di lam lai scanner core;
- co the tiep tuc thesis/demo ngay;
- nhung nen refactor dung thu tu de tranh no ky thuat lon hon sau nay.

## 9. Ket luan

Neu phai chot chi mot cau:

`Aegis hien tai da co scanner core du manh va huong kien truc dung de lam thesis/demo, nhung can lam sach boundary giua CLI, detector, triage, va reporting truoc khi mo rong dashboard/API/PR scan o muc nghiem tuc hon.`

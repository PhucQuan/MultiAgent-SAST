# Roadmap sau Rule Workbench V1 cho Aegis-SAST

## 1. Muc dich cua file nay

File nay chot ro thu tu phase tiep theo sau khi repo da co:

- normalized rule schema;
- importer subset;
- validator;
- review bundle;
- legacy bridge;
- va scaffold `Rule Workbench V1`.

No khong thay the file `35`, `36`, `37`, `38`.
No dung de tra loi cau hoi thuc te:

- sau khi co web workbench roi thi lam gi tiep;
- phase nao uu tien truoc;
- phase nao de sau;
- va phase nao khong duoc dao nguoc neu muon giu scope khoa luan dep.

## 2. Trang thai dau vao hien tai

Tinh den moc nay, repo da co 3 cum nen tang quan trong:

### 2.1. Scanner Python da sach hon truoc

- da co cleanup exact-call matching;
- da co detector dedupe;
- da co fix cross-file provenance;
- da co exclude profile cho scan wrapper.

### 2.2. Rule ingestion V1 da vao form

- da co normalized schema;
- da co importer cho Semgrep-shaped subset;
- da co validator;
- da co review bundle script;
- da co legacy bridge de scan thu nghiem voi `--rules`.

### 2.3. Rule Workbench V1 da co scaffold

- da co backend nho quanh `RuleWorkbenchService`;
- da co launcher script de chay local;
- da co frontend tinh de chon seed, build bundle, va preview artifacts.

Nghia la:

- repo da qua moc "chi co y tuong";
- nhung chua toi moc "co benchmark va bang chung khoa hoc day du".

## 3. Nguyen tac giu thu tu phase

Sau moc nay, thu tu hop ly phai la:

1. workbench chay that voi 1 family nho;
2. review bundle that tren corpus nho;
3. benchmark mini voi Semgrep;
4. roi moi them AI drafting bang ngon ngu tu nhien;
5. sau do moi nang detector contract va triage nang cao.

Khong nen dao nguoc thanh:

- them AI generation truoc khi co benchmark;
- import nhieu rule truoc khi co review bundle that;
- hay pitch workbench nhu detector moi.

## 4. Phase 1 - Van hanh that Rule Workbench V1

### Muc tieu

Bien scaffold web thanh mot luong van hanh duoc, khong chi la demo UI.

### Viec can lam

1. chay workbench local voi `COMMAND_INJECTION`;
2. build 1 reviewed bundle that tu seed fixture;
3. luu artifact vao `reports/rule_review/`;
4. ghi ro bundle nao la draft, bundle nao da review;
5. viet runbook ngan de nguoi khac chay lai duoc.

### Deliverables

- 1 reviewed bundle Python cho `COMMAND_INJECTION`;
- 1 huong dan chay local ngan;
- 1-2 anh/chup minh hoa cho bao cao hoac demo.

### Push gate

- bundle build on dinh qua web va qua CLI;
- artifact preview doc duoc;
- duong dan output va provenance ro rang.

## 5. Phase 2 - Mo rong reviewed bundles cho 3 family V1

### Muc tieu

Khong dung lai o `COMMAND_INJECTION`, ma hoan tat bo 3 family da chot scope.

### Thu tu uu tien

1. `COMMAND_INJECTION`
2. `PATH_TRAVERSAL`
3. `INSECURE_DESERIALIZATION`

### Viec can lam

1. bo sung seed fixtures hoac local seed snapshots cho tung family;
2. review source/sink/sanitizer cua tung family;
3. export legacy bridge cho tung reviewed bundle;
4. ghi note rule nao giu, rule nao bo, va vi sao.

### Deliverables

- 3 reviewed bundles V1;
- 3 validation reports;
- 3 legacy bridge outputs de scan thu nghiem.

### Luu y

Van giu nguyen nguyen tac:

- khong import full registry;
- khong copy raw rules wholesale vao repo public;
- khong cho AI nap rule thang vao detector runtime.

## 6. Phase 3 - Scan thu nghiem co kiem soat tren corpus nho

### Muc tieu

Dung reviewed bundles de scan that, nhung tren corpus nho va co the danh gia duoc.

### Corpus de xuat

- `examples/`
- `datasets/synthetic/`
- 1 repo subset nho thay vi scan nguyen repo lon

### Viec can lam

1. chay `scan_target.py` voi legacy bridge output;
2. so sanh finding giua:
   - default rules
   - reviewed bundle
3. ghi lai TP/FP so bo theo tung family;
4. chot xem reviewed bundle co giam noise hay khong.

### Deliverables

- bang so sanh finding count;
- note TP/FP so bo;
- top mismatch patterns cua V1.

## 7. Phase 4 - Benchmark mini voi Semgrep baseline

### Muc tieu

Chuyen tu demo sang bang chung co so lieu.

### Can so sanh

1. `Aegis core`
2. `Aegis + reviewed bundle`
3. `Semgrep subset baseline`

### Metrics

- precision
- recall
- F1
- finding count sau review/triage
- top FP families
- latency

### Deliverables

- benchmark runner nho;
- corpus co nhan so bo;
- bang ket qua de dua vao bao cao va slide.

### Y nghia

Day la phase rat quan trong vi no bien cau chuyen tu:

- "he thong co web va co AI"

thanh:

- "he thong giam FP hoac giu coverage ra sao voi baseline ro rang".

## 8. Phase 5 - AI drafting tu mo ta ngon ngu tu nhien

### Muc tieu

Day moi la phase "noi bang loi -> AI draft rule" dung nghia.

### Workflow dung

1. nguoi dung nhap mo ta tu nhien;
2. he thong truy hoi seed gan nhat tu local snapshot;
3. AI draft ra normalized rule;
4. validator check schema va scope;
5. con nguoi review;
6. neu on moi export bridge de scan thu nghiem.

### Viec can lam

1. them o nhap natural-language prompt vao workbench;
2. them prompt contract cho draft normalized YAML;
3. gan provenance `drafted-by-ai`;
4. ghi ro review status truoc khi export.

### Dieu khong duoc lam

- khong cho AI viet detector runtime;
- khong cho AI bo qua review gate;
- khong tinh AI draft la rule production ngay.

## 9. Phase 6 - Giam phu thuoc vao legacy bridge

### Muc tieu

Tien toi detector doc duoc normalized rules hoac co adapter tot hon.

### Viec can lam

1. map ro normalized detection fields vao detector runtime;
2. danh gia pattern nao legacy bridge dang mat nghia;
3. chot adapter contract thay vi de bridge tam thoi keo dai qua lau.

### Deliverables

- note thiet ke adapter hoac loader moi;
- test cho normalized-runtime mapping;
- giam chenhlech giua reviewed rules va runtime rules.

### Y nghia

Phase nay giup repo chuyen tu:

- "co bridge de scan tam"

sang:

- "rule review flow noi thong hon voi detector that".

## 10. Phase 7 - Noi reviewed rules voi evidence va triage

### Muc tieu

Ket hop rule authoring voi triage/evidence de co cau chuyen khoa hoc dep hon.

### Viec can lam

1. dua graph slice/evidence slice vao finding dung reviewed bundles;
2. do tac dong cua evidence toi giam FP;
3. neu can thi moi bat dau `Auditor/Skeptic/Judge` loop sau benchmark.

### Deliverables

- benchmark `bundle-only` vs `bundle + evidence`;
- JSON/Markdown report co evidence ngon hon;
- note error analysis cho finding bi suppress hoac needs-review.

### Luu y

Debate loop va retrieval layer chi nen vao sau khi:

- reviewed bundle flow on;
- benchmark co so lieu;
- evidence slice da gon.

## 11. Phase 8 - Dong goi khoa luan va demo

### Muc tieu

Chuyen cac artifact ky thuat thanh bo bao cao va demo co suc thuyet phuc.

### Viec can lam

1. chup lai flow workbench;
2. tong hop bang benchmark;
3. viet ro implementation vs limitations;
4. chot claim khoa hoc va engineering contribution;
5. lam kich ban demo:
   - seed
   - review
   - export
   - scan thu nghiem
   - benchmark so sanh

### Deliverables

- slide demo;
- bang ket qua;
- phan limitations va huong mo rong;
- kich ban bao ve 5-10 phut.

## 12. Thu tu uu tien nen giu

Neu tinh tu moc hien tai, thu tu hop ly nhat la:

1. Phase 1 - Van hanh that Workbench V1
2. Phase 2 - Hoan tat 3 reviewed bundles
3. Phase 3 - Scan thu nghiem co kiem soat
4. Phase 4 - Benchmark mini voi Semgrep
5. Phase 5 - AI drafting tu mo ta ngon ngu tu nhien
6. Phase 6 - Giam phu thuoc legacy bridge
7. Phase 7 - Evidence + triage nang cao
8. Phase 8 - Dong goi khoa luan va demo

## 13. Viec chua nen uu tien luc nay

Tam thoi chua nen day manh:

- import full Semgrep registry;
- Dynamic RAG runtime;
- live crawl rules tren web;
- local LLM lam detector chinh;
- mo rong da ngon ngu truoc khi Python workbench + benchmark on.

## 14. Ket luan

Sau `Rule Workbench V1`, repo khong nen chay theo huong:

- lam dep web truoc;
- hay them AI generation cho vui;
- hay scan them nhieu repo lon de khoe finding count.

Huong dung hon la:

- bien workbench thanh luong review that;
- benchmark no voi Semgrep;
- sau do moi them AI drafting co kiem soat;
- va cuoi cung moi noi thong voi triage/evidence va thesis pack.

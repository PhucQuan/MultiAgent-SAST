# Bo tai lieu do an cho Aegis-SAST

Thu muc nay tong hop phan hien trang, huong nang cap, benchmark, demo, va bo cau hoi phan bien de dua Aegis-SAST tu muc portfolio len muc do an tot nghiep va de tai NCKH co co so ky thuat ro rang.

## Cum tien do 20-31 da dat duoc gi

Cum tai lieu `20` den `31` hien tai da phan thanh 4 lop tien do ro rang:

1. **Triage va workflow**
   - `20`, `21`, `22`, `23`, `26`
   - Da co knowledge cards, workflow-state, repo intake, node contracts, va workflow metadata di xuyen qua report/SARIF.

2. **Moi truong va kha nang chay that**
   - `24`, `25`
   - Da co huong dan tuong thich CPython, smoke test nhe, va cach phan tach loi moi truong khoi loi scanner.

3. **Python graph core**
   - `27`, `28`, `29`, `30`
   - Da co explicit CFG/DFG, taint kill, dead-path pruning, `try/except/finally`, `break/continue`, `loop else`, function summary, va graph smoke script doc lap.

4. **Danh gia nghien cuu**
   - `31`
   - Da co mini benchmark ablation co dataset synthetic, runner, JSON/Markdown output, va so lieu de viet phan thuc nghiem so bo.

## File 32-35 bo sung gi

File `32-roadmap-4-6-thang-hybrid-sast-agent.md` chot huong trien khai tiep theo theo scope 4-6 thang, gom:

- Python la lane khoi dau manh nhat;
- JavaScript va Java phai duoc nang cap lien tuc theo roadmap;
- `Semgrep = baseline cong nghiep`;
- `LangGraph + Local LLM + RAG = lop AI hien dai`;
- `benchmark + SARIF + CI = lop chung minh gia tri khoa hoc va san pham`.

File `33-chien-luoc-capability-parity-python-javascript-java.md` bo sung them mot quyet dinh quan trong:

- khong giu Python lam dich den duy nhat cua de tai;
- dua Python, JavaScript va Java ve cung mot thang nang luc ky thuat;
- chot ro contract chung giua deterministic core va agent workflow.

File `34-rule-ingestion-va-normalized-schema-v1.md` chot:

- scope `rule ingestion V1` cho Python;
- normalized rule schema tach `detection` va `triage`;
- chien luoc import subset co provenance thay vi copy rule a o at.

File `35-roadmap-v1-python-rule-ingestion-va-triage.md` chot:

- thu tu uu tien phase tiep theo;
- scanner cleanup -> rule ingestion -> graph-slice -> benchmark -> debate loop -> knowledge retrieval;
- cach giu scope gon ma van co gia tri nghien cuu ro rang.

## Thu tu nen doc

1. `00-tong-hop-da-lam.md`
2. `01-hien-trang-he-thong.md`
3. `02-gap-va-co-hoi.md`
4. `03-muc-tieu-do-an.md`
5. `04-kien-truc-muc-tieu.md`
6. `14-de-cuong-nghien-cuu-de-tai.md`
7. `15-phase-3-thang-va-phan-cong-quan-tue.md`
8. `16-de-cuong-bao-cao-de-tai-ban-giang-vien.md`
9. `17-lo-trinh-ast-dfg-cfg-va-agent.md`
10. `18-lo-trinh-nang-cap-python-javascript-java-theo-giai-doan.md`
11. `19-tai-cau-truc-repo-theo-huong-khoa-luan-va-nghien-cuu.md`
12. `20-knowledge-cards-va-triage-engine-v1.md`
13. `21-workflow-state-va-langgraph-ready-orchestration.md`
14. `22-repo-intake-va-scan-profile-v1.md`
15. `23-auditor-skeptic-judge-va-source-context-v1.md`
16. `24-cai-dat-moi-truong-va-smoke-test-v1.md`
17. `25-tuong-thich-moi-truong-va-khuyen-nghi-cpython.md`
18. `26-workflow-metadata-vao-report-va-sarif.md`
19. `27-python-dfg-cfg-explicit-graph-v1.md`
20. `28-python-cfg-dfg-v1-1-taint-kill-va-dead-path.md`
21. `29-python-cfg-dfg-v1-2-loop-control-va-function-summary.md`
22. `30-manual-graph-smoke-va-kiem-thu-core.md`
23. `31-mini-benchmark-ablation-python-graph-v1-2.md`
24. `32-roadmap-4-6-thang-hybrid-sast-agent.md`
25. `33-chien-luoc-capability-parity-python-javascript-java.md`
26. `34-rule-ingestion-va-normalized-schema-v1.md`
27. `35-roadmap-v1-python-rule-ingestion-va-triage.md`
28. `06-lo-trinh-phat-trien.md`
29. `07-ke-hoach-benchmark.md`
30. `08-kich-ban-demo.md`
31. `09-cau-hoi-phan-bien.md`

## Muc luc tai lieu

| File | Muc dich |
|---|---|
| `00-tong-hop-da-lam.md` | File tong hop nhung gi da lam, dang co, va vi sao repo nay da co nen tang tot |
| `01-hien-trang-he-thong.md` | Mo ta kien truc hien tai, module, va luong du lieu trong repo |
| `02-gap-va-co-hoi.md` | Phan tich nhung diem con don gian va huong mo rong co gia tri do an |
| `03-muc-tieu-do-an.md` | Chot bai toan, muc tieu, pham vi, va tieu chi thanh cong |
| `04-kien-truc-muc-tieu.md` | Kien truc dich de bien scanner thanh SAST agent thuc thu |
| `05-goi-skill-agent.md` | Gioi thieu bo skill local da them vao repo va cach dung |
| `06-lo-trinh-phat-trien.md` | Roadmap thuc hien theo giai doan |
| `07-ke-hoach-benchmark.md` | Ke hoach danh gia voi baseline va metrics |
| `08-kich-ban-demo.md` | Kich ban demo khi bao cao hoac bao ve |
| `09-cau-hoi-phan-bien.md` | Nhom cau hoi kho va khung tra loi |
| `10-backlog-tinh-nang.md` | Danh sach tinh nang P0, P1, P2 |
| `11-rui-ro-va-giam-thieu.md` | Rui ro ky thuat, scope, evaluation, AI |
| `12-tai-lieu-tham-khao-noi-bo.md` | Repo tham khao va file trong repo can doc ky |
| `13-moc-thoi-gian-va-kpi.md` | Moc thoi gian, deliverables, va KPI tung giai doan |
| `14-de-cuong-nghien-cuu-de-tai.md` | De cuong nghien cuu chi tiet cho huong de tai lon, nhan manh kien truc hybrid, knowledge loading va dong gop khoa hoc |
| `15-phase-3-thang-va-phan-cong-quan-tue.md` | Ke hoach 3 thang, chia phase, milestone, KPI va phan cong cu the cho Quan va Tue |
| `16-de-cuong-bao-cao-de-tai-ban-giang-vien.md` | Ban de cuong viet theo van phong bao cao cho giang vien, tap trung vao bai toan, muc tieu, phuong phap, kien truc va ket qua du kien |
| `17-lo-trinh-ast-dfg-cfg-va-agent.md` | Chot vai tro cua AST, DFG, CFG, Call Graph va lo trinh nang cap thuc te cho Aegis-SAST theo huong do an lon |
| `18-lo-trinh-nang-cap-python-javascript-java-theo-giai-doan.md` | Roadmap nang cap theo phase cho Python, JavaScript va Java, tach ro breadth va depth, benchmark va agent |
| `19-tai-cau-truc-repo-theo-huong-khoa-luan-va-nghien-cuu.md` | Giai thich viec tai cau truc repo theo huong thesis-grade, tach ro code san pham, benchmark, datasets, va package dich |
| `20-knowledge-cards-va-triage-engine-v1.md` | Mo ta bo knowledge cards, triage engine, workflow route seed, va cach tich hop vao pipeline scan hien tai |
| `21-workflow-state-va-langgraph-ready-orchestration.md` | Mo ta lop workflow-state moi, route summary, trace node, va vi sao day la buoc dem dung truoc khi tich hop LangGraph that su |
| `22-repo-intake-va-scan-profile-v1.md` | Mo ta lop repo intake moi, cach detect ngon ngu/framework, scan profile, va gia tri cua metadata nay doi voi workflow agent va benchmark |
| `23-auditor-skeptic-judge-va-source-context-v1.md` | Mo ta node-level contracts cho Auditor, SkepticValidator, Judge, bo doc source context, va cach workflow da bat dau co hanh vi tung node that su |
| `24-cai-dat-moi-truong-va-smoke-test-v1.md` | Giai thich van de cai dat tren moi truong Windows UCRT, cach dong bo dependency, va cach chay smoke test nhe truoc khi chay full CLI |
| `25-tuong-thich-moi-truong-va-khuyen-nghi-cpython.md` | Chot ro van de tuong thich interpreter/ABI, vi sao MSYS2/UCRT gay loi cho stack native, va vi sao CPython chuan la moi truong khuyen nghi |
| `26-workflow-metadata-vao-report-va-sarif.md` | Mo ta viec dua workflow summary va node-level reviews vao JSON, Markdown va SARIF de output the hien ro gia tri cua lop triage/orchestration |
| `27-python-dfg-cfg-explicit-graph-v1.md` | Ghi lai buoc nang cap sang explicit Python CFG/DFG graph, cach tich hop vao plugin/detector, va y nghia cua no doi voi khoa luan va benchmark |
| `28-python-cfg-dfg-v1-1-taint-kill-va-dead-path.md` | Ghi lai dot nang cap tiep theo cua graph engine: kill-set cho safe overwrite, pruning dead path, va modeling co ban cho try/except/finally |
| `29-python-cfg-dfg-v1-2-loop-control-va-function-summary.md` | Ghi lai moc nang cap tiep theo cua graph engine: loop control cho break/continue va function summary de suy luan taint qua helper local tot hon |
| `30-manual-graph-smoke-va-kiem-thu-core.md` | Ghi lai script smoke test doc lap cho graph core, cach chay, va gia tri cua no doi voi phat trien, demo va bao cao khoa luan |
| `31-mini-benchmark-ablation-python-graph-v1-2.md` | Ghi lai bo benchmark synthetic nho cho Python graph v1.2, cac mode ablation, ket qua hien tai va cach dien giai trong bao cao |
| `32-roadmap-4-6-thang-hybrid-sast-agent.md` | Chot roadmap 4-6 thang tiep theo, tach ro must-have, strong contribution, stretch goal, va thu tu nang cap de tai theo huong Hybrid SAST + agent + benchmark |
| `33-chien-luoc-capability-parity-python-javascript-java.md` | Chot chien luoc dua Python, JavaScript va Java ve cung mot thang nang luc ky thuat, va quy dinh contract chung giua core voi agent |
| `34-rule-ingestion-va-normalized-schema-v1.md` | Chot schema rule normalize, pham vi ingestion V1, provenance, va cach tach detector fields khoi triage knowledge |
| `35-roadmap-v1-python-rule-ingestion-va-triage.md` | Chot roadmap gan nhat cho Python scanner cleanup, rule ingestion, graph-slice triage, benchmark, va phase AI nang cao sau do |

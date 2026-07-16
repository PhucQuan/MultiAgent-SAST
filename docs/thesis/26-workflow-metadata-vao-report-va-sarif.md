# Dua workflow metadata vao report va SARIF

## 1. Muc dich

Tai lieu nay mo ta mot buoc nang cap nho nhung co gia tri thuc te cao cho khoa luan:

- output khong chi con la finding thuan scanner
- report da bat dau the hien dau vet cua workflow triage
- SARIF khong chi mang severity va code flow, ma con mang thong tin workflow agent-ready

Noi ngan gon, day la buoc giup Aegis-SAST "nhin ra dang hybrid workflow" ngay o tang output.

---

## 2. Van de cua trang thai truoc

Truoc buoc nay:

- `ScanWorkflow` da co `repo_intake`, `auditor`, `skeptic_validator`, `judge`
- `TriageRecord` da co metadata review trong `finding.metadata`

Nhung output cuoi cung van chua khai thac het:

- JSON moi chu yeu ghi finding + triage decision
- Markdown moi hien finding, evidence, recommendation
- SARIF moi mang severity, triage status, code flow

Dieu nay tao ra khoang cach giua:

- kien truc workflow trong code
- va gia tri co the trinh bay trong report / benchmark / demo

---

## 3. Dieu chinh da thuc hien

## 3.1. JSON exporter

Da cap nhat:

- `aegis_sast/reporting/json_exporter.py`

JSON report hien tai co them:

- `workflow_summary` o top-level
- `agent_reviews` trong tung finding triaged

Noi dung workflow summary gom:

- `scan_profile`
- `framework_hints`
- `knowledge_card_count`
- `triage_summary`
- `route_summary`
- `auditor_summary`
- `skeptic_summary`
- `judge_summary`

Tac dung:

- de script benchmark doc summary nhanh
- de demo su hien dien cua workflow ma khong can mo code

## 3.2. Markdown exporter

Da cap nhat:

- `aegis_sast/reporting/markdown_exporter.py`

Markdown report hien tai co them:

- muc `Workflow Summary`
- muc `Agent Reviews` trong tung finding

Tac dung:

- bao cao doc tay ro hon
- de chup man hinh / dua vao phu luc / demo slide

## 3.3. SARIF formatter

Da cap nhat:

- `aegis_sast/integrations/sarif_formatter.py`

SARIF hien tai co them:

- `runs[0].properties.workflow_summary`
- `results[*].properties.agent_reviews`

Tac dung:

- giu duoc tinh tuong thich SARIF
- van nhung them metadata de phan tich sau trong CI/CD hoac benchmark tools

## 3.4. CLI plumbing

Da cap nhat:

- `aegis_sast/cli.py`

CLI hien tai truyen:

- `workflow_state.metadata`

vao:

- `JSONExporter`
- `MarkdownExporter`
- `SARIFFormatter`

Dieu nay quan trong vi exporter khong tu suy doan workflow, ma nhan metadata truc tiep tu lop orchestration.

---

## 4. Gia tri doi voi file 15, 16, 17

## 4.1. Doi voi file 15

File `15-phase-3-thang-va-phan-cong-quan-tue.md` can mot alpha demo co scan -> triage -> report.

Buoc nay giup report:

- khong con chi la list finding
- ma bat dau the hien route va vai tro node

## 4.2. Doi voi file 16

File `16-de-cuong-bao-cao-de-tai-ban-giang-vien.md` mo ta mot AI Triage Layer co:

- Planner
- Auditor
- Skeptic Validator
- Judge

Sau buoc nay, bao cao co the noi trung thuc hon:

- metadata cua workflow da duoc dua vao report output
- do do gia tri cua workflow co the kiem chung o tang artifact, khong chi o tang code

## 4.3. Doi voi file 17

File `17-lo-trinh-ast-dfg-cfg-va-agent.md` nhan manh agent chi co gia tri khi evidence du manh.

Buoc nay chinh la:

- dua ket qua evidence-aware triage ra tang report
- tao nen cho benchmark va phan tich sau nay

---

## 5. Test va xac nhan

Da bo sung test cho:

- JSON exporter
- Markdown exporter
- SARIF formatter

Huong test tap trung vao:

- co `workflow_summary`
- co `agent_reviews`
- output van duoc tao hop le

---

## 6. Han che hien tai

Can noi that ro:

- workflow metadata hien moi la deterministic workflow metadata
- chua phai trace cua LangGraph that su
- Markdown moi render summary text, chua co table hay visual flow
- SARIF metadata da co, nhung GitHub Code Scanning co the khong hien thi het cac custom property tren UI

Tuy nhien, day van la buoc dung va du thuc dung cho khoa luan.

---

## 7. Buoc tiep theo hop ly

Sau buoc nay, huong tiep theo nen la:

1. Chay lai scan tren sample vulnerable de nhin output moi.
2. Dua workflow metadata vao benchmark logs.
3. Neu can, them truong `workflow_trace` da rut gon vao JSON.
4. Sau do moi xet den LangGraph that su hoac DFG/CFG-lite tiep theo.

---

## 8. Ket luan

Buoc dua workflow metadata vao report va SARIF giup Aegis-SAST tien them mot buoc tu:

- scanner co triage

thanh:

- hybrid SAST co artifact phan anh duoc workflow

Day la mot diem cong rat tot cho khoa luan vi no bien kien truc thanh output co the nhin thay, luu lai va danh gia duoc.

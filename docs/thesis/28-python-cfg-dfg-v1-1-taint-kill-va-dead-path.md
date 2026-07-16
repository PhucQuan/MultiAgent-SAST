# Python CFG/DFG v1.1: Taint Kill, Dead Path, Try/Except

## 1. Muc dich tai lieu

Tai lieu nay ghi lai dot nang cap tiep theo cua `python_flow_graph.py` sau ban explicit graph v1. Muc tieu cua dot nay khong phai la "ve do thi dep hon", ma la giai quyet nhung loi false positive rat de lo ra khi dem di benchmark hoac bao ve de tai.

Ba van de duoc uu tien xu ly:

- bien da bi taint nhung sau do duoc gan lai gia tri an toan van bi xem la taint;
- code nam sau `return` van bi dung de tao node CFG/DFG;
- `try/except/finally` chua co cau truc control-flow rieng trong graph.

## 2. Van de ky thuat truoc khi nang cap

### 2.1. Taint khong co kill-set

Trong ban dau, khi mot bien da bi dua vao `tainted_vars`, no co xu huong "ban mai mai" cho den cuoi path. Dieu nay gay sai trong cac case rat co ban:

```python
cmd = request.args.get("cmd")
cmd = "echo safe"
os.system(cmd)
```

Neu khong co co che kill-set, scanner van co the bao command injection du bien `cmd` da duoc overwrite bang hang an toan.

### 2.2. Dead code sau return

Neu graph van tiep tuc tao node cho doan code sau `return`, DFG va metadata se bi nhieu, va mot so reasoning sau nay co the bi lech vi evidence chua duoc cat dead path som.

### 2.3. Thieu cau truc cho try/except/finally

Khi khong model `try/except/finally`, repo kho chung minh rang CFG da bat dau co kha nang phan tich control-flow co cau truc hon AST traversal thong thuong.

## 3. Nhung gi da duoc bo sung trong v1.1

### 3.1. Taint kill cho assignment an toan

`PythonDataflowAnalyzer._apply_transfer()` da duoc cap nhat theo huong:

- neu write moi doc tu du lieu tainted thi bien dich tiep tuc bi taint;
- neu write moi khong doc tu du lieu tainted thi taint cu cua bien bi xoa;
- neu write tai dong source thi van duoc danh dau tainted nhu cu.

Noi cach khac, graph da bat dau co y niem "kill-set" o muc thuc dung cho assignment/loop variable.

### 3.2. Dung block sau khi mat duong roi

`PythonFlowGraphBuilder._process_block()` da duoc doi de dung som khi statement hien tai khong con `fallthrough exit`. Dieu nay giup:

- khong sinh them node vo nghia sau `return` hoac `raise`;
- lam CFG sach hon;
- lam evidence va `graph_summary` dang tin hon.

### 3.3. Ho tro them `Raise`

`raise` da duoc model thanh node ket thuc duong di, tu do hop ly hon voi cac path bi cat som.

### 3.4. Ho tro co cau truc cho `Try`

Builder da co xu ly co ban cho:

- `try`
- `except`
- `finally`
- `orelse` sau `try`

Muc tieu cua buoc nay la dua `try/except/finally` vao CFG nhu mot cau truc dieu khien that su, chua nham den model exception semantics day du nhu graph engine hoc thuat chuyen sau.

## 4. Y nghia doi voi de tai

Dot nang cap nay co gia tri rat truc tiep cho khoa luan/NCKH vi no cham dung bai toan "giam false positive nhung khong overclaim":

1. Scanner khong con de bi bat loi o case overwrite an toan.
2. Graph khong con thu gom dead code sau `return` mot cach vo nghia.
3. Tai lieu co the noi ro rang Python CFG/DFG dang tien tu heuristic sang structured flow reasoning.

Neu ve sau nhom lam ablation study, day la mot moc de tach:

- AST/Taint cu
- AST + explicit graph v1
- AST + explicit graph v1.1 co kill-set va dead-path pruning

## 5. Nhung gi van chua nen noi qua muc

Mac du da tot hon ro, ban v1.1 van chua nen duoc mo ta la full inter-procedural CFG/DFG engine. Cac diem chua xong gom:

- chua co SSA;
- chua co `break` / `continue` graph semantics day du;
- chua co exception-flow semantics day du qua moi handler/finally trong moi truong thuc;
- chua co call/return edge thong nhat trong mot graph lien thu tuc;
- chua co path-sensitive sanitizer reasoning thuc su.

Noi dung dung de viet bao cao la:

> Aegis-SAST da co explicit Python CFG/DFG graph o muc thuc dung, da bo sung kill-set cho write an toan, pruning dead path sau statement ket thuc, va modeling co ban cho try/except/finally. Day la nen tang de di tiep sang inter-procedural refinement va benchmark false-positive reduction.

## 6. Huong nang cap tiep theo

Sau v1.1, thu tu hop ly nen la:

1. bo sung `break` / `continue` control-flow;
2. tang cuong local function summary cho argument -> parameter -> return;
3. day manh benchmark voi bo ca synthetic case va baseline Semgrep;
4. dua graph evidence vao Auditor / Judge de triage co co so hon;
5. neu kip moi tinh den inter-procedural graph sau hon.

## 7. Ket luan

Ban v1.1 khong lam cho Aegis-SAST "xong han" CFG/DFG, nhung no giai quyet dung nhung cho de sai nhat khi dem system di demo, benchmark, hoac viet bao cao hoc thuat. Ve gia tri khoa hoc, day la buoc rat quan trong vi no bien graph tu mot lop mo ta sang mot lop that su tac dong den precision.

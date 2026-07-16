# Python CFG/DFG v1.2: Loop Control va Function Summary

## 1. Muc dich tai lieu

Tai lieu nay ghi lai dot nang cap tiep theo cua graph engine Python sau cac buoc:

- explicit CFG/DFG v1;
- bo sung taint kill, dead path pruning, va `try/except/finally` trong v1.1.

Muc tieu cua v1.2 la day graph tu muc "co branch va return" len muc thuc dung hon cho bai toan SAST:

- model `break` / `continue` trong loop;
- model `for/while ... else` theo huong control-flow Python;
- sinh summary cho local helper functions de giam phu thuoc vao heuristic khi suy luan qua loi goi ham.

## 2. Van de truoc khi nang cap

### 2.1. Loop control chua duoc model ro

Truoc v1.2, `for` va `while` da co node loop va canh quay lai, nhung chua co xu ly rieng cho:

- `break`
- `continue`

Dieu nay dan den hai han che:

1. CFG chua phan biet ro duong nao thoat vong lap, duong nao quay lai dau loop.
2. Evidence path de dua cho triage chua du thuyet phuc trong nhung doan code co branch trong loop.
3. `loop else` cua Python chua duoc tach thanh no-break path ro rang.

### 2.2. Return-taint qua helper van con heuristic

Plugin Python da co co che kiem tra helper local/imported co the tra ve du lieu tainted hay khong, nhung cach lam cu van nghieng ve:

- quet AST/Tree-sitter rieng cho callee;
- lan duyet statement theo kieu heuristic;
- chua tan dung explicit DFG da xay duoc.

Neu muon bien de tai thanh mot he thong co gia tri khoa hoc hon, can co mot lop `function summary` noi ro:

- ham co nhung tham so nao;
- tham so nao co the anh huong toi gia tri `return`;
- tu do caller co the suy luan taint qua loi goi ham co co so hon.

## 3. Nhung gi da duoc bo sung trong v1.2

### 3.1. Them loop context trong graph builder

`PythonFlowGraphBuilder` da duoc bo sung `_LoopContext` de giu thong tin trong qua trinh dung graph cho moi loop:

- `loop_node_id`
- `exit_node_id`
- danh sach `break_exit_ids`
- danh sach `continue_exit_ids`
- environment kem theo cac diem thoat nay

Nho do builder khong con chi tao node loop mot cach don gian, ma da co the noi dung canh CFG phu hop cho tung loai loop control.

### 3.2. Ho tro `break`

Khi gap `break`, builder:

- tao node `break`;
- dua node do vao loop context hien tai;
- noi canh CFG tu `break` sang node exit cua loop voi nhan `break`.

Dieu nay giup graph phan biet ro:

- thoat khoi loop;
- va tiep tuc sang doan code sau loop.

### 3.3. Ho tro `continue`

Khi gap `continue`, builder:

- tao node `continue`;
- dua node do vao loop context hien tai;
- noi canh CFG tu `continue` quay ve node loop voi nhan `continue`.

Dieu nay giup graph phan biet ro:

- bo qua phan con lai cua than loop hien tai;
- quay lai dau loop de xet lan lap tiep theo.

### 3.4. Dead path pruning trong loop body tot hon

Do `break` va `continue` da tro thanh terminating statement trong block hien tai, cac statement nam sau chung trong cung block khong con bi dua vao CFG mot cach sai lech.

Day la diem quan trong voi false positive, vi neu khong pruning som, graph co the van giu lai cac sink nam sau `continue` hoac `break` du tren thuc te chung khong cung thuoc mot path hop le.

### 3.5. Ho tro `for/while ... else`

Builder da duoc bo sung kha nang noi false-edge cua loop vao than `else` khi co:

- `for ... else`
- `while ... else`

Trong model nay:

- duong `break` bo qua `else`;
- duong `false` cua loop di vao `else`;
- sau `else` moi noi ve merge node cua statement.

Day la mot cai tien nho nhung rat co y nghia vi no giup CFG dung hon voi semantics Python, nhat la khi benchmark tren cac case synthetic co loop branch.

### 3.6. Sinh `PythonFunctionSummary`

Graph da co them `PythonFunctionSummary`, luu cac thong tin:

- ten ham;
- danh sach tham so;
- node tham so;
- node return;
- danh sach tham so co the anh huong den return;
- metadata tong hop.

Summary nay duoc suy ra bang cach:

1. lay node parameter cua tung function;
2. lay node return cua function do;
3. di nguoc theo reverse DFG tu return node;
4. xac dinh parameter node nao thuc su co anh huong toi return.

### 3.7. Tich hop function summary vao Python plugin

`PythonPlugin._callee_return_is_tainted()` da duoc cap nhat theo thu tu:

1. neu co explicit graph cho callee, lay `function summary`;
2. map argument tainted cua caller sang parameter tainted cua callee;
3. neu `dependent_parameters` cua callee giao voi tap parameter tainted, ket luan gia tri return co the bi taint;
4. chi fallback ve logic quet cu khi khong the dung summary.

Noi ngan gon, reasoning qua helper local/imported da bat dau dua tren explicit graph thay vi chi dua tren heuristic.

## 4. Gia tri ky thuat cua v1.2

### 4.1. Gia tri voi CFG

Sau v1.2, CFG Python da manh hon ro o cac case:

- loop co branch ben trong;
- path bo qua sink vi `continue`;
- path thoat vong lap vi `break`;
- path chi xay ra khi loop khong bi `break` thong qua `loop else`;
- path sau `break` / `continue` trong cung block khong bi giu lai vo nghia.

### 4.2. Gia tri voi DFG

DFG khong chi dung cho assignment nua ma da bat dau dong gop vao bai toan `argument -> parameter -> return summary`.

Day la buoc rat quan trong vi no dua graph tu muc "theo doi bien trong mot ham" sang muc "co tom tat lien thu tuc cuc bo".

### 4.3. Gia tri voi triage va benchmark

Sau v1.2, nhom co them mot lop bang chung rat de dua vao benchmark:

- precision truoc va sau khi co loop-control reasoning;
- precision truoc va sau khi co function summary;
- so luong finding bi xoa do sink nam tren dead path sau `continue` / `break`;
- kha nang bat flow qua helper ma khong can heuristic manh tay.

## 5. Nhung gi da duoc verify

Trong dot nang cap nay, da co cac kiem tra muc graph-level:

- graph co node `break` va `continue`;
- graph co edge nhan `break` va `continue`;
- graph false-edge cua loop co the di vao `else` body;
- code sau `continue` trong cung block khong con la node reachable;
- function summary cua ham local co the xac dinh dung tham so nao anh huong den return.

Ngoai ra, `py_compile` da qua cho:

- `aegis_sast/analysis/python_flow_graph.py`
- `aegis_sast/plugins/python_plugin.py`
- `tests/test_python_flow_graph.py`

## 6. Gioi han van con ton tai

Mac du v1.2 da tot hon ro, van chua nen mo ta la full inter-procedural graph engine:

- chua co call edge / return edge thong nhat tren mot graph lon;
- chua model aliasing sau hon;
- chua model object field flow mot cach chat che;
- chua co exception-flow semantics day du;
- chua co path-sensitive sanitizer reasoning thuc su qua nhieu loop / nested branch.

Noi cach khac:

> v1.2 da dua Aegis-SAST tu explicit intra-file graph sang muc co loop-control reasoning va local inter-procedural summary, nhung chua phai graph engine hoan chinh o muc nghien cuu sau.

## 7. Y nghia doi voi khoa luan va NCKH

V1.2 rat co gia tri neu viet theo van phong ky thuat:

1. Co dong gop cai tien ro rang va do duoc:
   - them loop control;
   - them local function summary.

2. Co the tao ablation study co nghia:
   - baseline AST/taint;
   - + explicit CFG/DFG;
   - + taint kill va dead path pruning;
   - + loop control va function summary.

3. Co the tranh overclaim:
   - da co graph that su;
   - da co cai tien lien thu tuc cuc bo;
   - nhung van chua la full program graph engine.

## 8. Huong nang cap tiep theo

Sau v1.2, thu tu hop ly nen la:

1. bo sung `break` / `continue` cho nested `try/finally` phuc tap hon neu can;
2. tang cuong summary cho helper tra ve qua nhieu branch;
3. dua function-summary evidence vao metadata/report de demo dep hon;
4. benchmark voi Semgrep tren tap ca synthetic va real-world mini cases;
5. neu scope cho phep, nghien cuu call/return edges ro hon tren graph lien thu tuc.

## 9. Ket luan

Python CFG/DFG v1.2 la mot moc ky thuat quan trong cua Aegis-SAST. Dot nang cap nay khong mo rong theo huong "them tinh nang cho nhieu", ma nham dung vao hai diem co gia tri hoc thuat va thuc dung cao:

- path reasoning trong loop;
- suy luan qua local helper functions dua tren function summary.

Day la mot buoc hop ly de dua scanner tu muc portfolio-scale tien dan len muc khoa luan/NCKH thuyet phuc hon.

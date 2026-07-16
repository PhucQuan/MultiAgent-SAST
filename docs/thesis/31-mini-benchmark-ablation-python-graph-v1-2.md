# Mini Benchmark Ablation cho Python Graph v1.2

## 1. Muc dich

Sau khi Aegis-SAST da co:

- explicit CFG/DFG graph cho Python,
- taint kill va dead-path pruning,
- loop control (`break`, `continue`, `loop else`),
- local function summary,

nhom can mot benchmark nho, de chay nhanh, de lap lai, va du suc chung minh rang cac nang cap nay khong chi "dep ve kien truc" ma thuc su cai thien ket qua.

Tai lieu nay mo ta bo **mini benchmark ablation** da duoc bo sung cho repo.

## 2. Thanh phan da duoc them

### 2.1. Dataset synthetic

Da them bo du lieu:

- `datasets/synthetic/python_graph_ablation_v1_2/`

Bo du lieu nay gom 6 case Python co gan nhan:

1. flow truc tiep source -> sink
2. safe reassignment
3. dead path sau `return`
4. dead path sau `continue`
5. helper local tra ve tham so
6. helper local tra ve hang so an toan

### 2.2. Benchmark runner

Da them:

- `aegis_sast/benchmarking/python_graph_ablation.py`
- `scripts/benchmark_python_graph_ablation.py`

Runner nay so sanh 3 mode:

1. `linear_taint_baseline`
2. `graph_core_no_summary`
3. `graph_core_with_summary`

## 3. Y nghia cua 3 mode

### 3.1. `linear_taint_baseline`

Day la baseline co chu y don gian:

- lan truyen taint theo thu tu dong lenh
- khong co kill-set
- khong co CFG semantics
- khong co function summary

Mode nay dai dien cho mot lop detector heuristic de so sanh voi graph core.

### 3.2. `graph_core_no_summary`

Mode nay dung explicit CFG/DFG hien tai nhung **khong bat function summary**.

Nghia la:

- co dead-path pruning
- co loop reasoning
- co taint kill
- nhung chua suy luan qua helper local dua tren argument -> parameter -> return summary

### 3.3. `graph_core_with_summary`

Mode nay dung explicit CFG/DFG va **bat local function summary**.

Day la mode gan nhat voi nang luc graph v1.2 hien tai.

## 4. Ket qua hien tai

Voi bo synthetic dataset hien tai, benchmark da cho ra:

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `linear_taint_baseline` | 2 | 4 | 0 | 0 | 0.333 | 1.000 | 0.500 | 0.333 |
| `graph_core_no_summary` | 1 | 0 | 4 | 1 | 1.000 | 0.500 | 0.667 | 0.833 |
| `graph_core_with_summary` | 2 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |

## 5. Cach dien giai ket qua

### 5.1. Tu baseline sang graph core

Khi di tu `linear_taint_baseline` sang `graph_core_no_summary`, he thong giam manh false positive:

- khong con bi dinh case safe overwrite;
- khong con bi dinh case sink nam tren dead path sau `return`;
- khong con bi dinh case sink nam sau `continue`.

Day la bang chung truc tiep cho gia tri cua:

- CFG semantics
- dead-path pruning
- taint kill

### 5.2. Tu graph core sang graph core + summary

Khi bat `function summary`, he thong lay lai duoc true positive o case helper local:

- `helper returns parameter` duoc bat dung;
- `helper returns constant` khong bi FP.

Day la bang chung cho gia tri cua:

- argument -> parameter -> return reasoning
- local inter-procedural summary

## 6. Gia tri doi voi khoa luan/NCKH

Mini benchmark nay rat hop voi phan bao cao hoc thuat vi:

1. Nho, de lap lai, de kiem chung.
2. Tach ro tung lop dong gop:
   - taint heuristic
   - CFG/DFG graph
   - function summary
3. Co the dua thang vao phan **ablation study**.
4. Khong bi phu thuoc vao môi truong plugin day du hay dependency native.

Neu can viet ngan gon trong bao cao, co the trinh bay nhu sau:

> Chung toi xay dung mot bo synthetic benchmark nho gom 6 case de luong hoa gia tri cua tung lop reasoning. Ket qua cho thay graph core giam false positive ro rang so voi baseline taint tuyen tinh, trong khi function summary giup phuc hoi recall ma khong danh doi precision.

## 7. Cach chay

```powershell
python .\scripts\benchmark_python_graph_ablation.py
```

Output duoc sinh ra tai:

- `benchmarks/results/python_graph_ablation/*.json`
- `benchmarks/results/python_graph_ablation/*.md`

## 8. Gioi han hien tai

Mini benchmark nay chua thay the cho:

- benchmark plugin Python day du;
- benchmark doi chieu voi Semgrep;
- benchmark doi chieu voi CodeQL;
- benchmark tren real-world sample apps.

No la moc trung gian, dung de chung minh nhanh dong gop cua graph core.

## 9. Huong nang cap tiep theo

Sau mini benchmark nay, thu tu hop ly nen la:

1. mo rong them case synthetic cho `break`, `try/finally`, `loop else` phuc tap hon;
2. them output CSV/chart neu can ve bieu do;
3. noi benchmark nay voi plugin Python day du khi moi truong `tree_sitter` on dinh;
4. bo sung track doi chieu voi Semgrep tren cac case overlap;
5. neu kip, mo them benchmark nho cho JavaScript va Java.

## 10. Ket luan

Mini benchmark ablation nay la buoc rat dung luc cho Aegis-SAST. No bien nhung nang cap CFG/DFG va function summary vua lam xong thanh **so lieu cu the**, giup de tai manh hon ro ret khi viet khoa luan, bao cao NCKH, va demo voi giang vien.

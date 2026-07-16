# Manual Graph Smoke va Kiem thu Core

## 1. Muc dich

Sau khi graph engine Python duoc nang cap den cac moc:

- explicit CFG/DFG v1;
- v1.1 voi taint kill va dead-path pruning;
- v1.2 voi loop control, loop else, va function summary;

mot van de thuc te xuat hien la: moi truong plugin day du co the chua san sang do thieu dependency native nhu `tree_sitter_python`.

De giai quyet van de nay, repo da duoc bo sung script:

- `scripts/manual_graph_smoke.py`

Script nay cho phep kiem thu phan **core graph reasoning** ma khong phu thuoc vao Tree-sitter hoac plugin pipeline day du.

## 2. Tai sao script nay quan trong

Trong qua trinh lam khoa luan/NCKH, nhom khong chi can code ma con can:

- chung minh tung lop ky thuat da hoat dong;
- tach loi core-analysis voi loi moi truong;
- co mot cach smoke nhanh de demo cho giang vien hoac tu test tren may moi.

`manual_graph_smoke.py` giai quyet dung bai toan do.

## 3. Nhung gi script dang kiem tra

Script hien tai bao gom 5 nhom kiem tra nhe:

1. `safe_reassignment`
   - bien tainted sau do bi overwrite bang gia tri an toan
   - ket qua mong doi: khong con path den sink

2. `return_pruning`
   - code sau `return` khong duoc giu lai trong CFG nhu mot node reachable

3. `loop_control`
   - graph phai co nhan canh `break` va `continue`

4. `loop_else`
   - false-edge cua loop co the di vao than `else`

5. `function_summary`
   - graph phai suy ra duoc tham so nao anh huong den `return` cua helper local

## 4. Cach chay

Tu root repo:

```powershell
python .\scripts\manual_graph_smoke.py
```

Neu thanh cong, script se in cac dong dang:

- `[ok] safe_reassignment`
- `[ok] return_pruning`
- `[ok] loop_control`
- `[ok] loop_else`
- `[ok] function_summary`
- `[done] manual_graph_smoke`

## 5. Gia tri doi voi phat trien

Script nay rat hop cho nhung tinh huong sau:

- vua sua graph builder xong va muon check nhanh;
- may dang loi dependency plugin;
- can mot minh chung core-analysis de chup hinh dua vao slide/demo;
- can tach bug cua graph core khoi bug cua parser/plugin/reporter.

## 6. Gia tri doi voi khoa luan va NCKH

Ve mat trinh bay hoc thuat, script nay co gia tri o cho:

1. Cho thay nhom co cach kiem thu tung lop cua he thong, khong chi test end-to-end.
2. Cho thay dong gop cua graph engine co the duoc kiem chung doc lap.
3. Ho tro lap mini benchmark/noi suy khi moi truong day du chua san sang.

Neu viet trong bao cao, co the mo ta script nay nhu:

> mot bo smoke test muc core dung de xac minh cac thuoc tinh CFG/DFG quan trong truoc khi dua vao plugin pipeline va benchmark day du.

## 7. Gioi han

Script nay khong thay the cho:

- unit test day du;
- integration test cua plugin Python;
- benchmark voi Semgrep hoac baseline ben ngoai.

No chi la lop xac minh nhanh cho graph core.

## 8. Ket luan

`scripts/manual_graph_smoke.py` la mot bo tro thu thuc dung cho repo. No giup Aegis-SAST co mot cach kiem tra nhanh, re, de chay va it phu thuoc vao moi truong, rat phu hop cho giai doan nang cap lien tuc cua de tai.

# Cai dat moi truong va smoke test v1

## 1. Muc dich

Tai lieu nay duoc viet de giai quyet mot van de rat thuc te khi trien khai Aegis-SAST cho do an va nghien cuu:

- repo can chay duoc tren may phat trien that
- phai co cach test nhanh ngay ca khi moi truong chua cai du full dependency
- tai lieu cai dat phai khop voi code hien tai, khong duoc noi mot duong repo lam mot neo

Buoc nay dac biet quan trong sau khi nhom gap loi cai dat tren Windows UCRT / MinGW voi `pydantic-core`.

---

## 2. Van de gap phai

Trong qua trinh cai dat bang:

```powershell
& .\.venv\bin\python.exe -m pip install -r requirements.txt
```

repo tung bi dung o buoc build `pydantic-core` tren moi truong `mingw/ucrt` va khong the di tiep de chay smoke test.

Sau khi bo `pydantic`, nhom tiep tuc gap them mot loi cai dat moi o nhanh AI:

- `google-genai` keo theo dependency transitive can `cryptography`
- tren moi truong `mingw/ucrt`, pip khong co wheel phu hop nen roi sang build source
- qua trinh nay doi `Rust`, dan den install that bai

Ngoai nhanh AI, scanner core cung gap van de tuong tu voi:

- `tree-sitter-python`
- `tree-sitter-javascript`
- `tree-sitter-java`
- `tree-sitter-php`

Tren moi truong MSYS2/UCRT, pip roi sang build wheel bang `gcc`, trong khi mot so build script cua grammar package dang dua tham so theo kieu MSVC nhu `/std:c11` va `/utf-8`, dan den build fail.

Neu khong xu ly diem nay thi se co 3 he qua:

1. Nhanh `--no-ai` van bi block du tren ly thuyet no khong can LLM.
2. Tai lieu README va pyproject bi lech nhau.
3. Nhom khong co duong test nhanh de kiem tra workflow triage va orchestration moi.

---

## 3. Dieu chinh da thuc hien

## 3.1. Bo `pydantic` khoi runtime config

Da chuyen `aegis_sast/core/config.py` sang huong:

- dung `dataclass`
- dung stdlib
- lazy validate o runtime

Tac dung:

- giam mot dependency build phuc tap
- giu duoc duong chay `--no-ai`
- hop voi huong workflow deterministic dang co

## 3.2. Dong bo package metadata

Da cap nhat `pyproject.toml` de khop voi code hien tai:

- bo `pydantic`
- bo `pydantic-settings`
- bo sung cac parser da ngon ngu dang dung trong repo:
  - `tree-sitter-javascript`
  - `tree-sitter-java`
  - `tree-sitter-php`

Y nghia:

- tranh tinh trang `requirements.txt` mot kieu nhung `pip install -e .` lai mot kieu khac
- bao dam README va package metadata khop nhau hon

## 3.3. Them `requirements-dev.txt`

Da tach bo phu thuoc phat trien:

- `pytest`
- `pytest-cov`
- `black`
- `ruff`

Tac dung:

- de cai dat nhanh cho nguoi chi muon chay tool
- van co bo tooling rieng cho test va quality check

## 3.3.b. Tach AI dependency thanh nhanh tuy chon

Da tach:

- `requirements.txt` -> chi giu scanner core
- `requirements-ai.txt` -> chua `google-genai`

Dong thoi `pyproject.toml` da chuyen `google-genai` sang optional dependency.

Tac dung:

- nguoi dung co the cai scanner core va chay `--no-ai` ngay
- loi cai dat AI khong con chan duong test deterministic core
- kien truc ky thuat phu hop hon voi huong thesis: core phai chay doc lap, AI la lop tang cuong

## 3.3.c. Them `scripts/doctor_env.py`

Da them script:

- `scripts/doctor_env.py`

Script nay kiem tra:

- interpreter dang dung
- `sysconfig` platform tag
- du lieu tu `pyvenv.cfg`
- dau hieu dang chay bang MSYS2/UCRT Python

Tac dung:

- tach loi moi truong khoi loi code
- giup nhom ket luan nhanh rang van de nam o interpreter/ABI, khong nam o scanner logic
- rat huu ich khi demo, setup lai may, hoac ban giao cho giang vien / thanh vien moi

## 3.4. Them `scripts/manual_smoke.py`

Day la script smoke test nhe, khong can `pytest`, tap trung kiem tra:

- `AegisConfig.from_env()`
- `AuditorNode -> SkepticValidatorNode -> JudgeNode`
- `ScanWorkflow` metadata summary

Tac dung:

- kiem tra nhanh phan triage / orchestration ngay ca khi moi truong chua cai day du CLI stack
- rat huu ich trong giai doan phat trien khoa luan, khi nhom muon test nhanh logic moi

---

## 4. Hai muc kiem tra nen dung

## 4.1. Muc 1 - lightweight smoke

Dung khi:

- moi tao `.venv`
- chua cai day du `click`, `rich`, parser
- muon kiem tra nhanh workflow triage moi co vo khong

Truoc khi cai pip, nen chay:

```powershell
python .\scripts\doctor_env.py
```

Neu script bao:

- `mingw_*`
- `msys64`
- `incompatible for native dependency install`

thi nen dung CPython Windows chuan de tao venv moi truoc khi debug pip them nua.

Lenh:

```powershell
& .\.venv\bin\python.exe .\scripts\manual_smoke.py
```

Ky vong:

- in ra 3 buoc `[ok]`
- ket thuc voi `manual smoke completed successfully`

## 4.2. Muc 2 - full CLI smoke

Dung khi da cai xong full dependency runtime:

```powershell
python -m pip install -r requirements.txt
python -m aegis_sast.cli scan examples/vulnerable_sqli.py --no-ai --output json --output markdown --output sarif --output-dir reports/manual_smoke
```

Muc tieu:

- kiem tra repo intake
- kiem tra scan core
- kiem tra triage workflow
- kiem tra output JSON / Markdown / SARIF

Luu y:

- `examples/vulnerable_sqli.py` duoc uu tien lam positive smoke sample vi co sink ro trong cung flow scan co ban.
- `test_projects/demo_app.py` hien chua phai smoke sample tot cho regression nhanh, vi no de cham vao gioi han interprocedural trong cung mot file.

Neu muon bat AI verification va moi truong ho tro:

```powershell
python -m pip install -r requirements-ai.txt
```

Neu buoc nay that bai tren `mingw/ucrt`, van co the tiep tuc phat trien va benchmark nhanh `--no-ai`.

---

## 5. Gia tri doi voi file 15, 16, 17

Buoc nay khong thay doi kien truc dich trong file `15`, `16`, `17`.

No giai quyet tang van hanh va kha nang tai lap:

- file `15` can ke hoach 3 thang co the trien khai that
- file `16` can de cuong co tinh kha thi, khong chi dung tren giay
- file `17` can lo trinh nang cap duoc kiem chung bang smoke test va regression that

Noi ngan gon:

- `15`, `16`, `17` la target architecture va research roadmap
- `24` la tai lieu van hanh de giup target do chay duoc tren may phat trien that

---

## 6. Han che hien tai

Phai noi that ro:

- `scripts/manual_smoke.py` chua kiem tra scanner AST that
- smoke script chua thay the unit test day du
- full CLI van can dependency runtime nhu `click`, `rich`, `tree-sitter-*`
- AI verification van phu thuoc vao kha nang cai `google-genai` tren moi truong dang dung
- MSYS2/UCRT Python khong phai moi truong cai dat dang tin cay cho stack native hien tai cua repo

Tuy nhien, day van la bo dem rat huu ich de:

- tach loi environment voi loi logic
- test nhanh workflow moi truoc khi chay full scanner

---

## 7. Buoc tiep theo hop ly

Sau buoc nay, huong tiep theo nen la:

1. Chay `scripts/doctor_env.py` de xac nhan interpreter.
2. Neu dang o MSYS2/UCRT, tao lai venv bang CPython Windows chuan.
3. Cai xong `requirements.txt` va chay full CLI smoke.
4. Cai them `requirements-dev.txt` va chay `pytest`.
5. Dua metadata workflow moi vao report exporter va SARIF properties.
6. Sau khi on dinh moi tiep tuc mo rong DFG-lite / CFG-lite va LangGraph that su.

---

## 8. Ket luan

Buoc cap nhat moi truong va smoke test nay khong hoa my, nhung rat quan trong doi voi mot de tai nghien cuu khoa hoc lam tren repo that.

No giup Aegis-SAST:

- de cai dat hon
- de test hon
- giam lech giua tai lieu va implementation
- tao nen on dinh de di tiep sang benchmark va workflow agent phuc tap hon

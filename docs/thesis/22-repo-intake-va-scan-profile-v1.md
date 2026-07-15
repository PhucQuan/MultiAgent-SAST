# Repo Intake va Scan Profile v1

## 1. Muc dich

Tai lieu nay mo ta buoc nang cap tiep theo sau `workflow-state`: bo sung `Repo Intake` that su cho Aegis-SAST.

Buoc nay duoc thuc hien de bam sat dinh huong trong:

- `15-phase-3-thang-va-phan-cong-quan-tue.md`
- `16-de-cuong-bao-cao-de-tai-ban-giang-vien.md`
- `17-lo-trinh-ast-dfg-cfg-va-agent.md`

Trong cac file do, `Repo Intake` khong phai chi la y tuong mo ta kien truc. No la lop dau vao bat buoc de he thong co the:

- nhan dien ngon ngu truoc khi triage
- xac dinh framework hints
- chon scan profile phu hop voi scope nghien cuu
- tao metadata cho benchmark va reporting

---

## 2. Van de cua trang thai truoc

Truoc khi bo sung `Repo Intake v1`, workflow da co state va trace, nhung repo profile van duoc suy ra chu yeu tu:

- finding da scan ra
- duoi file cua `target_path`

Cach do co 3 han che:

1. Khong phan biet ro repo Python thuan voi repo polyglot co Python lam trong tam.
2. Khong co framework hints de viet bao cao, triage hay benchmark.
3. Khong phu hop voi kien truc trong file `16`, vi `Repo Intake Layer` dang duoc mo ta la mot lop rieng.

---

## 3. Thanh phan da duoc bo sung

## 3.1. `RepoIntake`

Da them file:

- `aegis_sast/orchestration/repo_intake.py`

Lop `RepoIntake` thuc hien 4 viec:

1. Thu thap cac file thuoc ngon ngu duoc plugin ho tro.
2. Dem so file theo ngon ngu.
3. Quet mot tap file cau hinh va file mau de tim framework hints.
4. Chon `scan_profile` va `analysis_plan`.

## 3.2. `RepoProfile`

`RepoProfile` duoc bo sung them truong:

- `scan_profile`

Vi vay, repo profile khong chi con la:

- target path
- detected languages
- framework hints

ma da co them:

- ho so quet du kien cua repo

## 3.3. Tich hop vao workflow

`ScanWorkflow` da duoc cap nhat de:

- uu tien dung repo profile tu `Repo Intake`
- fallback ve suy luan tu finding neu target khong ton tai
- ghi trace `repo_intake` vao workflow state

Dieu nay giup workflow gan hon voi cau truc LangGraph du kien:

- `repo_intake`
- `planner`
- `knowledge_loader`
- `auditor`
- `judge`
- `reporter`

## 3.4. Tich hop vao CLI

CLI da duoc bo sung bang `Repo Intake` truoc khi scan.

Hien tai, nguoi dung se thay duoc:

- `Scan Profile`
- `Languages`
- `Framework Hints`
- `Analysis Plan`
- `Supported Files`

Day la diem rat co gia tri cho demo va bao ve, vi no cho thay he thong:

- khong quet mu
- co nhan thuc ban dau ve repo
- co the giai thich vi sao Python duoc scan sau hon JavaScript/Java

---

## 4. Scan profile hien tai

`Repo Intake v1` dang dung logic profile bao thu sau:

| Dieu kien | Scan profile |
|---|---|
| Chi co Python | `python-deep` |
| Chi co JavaScript | `javascript-intra-file` |
| Chi co Java | `java-intra-file` |
| Chi co PHP | `php-intra-file` |
| Polyglot va co Python | `polyglot-python-priority` |
| Polyglot khong co Python | `polyglot-intra-file` |
| Chua xac dinh duoc | `generic` |

Logic nay phu hop voi file `17`, vi no giu dung nguyen tac:

- Python la ngon ngu phan tich sau
- JavaScript va Java van xuat hien trong workflow
- khong overclaim do sau cho moi ngon ngu

---

## 5. Framework hints hien tai

`Repo Intake v1` dang nhan nhieu nhom hint co ban:

### Python

- `flask`
- `django`
- `fastapi`
- `sqlalchemy`

### JavaScript

- `express`
- `koa`
- `node:http`
- `nextjs`

### Java

- `spring`
- `servlet`
- `jdbc`

### PHP

- `laravel`
- `symfony`

Day chua phai framework detection hoan chinh. Muc tieu hien tai la:

- tao metadata huu ich cho scan profile
- goi y nguu canh cho triage
- viet duoc bao cao ky thuat ro rang hon

---

## 6. Gia tri doi voi de tai

Buoc nang cap nay co 4 gia tri ro rang cho khoa luan:

### 6.1. Dung voi kien truc 6 lop

Trong file `16`, he thong dich co `Repo Intake Layer`. Nay lop do da bat dau co implementation seed that su.

### 6.2. Dung voi phan cong cong viec

Trong file `15`, Quyet phu trach core/backend. `Repo Intake` nam dung trong khoi cong viec nay vi no gan voi:

- CLI
- detector coordination
- scan profile
- benchmark metadata

### 6.3. Dung voi lo trinh agent

Trong file `17`, agent chi nen vao sau khi evidence du manh. `Repo Intake` la buoc dem hop ly truoc khi dua LangGraph vao day du, vi no tang state va metadata ma khong can goi LLM.

### 6.4. Dung cho benchmark

Sau nay benchmark co the tach ket qua theo:

- scan profile
- language mix
- framework hint

Dieu nay giup viet phan danh gia co can cu hon, thay vi chi bao precision/recall tong.

---

## 7. Han che hien tai

`Repo Intake v1` van co gioi han:

- framework detection moi o muc substring heuristics
- chua co dependency parser that cho `package.json`, `pom.xml`, `pyproject.toml`
- chua chon rule subset theo framework
- chua lien thong truc tiep voi benchmark harness
- chua tao context matrix cho tung finding

Tuy nhien, day la muc implementation dung cho giai doan hien tai.

---

## 8. Buoc tiep theo hop ly

Sau `Repo Intake v1`, cac buoc tiep theo nen la:

1. Tach `Auditor` va `SkepticValidator` thanh node that co contract rieng.
2. Bo sung helper doc them context file cho finding phuc tap.
3. Dua `scan_profile` vao benchmark metadata va SARIF properties.
4. Neu can, moi bat dau map state nay sang LangGraph that su.

---

## 9. Ket luan

`Repo Intake v1` la mot nang cap nho ve so dong code, nhung lon ve mat kien truc.

No giup Aegis-SAST tien gan hon toi mo hinh trong de cuong:

- co lop repo intake ro rang
- co profile quet theo ngon ngu
- co framework hints cho triage va benchmark
- co state metadata phu hop de di tiep sang LangGraph

Noi ngan gon, day la mot buoc "dung chat khoa luan", khong phai mot patch trang tri.

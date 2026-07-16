# Tuong thich moi truong va khuyen nghi CPython

## 1. Muc dich

Tai lieu nay chot mot diem rat thuc dung cho Aegis-SAST:

- project nay co scanner core dung native dependency
- vi vay moi truong Python khong chi la "co chay duoc Python" la du
- interpreter, ABI tag va kieu wheel ho tro anh huong truc tiep den kha nang cai dat

Muc tieu cua tai lieu la giup nhom khong mat thoi gian debug nham huong khi loi that su nam o moi truong.

---

## 2. Dau hieu cua moi truong dang gay loi

Neu gap cac dau hieu sau, kha nang cao la dang dung Python cua MSYS2/UCRT:

- `sysconfig.get_platform()` tra ve dang `mingw_x86_64_ucrt_gnu`
- `pyvenv.cfg` co `home = C:\\msys64\\ucrt64\\bin`
- interpreter nam o duong dan kieu `.venv/bin/python.exe` tren Windows
- log build wheel goi `gcc.EXE` tu `C:\\msys64\\ucrt64\\bin`

Day la nhung dau hieu da xuat hien truc tiep trong qua trinh cai Aegis-SAST tren may phat trien hien tai.

---

## 3. Vi sao no gay loi cho Aegis-SAST

Aegis-SAST khong phai project pure-Python hoan toan. Hien tai repo phu thuoc vao:

- `tree-sitter`
- `tree-sitter-python`
- `tree-sitter-javascript`
- `tree-sitter-java`
- `tree-sitter-php`

Nhanh AI con co the phu thuoc them vao:

- `google-genai`
- `cryptography` thong qua dependency transitive

Khi interpreter khong match voi wheel co san tren PyPI, pip se:

1. bo qua wheel
2. roi sang build source
3. doi toolchain native phu hop

Voi MSYS2/UCRT, day la diem de xuat hien loi ABI, flag compiler, hoac missing Rust.

---

## 4. Ket luan ky thuat can chot

Can noi ro trong bao cao va khi lam viec nhom:

- van de cai dat hien tai khong phai do kien truc scanner sai
- van de nam o su khong tuong thich giua native dependency va moi truong interpreter
- do do, "doi interpreter" la buoc sua dung ve ky thuat, khong phai cach chua meo

Noi ngan gon:

> Aegis-SAST nen duoc phat trien va benchmark tren CPython Windows chuan hoac Linux/macOS chuan, khong nen lay MSYS2/UCRT Python lam moi truong chinh.

---

## 5. Moi truong duoc khuyen nghi

### 5.1. Windows

Khuyen nghi:

- cai CPython chuan tu python.org
- tao venv bang `py -3.12 -m venv .venv`
- kich hoat bang `.\\.venv\\Scripts\\Activate.ps1`

### 5.2. Linux / macOS

Khuyen nghi:

- dung CPython thong thuong
- tao venv bang `python3 -m venv .venv`
- kich hoat bang `source .venv/bin/activate`

---

## 6. Script da bo sung

Repo da them:

- `scripts/doctor_env.py`

Script nay khong sua loi thay nguoi dung, nhung giup:

- phat hien som moi truong khong hop le
- giam thoi gian debug pip
- ghi nhan duoc vi sao mot lan cai dat that bai

---

## 7. Gia tri doi voi khoa luan va nghien cuu

Diem nay co gia tri that doi voi de tai vi:

1. no lam ro kha nang tai lap moi truong thuc nghiem
2. no giup tach biet loi he thong va loi thuat toan
3. no tang tinh nghiem tuc cua repo khi demo va ban giao

Day la mot phan cua engineering quality, khong chi la mot ghi chu cai dat.

---

## 8. Ket luan

Neu tiep tuc dung MSYS2/UCRT Python, nhom se tiep tuc gap loi native dependency va mat thoi gian o tang moi truong.

Huong dung la:

- chot CPython chuan lam moi truong phat trien
- dung `scripts/doctor_env.py` de check som
- sau do moi chay install, smoke, benchmark va phat trien tiep

# Gap va co hoi nang cap

## Van de lon nhat hien tai

### 1. Chua la "agent" dung nghia

Project hien tai la scanner co AI verification, chua phai agent co workflow:

- lap ke hoach
- lua chon cong cu
- chuan hoa findings
- triage
- remediation
- benchmark
- tao tai lieu tong hop

### 2. Chua co benchmark va baseline

Neu khong co benchmark, rat kho de chung minh:

- do chinh xac
- muc giam false positive
- gia tri cua AI triage
- diem khac biet so voi Semgrep hoac CodeQL

### 3. Chua co normalized finding schema manh

Hien tai finding chu yeu la object noi bo va report cuoi. Chua co schema triage-rich de phan biet:

- confirmed
- likely
- needs review
- suppressed

### 4. Chua co duong di san pham ro

Chua co:

- SARIF
- GitHub Actions workflow
- CI gating
- machine-readable triage outcome

## Co hoi nang cap lon nhat

### Co hoi 1: Bien AI verification thanh triage engine

Day la nang cap co gia tri rat cao vi:

- giu lai scanner deterministic
- dung AI dung cho cho manh nhat
- tao dong gop ro rang cho do an

### Co hoi 2: Them benchmark voi baselines

Neu co bang so lieu truoc/sau AI triage, ban co the bao ve rat chac ve dong gop.

### Co hoi 3: Dong goi thanh local skill pack

Skill pack giup project co:

- tinh chat agent
- quy trinh ro rang
- kha nang tai su dung
- tai lieu hoa de chuyen giao

### Co hoi 4: Tich hop SARIF va CI

Day la phan rat de demo va cho thay tinh san pham.

## Nhung phat hien can luu y

### Ve `--rules`

Can xem lai luong rule custom de dam bao detector su dung dung bo rules nguoi dung truyen vao thay vi khoi tao lai theo ngon ngu trong qua trinh scan.

### Ve output format

Config cho phep `html` la output hop le, nhung pipeline xuat report hien tai moi co JSON va Markdown.

### Ve test va reproducibility

Repo da co nhieu test, nhung moi truong thuc thi can duoc dong goi ro hon de co the tu tin noi "one-command reproducible".

## Chot lai

Project khong yeu o scanner core.
Project dang yeu o lop:

- orchestration
- evaluation
- triage
- product integration

Day chinh la noi ban nen dau tu de bien no thanh do an lon.


# Rule Workbench Extension - SSRF

## 1. Muc dich

Sau khi da chot reviewed bundle flow cho:

- `COMMAND_INJECTION`
- `PATH_TRAVERSAL`
- `INSECURE_DESERIALIZATION`

va da mo rong on cho `SQL_INJECTION`, family hop ly tiep theo la `SSRF`.

Day van la family mo rong sau V1 strict scope, nen khong thuoc profile `python-rule-workbench-v1` goc.

## 2. Vi sao chon SSRF tiep theo

`SSRF` hop voi Aegis vi:

- van la bai toan source -> sink rat ro;
- repo da co knowledge card `generic-ssrf`;
- default Python rules da co sink `requests.get(` va `urllib.request.urlopen(`;
- va family nay de noi vao benchmark mo rong sau `SQL_INJECTION`.

No cung giu scope gon hon `XSS`, vi khong can vao context output encoding hay HTML sink phuc tap ngay luc nay.

## 3. Seed fixture da them

Fixture moi:

- `datasets/synthetic/rule_review_v1/seed_inputs/python_ssrf_semgrep_shape.yaml`

Scope reviewed sink hien tai:

- `requests.get(...)`
- `urllib.request.urlopen(...)`

Scope reviewed sanitizer hien tai:

- `urllib.parse.urlparse(...)`

## 4. Vi sao giu sink set nay truoc

Muc tieu cua extension nay la:

- review duoc artifact va provenance cho SSRF;
- do duoc lech giua default scanner va reviewed bundle;
- va khong mo rong sink qua nhanh khi chua benchmark xong.

Vi vay, reviewed SSRF seed giai doan nay giu sat vao sink ma default Python rules da co.

## 5. Example rieng cho SSRF

Example moi:

- `examples/vulnerable_ssrf.py`

No cover:

- `requests.get(...)` voi URL nguoi dung nhap;
- `urllib.request.urlopen(...)` voi dich den nguoi dung dieu khien;
- them 1 safe case voi dich den constant de benchmark khong bi nhieu boi mixed file.

## 6. Cach build reviewed bundle

Vi SSRF la extension sau V1 strict scope, tam thoi van dung profile `generic`.

```powershell
python scripts/build_rule_review_bundle.py `
  datasets/synthetic/rule_review_v1/seed_inputs/python_ssrf_semgrep_shape.yaml `
  --output-dir reports/rule_review/ssrf_seed `
  --language python `
  --family SSRF `
  --profile generic `
  --provenance-source manual-semgrep-fixture `
  --snapshot-version local-seed-v1 `
  --normalized-format json `
  --validation-format json `
  --legacy-format yaml
```

## 7. Cach compare voi default rules

```powershell
python scripts/compare_reviewed_bundle_scan.py `
  examples/vulnerable_ssrf.py `
  --reviewed-rules reports/rule_review/ssrf_seed/python_ssrf_semgrep_shape.legacy.yaml `
  --format json `
  --format markdown
```

## 8. Cach doc ket qua

Muc tieu truoc mat la:

1. reviewed bundle co giu sink coverage cho `requests.get` va `urllib.request.urlopen` khong;
2. default scanner co di cung reviewed bundle tren example rieng khong;
3. safe case constant URL co bi flag khong.

Neu `default` va `reviewed` bang nhau tren example nay, thi SSRF du dieu kien de them vao benchmark extension rieng.

## 9. Ket luan ngan

SSRF la buoc di tiep theo hop ly sau SQLi vi:

- van sat voi deterministic detector;
- de benchmark tren example nho;
- de viet vao khoa luan;
- va khong buoc team mo som sang bai toan XSS/context output phuc tap hon.

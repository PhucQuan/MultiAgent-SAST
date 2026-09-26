# Chot huong rule cho lane Quan ngay 2026-09-07

## 1. Cau hoi can chot

Phan rule cua Aegis-SAST nen chot theo huong nao:

1. chi dung rule tu viet;
2. bo rule hien tai, chuyen qua baseline Semgrep;
3. giu rule hien tai va nap them reviewed Semgrep overlay.

## 2. Ket luan ngan gon

Nen chot theo huong **so 3**:

- giu bo rule hien tai cua Aegis lam nen;
- nap them reviewed Semgrep overlay cho nhung family can benchmark va claim;
- khong chot theo huong rule tu viet 100%;
- cung khong thay toan bo detector bang Semgrep raw.

Noi ngan gon hon:

**Aegis rule + reviewed Semgrep overlay** la huong nen dung de chot.

## 3. Vi sao khong nen chot theo huong rule tu viet 100%

Neu chi dung rule tu viet thi co 3 van de:

1. Kho noi ve do tin cay va provenance khi bao cao.
2. Kho giai thich vi sao pattern nay duoc chon, pattern kia bi bo.
3. De bi hoi nguoc la rule do dua tren chuan nao.

Rule tu viet van can, nhung nen dung cho:

- phan detector-specific cua Aegis;
- phan modeling rieng cua repo;
- nhung cho Semgrep baseline chua phu hoac phu chua dung.

## 4. Vi sao cung khong nen bo het de theo Semgrep raw

Neu bo het rule hien tai de theo Semgrep raw thi co 3 van de:

1. Mat quyen kiem soat detector cua repo.
2. Lech cau chuyen thesis, vi Aegis khong con la scanner core cua minh nua.
3. Khop kem voi cac phan evidence, triage, va detector heuristics da co san trong repo.

Huong dung hon la:

- lay Semgrep lam baseline co uy tin;
- review lai subset can dung;
- dua vao runtime duoi dang overlay da kiem soat.

## 5. Chung cu tu codebase hien tai

Code hien tai da nghieng ro ve huong "giu Aegis, nap them overlay":

- `aegis_sast/analysis/rule_engine.py`
  - neu co `rules_path` thi thay bo rule goc;
  - neu khong thi load built-in rules theo ngon ngu;
  - sau do moi merge `extra_rules_paths` len tren.

- `aegis_sast/orchestration/service.py`
  - detector duoc tao bang `RuleEngine(config.custom_rules_path, extra_rules_paths=request.append_rules_paths)`;
  - nghia la runtime chinh da support ro base + overlay.

- `aegis_sast/rule_profiles.py`
  - da co `semgrep-python-core4`;
  - da co `semgrep-python-ssrf`;
  - ca hai deu la checked-in reviewed profiles cua repo.

- `datasets/benchmark/reviewed_bundle_v1/cases_python_reviewed_suite.json`
  - benchmark suite hien tai da dung `reviewed_rule_profile`;
  - nghia la lane benchmark moi cung dang di theo huong profile-based overlay.

## 6. Chung cu tu smoke benchmark ngay 2026-09-07

Da chay:

```bash
python scripts/run_benchmark_v1.py \
  --manifest datasets/benchmark/reviewed_bundle_v1/cases_python_reviewed_suite.json \
  --output-dir .tmp_reviewed_profile_smoke \
  --format json --format markdown
```

Ket qua tong:

- default findings: `23`
- reviewed findings: `30`
- delta: `+7`
- mismatch delta: `0`

Phan tang ro nhat nam o:

- `COMMAND_INJECTION`: them `os.popen(`
- `PATH_TRAVERSAL`: them `send_file(`, `os.remove(`, `os.listdir(`

Trong khi do:

- `INSECURE_DESERIALIZATION` giu nguyen do phu;
- `SQL_INJECTION` giu nguyen do phu;
- `SSRF` giu nguyen do phu.

Y nghia:

- overlay reviewed Semgrep dang bo sung sink coverage that su;
- khong pha vo nhung family da on;
- khong cho thay dau hieu mismatch tang them trong smoke suite nay.

## 7. Cach chot de dung trong tuan nay

Tuan nay nen chia rule thanh 3 tang ro rang:

### Tang 1 - Rule Aegis mac dinh

Day la tang nen, luon giu.

Dung cho:

- detector core;
- cac lane scan thong thuong;
- cac family da co modeling rieng trong repo.

### Tang 2 - Reviewed Semgrep overlay

Day la tang dung de chot benchmark va claim cho nhung family da review xong.

Hien tai uu tien:

- `semgrep-python-core4`
- `semgrep-python-ssrf`

Dung cho:

- benchmark mini;
- smoke compare;
- thesis-safe demo;
- cac lane can provenance ro rang.

### Tang 3 - Rule tu viet bo sung

Van duoc giu, nhung khong nen dung lam cau chuyen chinh khi bao cao.

Dung cho:

- detector-specific pattern;
- patch gap nho;
- thu nghiem nhanh;
- modeling tam thoi truoc khi review chuan hoa.

## 8. Cach noi trong bao cao cho gon

Co the noi nhu sau:

> Nhom khong chot theo huong rule tu viet hoan toan. Huong dang dung la giu bo rule va detector cua Aegis lam nen, sau do nap them cac reviewed Semgrep overlay cho nhung family uu tien. Cach nay giup phan rule co diem xuat phat tu baseline co uy tin, nhung van giu duoc detector va triage pipeline cua Aegis.

## 9. Viec Quan nen lam tiep ngay

1. Chot note nay thanh rule policy ngan cho sprint hien tai.
2. Freeze 2 profile:
   - `semgrep-python-core4`
   - `semgrep-python-ssrf`
3. Khi benchmark va demo, uu tien dung:
   - built-in Aegis rules
   - cong reviewed profile
4. Khong dung `--rules` thay toan bo bo rule cho claim chinh, tru khi dang debug hoac thu nghiem rieng.
5. Neu co them rule moi, uu tien di theo quy trinh:
   - baseline co uy tin
   - review subset
   - dong goi profile
   - benchmark lai

## 10. Chot cuoi cung

De chot cho de lam:

- **Khong chot theo huong rule tu viet 100%.**
- **Khong thay Aegis bang Semgrep raw.**
- **Chot theo huong giu Aegis core, nap them reviewed Semgrep overlay.**

Day la huong vua de bao cao, vua co co so ky thuat, vua hop voi codebase hien tai.

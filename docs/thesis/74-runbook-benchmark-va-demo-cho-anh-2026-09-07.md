# Runbook benchmark va demo cho Anh ngay 2026-09-07

## 1. Muc tieu

File nay dung de chot nhanh 3 viec:

1. Chay lai benchmark reviewed-rule-profile.
2. Lay dung artifact de demo.
3. Kiem tra dashboard doc report on truoc luc bao cao.

Khong mo them scope moi. Cu sprint nay chi can giu 1 bo artifact on dinh de ca nhom dung chung.

## 2. Lenh can chay

### 2.1. Chay benchmark reviewed-rule-profile

```bash
python scripts/run_benchmark_v1.py ^
  --manifest datasets/benchmark/reviewed_bundle_v1/cases_python_reviewed_suite.json ^
  --output-dir reports/dashboard_runs/reviewed-rule-profile-2026-09-07 ^
  --format json ^
  --format markdown
```

### 2.2. Neu can check lai test lane nay

```bash
python -m pytest ^
  tests/test_rule_profiles.py ^
  tests/test_scan_target_profiles.py ^
  tests/test_run_benchmark_v1.py ^
  tests/test_reviewed_bundle_scan_compare.py ^
  tests/test_normalized_rule_validator.py
```

Ket qua da xac nhan ngay 2026-09-07: `34 passed`.

### 2.3. Chay dashboard local

```bash
cd apps/findings-dashboard
npm.cmd run dev
```

Neu can check nhanh truoc khi demo:

```bash
npm.cmd run lint
npm.cmd run build
```

Trang thai da xac nhan ngay 2026-09-07:

- `lint` pass
- `build` pass
- co 1 warning Turbopack/NFT lien quan `next.config.ts` va `src/app/api/scan/route.ts`, nhung build van xong va khong block demo

## 3. Artifact da chot

### 3.1. Summary tong

- file JSON tong: `reports/dashboard_runs/reviewed-rule-profile-2026-09-07/benchmark_summary.json`
- file Markdown tong: `reports/dashboard_runs/reviewed-rule-profile-2026-09-07/benchmark_summary.md`

So nhanh:

- `5` cases
- default findings: `23`
- reviewed findings: `30`
- delta: `+7`
- mismatch delta: `0`

### 3.2. Report nen mo de demo

Uu tien so 1:

- `reports/dashboard_runs/reviewed-rule-profile-2026-09-07/python-path-traversal/reviewed_scan/aegis_sast_report_20260907_101003.json`

Ly do:

- default `4` -> reviewed `10`
- nhin ro phan them sink `send_file(`, `os.remove(`, `os.listdir(`
- trong cung report co ca finding bi `suppressed`, nen de noi phan triage

Uu tien so 2:

- `reports/dashboard_runs/reviewed-rule-profile-2026-09-07/python-command-injection/reviewed_scan/aegis_sast_report_20260907_101003.json`

Ly do:

- default `8` -> reviewed `9`
- co them case `os.popen(`
- report gon, de mo neu can demo nhanh

## 4. Cach verify dashboard

### 4.1. Check report index

Sau khi dashboard chay o `http://localhost:3000`, goi:

```powershell
Invoke-WebRequest -UseBasicParsing "http://localhost:3000/api/reports?includeArchive=1"
```

Neu tra ve danh sach co report ben duoi `dashboard_runs/reviewed-rule-profile-2026-09-07/...` la on.

### 4.2. Check report cu the

Dashboard route dung query `path=...`, khong phai URL segment.

Vi du voi report demo path traversal:

```powershell
$p = "dashboard_runs/reviewed-rule-profile-2026-09-07/python-path-traversal/reviewed_scan/aegis_sast_report_20260907_101003.json"
$u = "http://localhost:3000/api/reports?path=" + [uri]::EscapeDataString($p)
Invoke-WebRequest -UseBasicParsing $u
```

Vi du voi report demo command injection:

```powershell
$p = "dashboard_runs/reviewed-rule-profile-2026-09-07/python-command-injection/reviewed_scan/aegis_sast_report_20260907_101003.json"
$u = "http://localhost:3000/api/reports?path=" + [uri]::EscapeDataString($p)
Invoke-WebRequest -UseBasicParsing $u
```

Trang thai da check ngay 2026-09-07:

- path traversal reviewed report doc duoc, tong `10` findings
- command injection reviewed report doc duoc, tong `9` findings

## 5. Noi nhanh khi demo

Neu can 1 doan noi gon:

> Scanner van la Aegis. Rule dung theo huong giu Aegis lam nen va nap them reviewed Semgrep overlay. O smoke suite nay, reviewed profile tang them 7 findings, phan ro nhat nam o path traversal va command injection. Dashboard da doc duoc report moi, nen co the demo flow report -> dashboard ma khong can scan lai tren san khau.

## 6. Checklist truoc luc bao cao

1. Chay lai benchmark neu can refresh artifact.
2. Xac nhan `benchmark_summary.json` va `benchmark_summary.md` co trong `reports/dashboard_runs/reviewed-rule-profile-2026-09-07`.
3. Mo san report path traversal reviewed de demo chinh.
4. Chuan bi them report command injection lam phuong an du phong.
5. Bat dashboard local.
6. Check `GET /api/reports?includeArchive=1`.
7. Check `GET /api/reports?path=...` voi report demo.
8. Neu build co warning NFT thi chi note la non-blocking, khong doi sang fix dashboard trong sprint nay.

## 7. Chot ngan

Phan cua Anh coi nhu da co bo chot de dung:

- benchmark da co artifact that
- report demo da chon xong
- dashboard da verify doc duoc report moi
- runbook nay du de ca nhom lam lai cung mot kieu

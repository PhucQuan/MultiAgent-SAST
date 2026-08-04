# Aegis Findings Desk

Dashboard local cho Aegis-SAST, theo huong product layer tach rieng khoi scanner core. App nay doc cac file JSON da export trong `reports/`, chuan hoa ve mot finding schema thong nhat, roi hien thi theo workflow review gan voi cach Snyk/Datadog lam finding explorer.

## Muc tieu

- khong phu thuoc vao detector internals
- giu scanner deterministic la detector chinh
- de AI triage, explanation, workflow route, va reviewer memory nam o lop tren
- tao demo va thesis artifact dep hon CLI thuan

## Quyet dinh kien truc

1. Dashboard la app rieng trong `apps/findings-dashboard`, khong chen thang vao CLI.
2. Route server chi doc an toan ben trong thu muc `reports/`.
3. App ho tro ca report workflow/rich moi va report legacy cu.
4. Reviewer feedback duoc luu local trong `localStorage`, khong lam ban report goc.
5. Page chinh giu server boundary gon, tuong tac dat trong client shell.

## Cac file quan trong

- `src/lib/report-types.ts`: normalized schema cho report va finding
- `src/lib/report-adapter.ts`: bridge tu JSON report thuc te sang schema dashboard
- `src/lib/report-loader.ts`: loader phia server, gioi han trong `reports/`
- `src/lib/review-store.ts`: reviewer memory local
- `src/app/api/reports/route.ts`: API list/detail report
- `src/components/dashboard-shell.tsx`: shell chinh cua dashboard

## Chay local

Dung PowerShell thi nen goi qua `npm.cmd`:

```powershell
cd apps/findings-dashboard
npm.cmd install
npm.cmd run dev
```

Mo `http://localhost:3000`.

## Verify

```powershell
cd apps/findings-dashboard
npm.cmd run lint
npm.cmd run build
```

## Scope hien tai

Da co:

- report explorer ben trai
- finding queue o giua
- detail pane ben phai
- filter theo severity, status, language, family
- confidence, explanation, evidence path, source/sink context
- reviewer feedback local: note, mute, disposition
- import JSON thu cong ngoai workspace

Chua co:

- login/user system
- database feedback trung tam
- SARIF/PR comment integration
- remediation patch draft
- finding grouping theo root cause

## Huong mo rong hop ly

1. Dong bo feedback local -> reviewed bundles hoac store nho.
2. Chi hien finding `confirmed` va `likely` cho lane PR comment.
3. Them diff-aware scan va validator second pass.
4. Group finding theo source/sink/root cause.
5. Noi voi remediation draft + rescan validation.

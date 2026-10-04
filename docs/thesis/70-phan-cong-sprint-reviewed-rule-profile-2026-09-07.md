# Phan cong sprint 2026-09-07 den 2026-09-13 sau lane reviewed-rule-profile

## 1. Muc tieu tai lieu

Tai lieu nay chot cau tra loi cho 2 cau hoi:

1. Bay gio nen lam tiep cai gi.
2. Co nen phan cong tiep cho cac thanh vien khac khong.

Tra loi ngan gon la: **co**. Nhung sprint nay khong nen mo them scope lon. Can bam sat lane ma repo dang mo do trong worktree hien tai:

- reviewed rule profile da check-in;
- benchmark manifest da bat dau chuyen sang profile thay vi path roi;
- triage/AI can duoc do tac dong tren artifact da freeze, khong mix chung voi detector changes.

## 2. Snapshot hien tai da xac nhan

### 2.1. Current implementation

Tinh den **2026-09-07**, repo da co cac dau hieu sau:

- Python van la thesis lane chinh va la lane co claim manh nhat.
- Triage modes `all`, `visible`, `high-confidence` da co nen tu cac dot 17/08/2026.
- Worktree hien tai da them `--reviewed-rule-profile` vao:
  - `aegis_sast/cli.py`
  - `scripts/scan_target.py`
  - `scripts/compare_reviewed_bundle_scan.py`
  - `scripts/run_benchmark_v1.py`
- Da co checked-in profiles trong `aegis_sast/rule_profiles.py`:
  - `semgrep-python-core4`
  - `semgrep-python-ssrf`
- Rule validator da mo them profile scope trong `aegis_sast/rule_workbench/service.py`:
  - `python-reviewed-core4-v1`
  - `python-reviewed-ssrf-v1`

### 2.2. Chung cu repo dang o nhung dau

Ngay **2026-09-07**, nhom test tap trung cho lane nay da pass:

```bash
python -m pytest \
  tests/test_rule_profiles.py \
  tests/test_scan_target_profiles.py \
  tests/test_run_benchmark_v1.py \
  tests/test_reviewed_bundle_scan_compare.py \
  tests/test_normalized_rule_validator.py
```

Ket qua: **34 tests passed**.

Dieu nay co nghia la lane `reviewed_rule_profile` khong con o muc y tuong hay prototype vo. No da co:

- CLI surface;
- script surface;
- benchmark manifest support;
- validator scope;
- regression tests.

## 3. Cai nen lam tiep ngay bay gio

### 3.1. Uu tien 1 - Khoa lane reviewed-rule-profile thanh artifact benchmark that

Day la viec nen lam tiep ngay. Ly do:

- code da co;
- test da xanh;
- nhung claim thesis/demo se yeu neu chua co 1 run artifact that su dung profile moi;
- AGENTS cua repo cung nhac ro `--rules` va detector pipeline can duoc lam ro end-to-end.

Muc tieu cua uu tien 1:

- co 1 benchmark run that su dung `reviewed_rule_profile` thay vi path roi;
- co 1 report/summary ma ai trong nhom cung chay lai duoc;
- co 1 note ngan giai thich reviewed profile dang them gi len built-in core.

### 3.2. Uu tien 2 - Do rieng tac dong cua triage/AI tren artifact da freeze

Sau khi uu tien 1 xong, moi nen do tiep:

- detector + reviewed profile cho ra gi;
- triage deterministic doi gi;
- AI overlay doi them gi.

Neu sprint nay van tron ba thu tren cung mot lan chay thi se rat kho tra loi:

- diem nao do detector;
- diem nao do reviewed rules;
- diem nao do triage;
- diem nao do AI.

### 3.3. Uu tien 3 - Khoa ReviewMemory -> TriageMemory contract v1

Viec nay van can lam, nhung dung sau uu tien 1 va 2. Ly do:

- no tao cau chuyen san pham va nghien cuu rat dep;
- nhung no khong nen chen vao giua luc benchmark lane moi chua duoc freeze.

## 4. Engineering gaps can noi that

### 4.1. Current implementation

- Da co reviewed profile runtime entrypoint.
- Da co validator scope cho reviewed profiles.
- Da co benchmark manifests bat dau chuyen qua reviewed profiles.
- Da co triage architecture va dashboard review memory.

### 4.2. Engineering gaps

Nhung gap con lai dang dang lam nhat la:

1. Chua co 1 benchmark artifact da freeze va ghi lai ro rang bang reviewed profiles moi.
2. Chua tach ro delta do detector/profile va delta do triage/AI tren cung mot target.
3. `ReviewMemory -> TriageMemory` moi la spec story, chua thanh handoff end-to-end.
4. Thesis/demo note chua cap nhat dong bo voi lane `reviewed_rule_profile` moi.
5. Worktree hien tai dang nhieu file tam va thay doi chua freeze, nen can 1 sprint rat ky luat.

### 4.3. Research contribution

Neu lam dung thu tu, sprint nay co the tao ra dong gop nghien cuu ro rang:

- reviewed baseline khong con nam ngoai runtime ma da vao detector pipeline co kiem soat;
- triage/AI duoc do tac dong tren nen artifact co the lap lai;
- co the trinh bay tach bach hon giua detector evidence va review layer.

### 4.4. Demo value

Cuoi sprint nen co du 3 thu:

1. 1 lenh scan/benchmark profile-based chay duoc.
2. 1 report summary cho thay profile reviewed dang thay doi gi.
3. 1 minh hoa triage/AI doc lai artifact da freeze thay vi scan lai tung lan.

## 5. Phan cong cu the cho tung nguoi

## 5.1. Quan

**Vai tro sprint nay:** owner cua **detector core + reviewed rules + profile handoff**.

### Viec bat buoc

1. Khoa reviewed rule bundle thanh profile canonical.
   - Xac nhan `rules/reviewed/` khop voi 2 profile da check-in.
   - Xac nhan pham vi family cua `semgrep-python-core4` va `semgrep-python-ssrf` khong lech validator scope.

2. Smoke test end-to-end cho 3 entrypoint:
   - `aegis_sast/cli.py`
   - `scripts/scan_target.py`
   - `scripts/compare_reviewed_bundle_scan.py`

3. Viet 1 note handoff ngan:
   - profile nao them rules nao;
   - profile nao chi dung cho family nao;
   - profile nao la thesis-safe claim, profile nao la breadth extension.

### Deliverable

- 1 note markdown handoff trong `docs/thesis/` hoac `reports/benchmark/...`
- 1 ket qua smoke run cho `semgrep-python-core4`
- 1 ket qua smoke run cho `semgrep-python-ssrf`

### Han noi bo

**Thu Tu, 2026-09-09 - 22:00**

## 5.2. Anh

**Vai tro sprint nay:** owner cua **benchmark, runbook, integration, thesis-safe artifact freeze**.

### Viec bat buoc

1. Khoa manifest benchmark theo reviewed profile.
   - Uu tien reviewed suite Python truoc.
   - Chot target nao la core4, target nao la SSRF extension.

2. Chay lai benchmark summary bang lane moi.
   - Xuat `benchmark_summary.json`
   - Xuat markdown summary
   - Ghi ro profile nao da dung cho tung case

3. Chot runbook ngan de ca nhom chay cung mot kieu.
   - input nao
   - lenh nao
   - artifact nao duoc giu
   - file tam nao khong dua vao claim

4. Kiem tra import report vao dashboard va duong export can thiet.
   - JSON
   - Markdown
   - neu can thi check SARIF

### Deliverable

- 1 benchmark summary moi bang reviewed profile
- 1 runbook markdown ngan
- 1 checklist integration/demo pack

### Han noi bo

**Thu Sau, 2026-09-11 - 20:00**

## 5.3. Tue

**Vai tro sprint nay:** owner cua **triage, AI overlay, review-memory contract**.

### Viec bat buoc

1. Khong doi detector/rules trong sprint nay.
   - Tue nhan artifact da freeze tu Anh roi moi do triage.
   - Muc tieu la do tac dong review layer tren cung 1 artifact, khong thay nhieu bien cung luc.

2. Do tac dong deterministic triage va AI overlay tren artifact da freeze.
   - finding nao doi status
   - finding nao doi confidence
   - reason codes nao la quan trong nhat
   - truong hop nao van phai de `needs-review`

3. Chot spec `ReviewMemory -> TriageMemory` v1 dua tren code hien co.
   - diem xuat phat:
     - `apps/findings-dashboard/src/lib/review-store.ts`
     - `aegis_sast/core/models.py`
     - `aegis_sast/orchestration/state.py`
   - chi can spec + sample payload + ghi ro phan implement de sprint sau

4. Viet 1 note demo AI/triage dung scope.
   - khong claim AI thay detector
   - chi claim AI/triage doc lai finding, doi muc uu tien, va giai thich ly do

### Deliverable

- 1 note delta `detector/profile -> triage -> AI overlay`
- 1 spec `ReviewMemory -> TriageMemory` v1
- 1 note demo AI/triage 3-5 phut

### Han noi bo

**Chu Nhat, 2026-09-13 - 18:00**

## 6. Moc phoi hop chung

1. **Scope lock**
   - Thoi gian: **Thu Hai, 2026-09-07 - 21:00**
   - Muc tieu: chot sprint nay chi lam `reviewed profile -> benchmark freeze -> triage delta`.

2. **Profile handoff**
   - Thoi gian: **Thu Tu, 2026-09-09 - 22:30**
   - Dau vao:
     - Quan giao note profile
     - Quan giao smoke artifact

3. **Benchmark freeze**
   - Thoi gian: **Thu Sau, 2026-09-11 - 20:30**
   - Dau vao:
     - Anh giao summary va runbook
     - ca nhom chot artifact nao dung de claim

4. **Triage review**
   - Thoi gian: **Chu Nhat, 2026-09-13 - 18:30**
   - Dau vao:
     - Tue giao delta triage/AI
     - Tue giao memory contract v1

## 7. Viec khong nen lam trong sprint nay

De tranh dan trai, sprint nay **khong nen**:

1. Mo them language moi.
2. Redesign lon dashboard.
3. Tron detector change, reviewed profile change, triage change, AI change vao cung 1 benchmark claim.
4. Claim AI cai thien benchmark neu chua co side-by-side delta tren artifact da freeze.
5. Don worktree bang cach xoa file cua nhau khi chua chot file nao la artifact, file nao la tam.

## 8. Ket luan ngan

Neu hoi "gio lam tiep cai gi" thi cau tra loi hop ly nhat la:

1. **Khoa lane reviewed-rule-profile thanh benchmark artifact that.**
2. **Do rieng triage/AI tren artifact do.**
3. **Sau do moi khoa memory contract va demo story.**

Neu hoi "co phan cong tiep cho cac thanh vien khac khong" thi cau tra loi la:

- **Co, va van nen chia 3 lane ro rang.**
- **Quan** giu detector/rule/profile.
- **Anh** giu benchmark/runbook/integration.
- **Tue** giu triage/AI/review-memory.

Thu tu nay bam sat codebase hien tai hon la quay lai roadmap rong, va cung phu hop voi huong thesis dang duoc trinh bay trong cac tai lieu 00, 04 va 69.

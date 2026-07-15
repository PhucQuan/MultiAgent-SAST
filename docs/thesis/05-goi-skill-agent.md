# Goi skill agent da them vao repo

## Muc dich

Thu muc `skills/` duoc them de bien repo nay thanh mot workspace co huong agent ro rang, khong con phu thuoc vao mot prompt dai va kho tai su dung.

## Cac skill hien co

| Skill | Vai tro |
|---|---|
| `aegis-sast-agent` | Dieu phoi cong viec tong the |
| `aegis-sast-architecture` | Recon, kien truc, trust boundaries |
| `aegis-sast-rule-author` | Rule, plugin, coverage mo rong |
| `aegis-sast-triage` | Chuan hoa findings va giam FP |
| `aegis-sast-remediation` | Remediation plan va patch strategy |
| `aegis-sast-benchmark` | Baseline, metrics, benchmark |

## Cach dung de lam viec

### Truong hop 1: Muon hieu repo dang o dau

Su dung `aegis-sast-architecture`.

### Truong hop 2: Muon nang scanner core

Su dung `aegis-sast-rule-author`.

### Truong hop 3: Muon bo sung AI triage

Su dung `aegis-sast-triage`.

### Truong hop 4: Muon chuyen finding thanh patch plan

Su dung `aegis-sast-remediation`.

### Truong hop 5: Muon co so lieu de bao ve

Su dung `aegis-sast-benchmark`.

## Gia tri cua goi skill doi voi do an

- Cho thay project co quy trinh agent hoa
- Giam phu thuoc vao prompt ngau hung
- De mo rong va chuyen giao
- Bien phan tai lieu thanh mot phan cua he thong

## Ket hop voi AGENTS.md

File `AGENTS.md` o root repo dong vai tro entrypoint de:

- nhac tac nhan doc tai lieu tong hop
- chon skill dung theo bai toan
- khong tu nhan nham kha nang cua project


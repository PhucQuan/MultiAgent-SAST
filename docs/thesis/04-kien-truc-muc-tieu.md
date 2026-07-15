# Kien truc muc tieu cho Aegis-SAST

## Dinh huong tong the

Kien truc dich nen la kien truc 6 lop:

1. `Repo Intake`
2. `Detection Core`
3. `Finding Normalization`
4. `AI Triage`
5. `Remediation and Reporting`
6. `Evaluation and CI`

## Kien truc de xuat

### Lop 1: Repo Intake

- nhan thu muc hoac Git URL
- detect ngon ngu va framework
- chon scan profile

### Lop 2: Detection Core

- plugin registry
- AST parser
- rule engine
- taint propagation
- optional adapters cho Semgrep, secret scanner

### Lop 3: Finding Normalization

- dua tat ca findings ve mot schema thong nhat
- gan metadata cho finding:
  - tool
  - language
  - source
  - sink
  - evidence
  - severity

### Lop 4: AI Triage

- danh gia muc do thuyet phuc cua finding
- phan loai `confirmed`, `likely`, `needs-review`, `suppressed`
- viet explanation va remediation hint

### Lop 5: Remediation and Reporting

- tao remediation plan
- xuat JSON, Markdown, va SARIF
- tao final report theo severity va confidence

### Lop 6: Evaluation and CI

- benchmark scripts
- baseline comparison
- GitHub Actions
- regression rerun

## Mapping tu architecture hien tai sang architecture dich

| Hien tai | Dich |
|---|---|
| `cli.py` | repo intake + orchestration entrypoint |
| `vulnerability_detector.py` | detection core |
| `models.py` | finding normalization foundation |
| `gemini_client.py` | AI triage seed |
| `reporting/*.py` | reporting layer |
| `tests/` | regression base |
| docs moi | evaluation and thesis layer |

## Uu tien thuc thi

### Phase 1

- hoan thien local skill pack
- chuan hoa tai lieu do an
- fix cac diem lech giua claim va implementation

### Phase 2

- normalized finding schema
- triage statuses
- final report tu triage

### Phase 3

- benchmark
- baseline compare
- SARIF
- CI

### Phase 4

- remediation workflow
- autofix o muc co kiem soat


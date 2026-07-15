# Hien trang he thong

## So do module hien tai

| Khu vuc | File chinh | Vai tro |
|---|---|---|
| CLI | `aegis_sast/cli.py` | Nhan target, config, chay detector, goi AI verification, export report |
| Config | `aegis_sast/core/config.py` | Quan ly env, output, AI settings, cache |
| Registry | `aegis_sast/core/registry.py` | Dang ky plugin theo ngon ngu va extension |
| Models | `aegis_sast/core/models.py` | Dinh nghia finding, dataflow, severity, scan result |
| Rule engine | `aegis_sast/analysis/rule_engine.py` | Load YAML/JSON rules |
| Detector | `aegis_sast/analysis/vulnerability_detector.py` | Dieu phoi scan file va thu muc |
| Call graph | `aegis_sast/analysis/call_graph.py` | Function index va import resolution cho Python |
| Plugins | `aegis_sast/plugins/*.py` | Parse AST va extract source, sink, sanitizer theo ngon ngu |
| AI layer | `aegis_sast/ai/gemini_client.py` | Verify findings bang Gemini va cache |
| Reporting | `aegis_sast/reporting/*.py` | Export JSON va Markdown |
| Rules | `rules/*.yaml` | Khai bao source, sink, sanitizer |
| Tests | `tests/*.py` | Bao ve phan rule, plugin, dataflow, cross-file |

## Luong xu ly hien tai

1. Nguoi dung goi `aegis-sast scan <target>`.
2. CLI doc config va dang ky plugin.
3. Detector scan tung file theo extension ho tro.
4. Plugin parse AST va extract source, sink, sanitizer.
5. Taint flow duoc track tu source den sink.
6. Detector sinh `Vulnerability`.
7. Neu bat AI thi Gemini verify tung finding.
8. Report duoc export ra JSON va Markdown.

## Diem dang gia ve kien truc

### Diem on

- Tach lop core, analysis, plugin, ai, reporting kha ro
- Plugin interface lam cho he thong de mo rong
- Rule YAML giup de sua va mo rong detection
- Co chia models ro rang cho finding va scan result

### Diem can cung co hoa

- Detector dang chua la mot orchestration engine cho agent
- Rule custom qua `--rules` can duoc di xuyen het pipeline chat hon
- AI verification chua doi `finding list` thanh `triaged evidence list`
- Reporting chua co SARIF de di vao GitHub code scanning
- Kha nang danh gia va benchmark chua duoc dua vao kien truc

## Hien trang theo tung truc ky thuat

### Detection depth

- Pattern-based va AST-aware
- Co taint analysis co ban
- Python co cross-file support
- Cac ngon ngu khac chu yeu la intra-file

### Productization

- Co CLI
- Co Docker
- Co reports
- Chua co CI-first workflow
- Chua co web dashboard hoac SARIF

### AI maturity

- Co API client
- Co prompt layer
- Co cache
- Chua co status nhu `confirmed`, `likely`, `suppressed`
- Chua co confidence-driven filtering trong final report

## Gia tri hien tai doi voi do an

Neu trinh bay dung, hien trang nay cho phep ban tuyen bo:

- Ban da xay dung duoc mot SAST core scanner
- Ban da nghien cuu va ap dung AST + taint analysis
- Ban da co huong hybrid AI + rule-based

Nhung de thanh do an lon, can bo sung:

- bo skill agent
- benchmark khoa hoc
- triage engine
- workflow remediation


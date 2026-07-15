# Tai lieu tham khao noi bo

## Repo tham khao ben ngoai

### `utkusen/sast-skills`

Hoc:

- cach chia workflow thanh architecture -> parallel vuln checks -> final report
- cach dong goi quy trinh thanh bo skill

### `github/codeql`

Hoc:

- tu duy query-based analysis
- dataflow modeling
- packs va suites
- pham vi serious scanner ecosystem

### `usestrix/strix`

Hoc:

- tac nhan huong pentest va validation
- sandbox-first workflow
- CI va diff-based usage

### `semgrep/semgrep`

Hoc:

- rule UX
- multi-language practicality
- product integration
- scanner baseline de benchmark

## File trong repo Aegis-SAST nen doc ky

| File | Vi sao can doc |
|---|---|
| `aegis_sast/cli.py` | biet diem vao va luong scan hien tai |
| `aegis_sast/analysis/vulnerability_detector.py` | biet dieu phoi scanner core |
| `aegis_sast/analysis/call_graph.py` | biet phan cross-file hien tai |
| `aegis_sast/plugins/python_plugin.py` | biet logic extraction va propagation sau nhat |
| `aegis_sast/ai/gemini_client.py` | biet vai tro AI verification hien tai |
| `rules/python.yaml` | biet muc coverage va sanitizer |
| `tests/test_cross_file.py` | biet expectation cross-file |
| `docs/slides.html` | biet cach project dang duoc trinh bay |

## Cach doc tham khao cho dung

- Khong copy toan bo kien truc cua repo lon
- Chi hoc pattern phu hop voi scope do an
- Moi tham khao phai tra loi cau hoi:
  - hoc gi
  - ap dung vao dau
  - co do duoc khong


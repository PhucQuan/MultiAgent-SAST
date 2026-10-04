# Benchmark Runbook

## 1) Prerequisites

### Environment
- Python: 3.11 or 3.12 recommended (the repo examples use Python 3.12 in the README).
- Virtual environment: recommended to isolate dependencies.
- OS: Windows PowerShell examples below; bash/zsh is similar.

### Dependencies
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-ai.txt
python -m pip install -r requirements-dev.txt
```

### Input artifacts
Typical benchmark inputs used in this project:
- OWASP Benchmark dataset root: `D:\BenchmarkPython\testcode` (or equivalent local path)
- Ground-truth CSV: `D:\BenchmarkPython\expectedresults-0.1.csv`
- Aegis scan report JSON: one report under `reports/` such as `reports/aegis_sast_report_*.json`
- Optional benchmark score output directory: `reports/artifacts_owasp/BenchmarkPython_core_score/`

> In this repo, the latest benchmark summary is already available in `reports/artifacts_owasp/BenchmarkPython_core_score/owasp_score_summary.json` and `.md`.

---

## 2) How to run

### 2.1 Scan target with Aegis
```powershell
python -m aegis_sast.cli scan "D:\BenchmarkPython\testcode" --no-ai --output json --output markdown --output sarif --output-dir reports\artifacts_owasp\BenchmarkPython_core
```

If the goal is a smaller local smoke run:
```powershell
python -m aegis_sast.cli scan test_projects --no-ai --output json --output markdown --output sarif --output-dir reports\manual_smoke
```

### 2.2 Score the scan report against OWASP ground truth
```powershell
python scripts\score_owasp_benchmark.py `
  --report reports\artifacts_owasp\BenchmarkPython_core\aegis_sast_report_*.json `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --output-dir reports\artifacts_owasp\BenchmarkPython_core_score
```

Use the actual report path if multiple files exist:
```powershell
python scripts\score_owasp_benchmark.py `
  --report reports\aegis_sast_report_20260822_194845.json `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --output-dir reports\artifacts_owasp\BenchmarkPython_core_score
```

### 2.3 Optional Semgrep baseline
```powershell
python scripts\run_semgrep_owasp_python.py --family PATH_TRAVERSAL --family SQL_INJECTION --family COMMAND_INJECTION --family INSECURE_DESERIALIZATION
```

---

## 3) Benchmark modes: all, visible, high-confidence

### Meaning of each mode
The benchmark scorer applies a triage filter before counting findings:

- `all`: no filtering; all findings are included
- `visible`: exclude only `suppressed` findings
- `high-confidence`: keep only `confirmed` and `likely` findings

The triage statuses are the normalized statuses used by the workflow:
- `confirmed`
- `likely`
- `needs-review`
- `suppressed`

### How the score is computed
For each family or aggregate result:
- `TP` = true positive
- `FP` = false positive
- `FN` = false negative
- `precision = TP / (TP + FP)`
- `recall = TP / (TP + FN)`
- `F1 = 2 * precision * recall / (precision + recall)`

### Current project result (already measured)
From the latest summary in `reports/artifacts_owasp/BenchmarkPython_core_score/owasp_score_summary.json`:

| Mode | Precision | Recall | F1 | Notes |
|---|---:|---:|---:|---|
| `all` | 0.8947 | 0.8416 | 0.8673 | Includes all findings |
| `visible` | 1.0000 | 0.8416 | 0.9140 | Suppressed findings removed |
| `high-confidence` | 1.0000 | 0.7228 | 0.8391 | Strict confidence filter |

Interpretation:
- `visible` is the best demo-friendly metric because it eliminates noise while preserving most true positives.
- `high-confidence` is useful for a conservative security-readiness narrative; it reduces false positives but sacrifices recall.
- `all` is the full raw scan picture and is useful for completeness and downstream analysis.

---

## 4) Troubleshooting

| Problem | Symptom | Likely cause | Fix |
|---|---|---|---|
| Python version mismatch | `SyntaxError` or package install failure | Python not 3.11/3.12 | Recreate venv with `py -3.12 -m venv .venv` |
| Missing Python packages | `ModuleNotFoundError` | Requirements not installed | Run `python -m pip install -r requirements.txt` and AI/dev requirements |
| No report file found | Benchmark script exits with file missing | Wrong `--report` path | Point to the newest JSON under `reports/` |
| CSV not found | `FileNotFoundError` from score script | Benchmark ground truth not present | Ensure `D:\BenchmarkPython\expectedresults-0.1.csv` exists or pass the correct path |
| SARIF export absent | No SARIF output generated | `--output sarif` not set or scanner not configured | Add `--output sarif` and confirm the output directory |
| Benchmark output directory empty | No score summary generated | Scan report not valid or grader failed | Validate the JSON report is non-empty and contains findings |
| Triage statuses look noisy | Too many `needs-review` or `suppressed` | Triage workflow layered too broadly | Re-run with intended filter: `all` / `visible` / `high-confidence` |
| Zip packaging fails | `package_artifacts.py` stops early | Required file missing or invalid path | Ensure repo root is correct and required files exist |

### Quick validation checklist
```powershell
python scripts\doctor_env.py
python -m aegis_sast.cli --help
python scripts\score_owasp_benchmark.py --help
```

---

## 5) Recommended reporting pattern for the team

For final thesis/demo presentation, use these three views together:
1. `all`: transparency / full scan result
2. `visible`: business-friendly / practical triage result
3. `high-confidence`: conservative evidence-quality result

This gives a balanced story: raw capability, operational usability, and evidence quality.

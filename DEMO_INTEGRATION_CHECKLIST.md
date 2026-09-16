# Demo Integration Checklist

## 1) End-to-end demo scenario

### Step 1: Scan Python target (reduced FP / PATH_TRAVERSAL)
- Target: Python OWASP Benchmark lane, especially the reduced false-positive PATH_TRAVERSAL case set.
- Goal: generate a clean JSON + SARIF report.
- Expected artifacts:
  - `reports/artifacts_owasp/BenchmarkPython_core/` (or equivalent scan output folder)
  - `aegis_sast_report_*.json`
  - `*.sarif` if export is enabled

```powershell
python -m aegis_sast.cli scan "D:\BenchmarkPython\testcode" --no-ai --output json --output markdown --output sarif --output-dir reports\artifacts_owasp\BenchmarkPython_core
```

### Step 2: Triage / LangGraph workflow
- Run the deterministic scan first.
- Feed findings into the triage layer.
- Classify into four statuses:
  - `confirmed`
  - `likely`
  - `needs-review`
  - `suppressed`

Expected behavior:
- noisy or non-actionable findings become `suppressed`
- clear exploitable patterns remain `confirmed` / `likely`
- borderline cases remain `needs-review`

### Step 3: Aggregate results and benchmark
- Score the report against OWASP expected results.
- Compare across the 3 benchmark modes:
  - `all`
  - `visible`
  - `high-confidence`

```powershell
python scripts\score_owasp_benchmark.py `
  --report reports\aegis_sast_report_20260822_194845.json `
  --expected-results "D:\BenchmarkPython\expectedresults-0.1.csv" `
  --output-dir reports\artifacts_owasp\BenchmarkPython_core_score
```

### Step 4: Dashboard showcase
- Show the scan result summary in the dashboard.
- Emphasize the triage distribution and final visible set.
- Highlight that the dashboard reflects the same evidence used for benchmark scoring.

---

## 2) Pre-demo checklist

Use this before a live report or presentation:

### Artifacts
- [ ] Latest Aegis JSON report exists under `reports/`
- [ ] Benchmark summary JSON exists under `reports/artifacts_owasp/BenchmarkPython_core_score/`
- [ ] Benchmark summary Markdown exists and is readable
- [ ] SARIF export exists if the demo requires CI-style output
- [ ] Demo target path is stable and accessible

### Config and scripts
- [ ] Python venv is active
- [ ] Dependencies installed from `requirements.txt` and AI/dev requirements
- [ ] `scripts/score_owasp_benchmark.py` is executable
- [ ] Benchmark ground-truth CSV path is valid
- [ ] Output directory is writable
- [ ] Dashboard app is running (if the demo includes UI)

### Sanity checks
- [ ] Report contains findings in expected categories (PATH_TRAVERSAL, COMMAND_INJECTION, SQL_INJECTION, INSECURE_DESERIALIZATION)
- [ ] Triage statuses are present and not empty
- [ ] `visible` mode removes `suppressed` noise cleanly
- [ ] Final benchmark summary matches latest run

---

## 3) Speaking points for the team

### Core message
- Aegis-SAST is not only a detector; it is a full scan-to-triage-to-report workflow.
- We reduce noise before the human sees the result.
- Benchmarking provides quantitative proof, not just demo screenshots.

### Demo narrative
1. "We start with a real Python benchmark target and scan it."
2. "The triage workflow classifies findings into `confirmed`, `likely`, `needs-review`, and `suppressed`."
3. "We then score the report to compare the raw and filtered views."
4. "The dashboard shows the same evidence in a clean, human-readable format."

### Key numbers to mention
- `visible` mode reaches `precision = 1.0000`, which is strong for reduced false positives.
- `all` mode demonstrates full raw detection capability.
- `high-confidence` mode is useful for audit/strict review, at the cost of lower recall.

### Closing line
> We are not only finding vulnerabilities—we are making them operationally reviewable, benchmarkable, and dashboard-ready.

---

## 4) Suggested demo flow for the presenter

```text
Scan target
  -> JSON report + SARIF export
  -> Triage workflow decides status
  -> Benchmark scorer computes all / visible / high-confidence
  -> Dashboard displays final results
```

This is the unified story for the team during presentation.

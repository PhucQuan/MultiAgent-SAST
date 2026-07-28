# Rule Workbench V1

Minimal local web scaffold for the Aegis rule-review flow.

## Run

```powershell
python scripts/run_rule_workbench.py --port 8765
```

Then open `http://127.0.0.1:8765`.

## Scope

- build a review bundle from a local Semgrep-shaped seed
- validate the normalized output
- preview generated artifacts
- export an optional legacy bridge for `scan_target.py --rules`

This V1 intentionally does **not** push rules straight into runtime detection
and does **not** claim AI-generated rules are production-ready without review.

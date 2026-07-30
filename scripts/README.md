# Scripts

This directory is for operational scripts that support the thesis workflow.

## Good candidates

- benchmark runners
- SARIF export helpers
- result aggregation scripts
- chart generation helpers
- dataset preparation utilities

## Current examples

- `manual_smoke.py`: quick CLI/workflow smoke checks
- `manual_graph_smoke.py`: graph-core smoke checks without Tree-sitter
- `benchmark_python_graph_ablation.py`: synthetic ablation runner for Python graph v1.2
- `scan_target.py`: manual wrapper for scanning any local file or repository target
  - supports `--exclude-dir`, `--exclude-glob`, `--exclude-profile`, and `--progress-every` for large repo scans
  - auto-applies a conservative `baseline` exclusion profile for directory scans
  - supports `--artifact-profile`, `--keep-last`, `--view`, and `--no-save` for lighter terminal-first demo scans
- `analyze_scan_report.py`: summarize one JSON report or compare two reports after manual scans
  - highlights top finding families, source/sink patterns, duplicate groups, and optional source-pattern mismatches
- `import_semgrep_subset.py`: normalize a small Semgrep taint-rule subset into the Aegis review schema
  - keeps provenance metadata and is meant for human-reviewed seed imports
- `compare_reviewed_bundle_scan.py`: run default rules and one reviewed legacy bundle side by side on a small target
  - writes `comparison_summary.json` so the team can record Phase 1 smoke results for the thesis
- `run_benchmark_v1.py`: run the reviewed-bundle mini benchmark across the 3 Python V1 families
  - aggregates per-case `comparison_summary.json` files into one `benchmark_summary.json` and Markdown report
  - also supports custom manifests such as `datasets/benchmark/reviewed_bundle_v1/cases_sql_injection_extension.json` and `cases_ssrf_extension.json`
- `report_console.py`: terminal-first viewer and cleanup helper for `manual_targets`, `rule_review_smoke`, and benchmark artifacts
  - supports `runs`, `show`, and `clean` subcommands so demo/review flows do not have to dig through timestamped directories

## Guidelines

- keep scripts small and task-specific
- prefer calling package code instead of duplicating logic
- document inputs and outputs at the top of each script

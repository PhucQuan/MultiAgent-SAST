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
- `analyze_scan_report.py`: summarize one JSON report or compare two reports after manual scans
  - highlights top finding families, source/sink patterns, duplicate groups, and optional source-pattern mismatches
- `import_semgrep_subset.py`: normalize a small Semgrep taint-rule subset into the Aegis review schema
  - keeps provenance metadata and is meant for human-reviewed seed imports

## Guidelines

- keep scripts small and task-specific
- prefer calling package code instead of duplicating logic
- document inputs and outputs at the top of each script

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

## Guidelines

- keep scripts small and task-specific
- prefer calling package code instead of duplicating logic
- document inputs and outputs at the top of each script

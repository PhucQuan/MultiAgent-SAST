# Benchmarks

This directory is reserved for thesis-grade evaluation assets.

## Purpose

- store benchmark plans and evaluation notes
- organize baseline comparison inputs and outputs
- separate research evaluation from day-to-day examples

## Suggested layout

```text
benchmarks/
  baselines/
  fixtures/
  results/
```

## Scope

- `baselines/`: Semgrep and CodeQL comparison notes, command templates, and result mappings
- `fixtures/`: benchmark-ready sample applications and labeled cases
- `results/`: generated benchmark outputs such as CSV, JSON, and charts

## Current in-repo benchmark

The repository now includes a lightweight synthetic ablation benchmark for the
Python graph core:

- dataset: `datasets/synthetic/python_graph_ablation_v1_2/`
- runner: `scripts/benchmark_python_graph_ablation.py`

This is intentionally smaller than a full Semgrep or CodeQL comparison, but it
gives the thesis workflow a repeatable benchmark for graph-core improvements.

Generated benchmark results should not be committed by default.

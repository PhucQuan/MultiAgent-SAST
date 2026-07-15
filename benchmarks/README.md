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

Generated benchmark results should not be committed by default.

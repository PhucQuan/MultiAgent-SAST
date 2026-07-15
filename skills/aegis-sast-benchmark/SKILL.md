---
name: aegis-sast-benchmark
description: Thiết kế benchmark, baselines, metrics, và experiment matrix cho Aegis-SAST so với Semgrep, CodeQL, hoặc bộ mẫu dễ tổn thương tự xây dựng. Use when preparing thesis evaluation, comparing tools, or proving the value of AI triage and cross-file analysis.
---

# Aegis SAST Benchmark

Read `references/evaluation-plan.md` before planning experiments.

## Benchmark For Credibility

- Compare against at least one baseline scanner.
- Use repeatable datasets.
- Report both quality and cost.

## Minimum Metrics

- precision
- recall
- F1
- runtime
- findings per vulnerability class
- false-positive reduction before and after AI triage

## Default Baselines

- Semgrep for rule-based multi-language comparison
- CodeQL for mature query and dataflow comparison
- curated local vulnerable samples for controlled demonstrations

## Produce Thesis-Grade Outputs

- experiment matrix
- benchmark dataset list
- measurement protocol
- result table templates
- interpretation notes


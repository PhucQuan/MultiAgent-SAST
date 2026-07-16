# Synthetic Dataset

This directory is for labeled synthetic findings and small vulnerable/safe code samples.

## Recommended contents

- per-language samples for Python, JavaScript, and Java
- per-CWE sample groups
- labels such as `true_positive`, `false_positive`, `needs_review`

## Research value

Synthetic datasets make it easier to:

- run ablation studies
- measure false-positive reduction
- compare deterministic-only vs hybrid-agent workflows

## Current dataset

- `python_graph_ablation_v1_2/`: 6 labeled Python cases for CFG/DFG, dead-path pruning, loop control, and local function summary ablation

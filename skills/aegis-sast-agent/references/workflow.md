# Aegis-SAST End-to-End Workflow

## Goal

Use this workflow when the repository needs to behave like a real SAST agent platform instead of a standalone scanner.

## Phases

### 1. Recon

- Read the thesis docs first.
- Identify the current code path for parsing, rule loading, taint tracking, AI verification, and reporting.
- Record what is implemented versus what is still aspirational.

### 2. Scope Selection

Choose one primary workstream:

- `architecture`: map attack surface, trust boundaries, and service entry points
- `scanner-core`: rules, plugins, taint propagation, call graph
- `triage`: evidence scoring, false-positive reduction, normalized findings
- `remediation`: patch strategies and fix generation
- `benchmark`: datasets, baselines, metrics, and experiment scripts

### 3. Artifact Production

For each workstream, create reusable artifacts under `docs/thesis/`:

- architecture diagrams in Markdown form
- evaluation criteria
- backlog and milestones
- benchmark matrices
- demo narratives

### 4. Implementation Translation

Translate design into engineering items with:

- target files
- expected behavior change
- validation plan
- thesis value

## Quality Bar

Only call the project thesis-ready when it has:

- a clear problem statement
- a meaningful research or engineering contribution
- an evaluation plan
- a repeatable demo
- a roadmap beyond the current portfolio scope


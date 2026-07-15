---
name: aegis-sast-agent
description: Điều phối end-to-end workflow cho dự án Aegis-SAST: đọc hiện trạng repo, chọn hướng quét và phân tích phù hợp, chuẩn hóa findings, triage, remediation planning, benchmark, và viết tài liệu đồ án. Use when building this repo into a thesis-scale SAST agent rather than a simple scanner.
---

# Aegis SAST Agent

Read `references/workflow.md` before acting.

## Run The Core Flow

1. Read `docs/thesis/00-tong-hop-da-lam.md`.
2. Inspect the relevant source files before proposing changes.
3. Decide whether the task is mainly:
   - architecture and recon
   - rule and detection evolution
   - finding triage
   - remediation
   - benchmark and thesis evidence
4. Route into the matching local skill when a narrower workflow exists.

## Keep The Project Honest

- Distinguish between what the repo already does and what is only planned.
- Prefer artifacts the user can reuse in a thesis:
  - architecture notes
  - benchmark plans
  - result schemas
  - demo scripts
  - defense notes
- Turn broad requests into concrete deliverables inside `docs/thesis/`.

## Treat Aegis-SAST As A Hybrid System

- Use the current AST + taint engine as the scanner core.
- Treat AI as a triage and remediation assistant, not as the only security signal.
- Prefer a hybrid future architecture:
  - local rule engine
  - optional external scanners
  - normalized finding schema
  - evidence-aware AI triage

## Default Deliverables

When the user asks for large project improvement, produce some combination of:

- a current-state summary
- a gap analysis
- a target architecture
- a roadmap
- a benchmark plan
- a demo or defense pack


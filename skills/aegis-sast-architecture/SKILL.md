---
name: aegis-sast-architecture
description: Phân tích kiến trúc codebase, attack surface, luồng dữ liệu, trust boundaries, module security-critical, và điểm vào của hệ thống. Use when mapping the current Aegis-SAST repo, preparing thesis architecture notes, or deciding where an agent layer should sit.
---

# Aegis SAST Architecture

Read `references/recon-checklist.md` before doing deep analysis.

## Map The Repository

1. Identify the scanner core:
   - CLI
   - detector
   - rule engine
   - plugin system
   - AI layer
   - reporting
2. Identify the evidence path from input source to exported report.
3. Separate current architecture from target architecture.

## Focus On Security-Critical Boundaries

- repository input and file discovery
- parsing boundaries
- taint propagation boundaries
- cross-file resolution boundaries
- AI prompt and response boundaries
- report generation boundaries

## Produce Architecture Notes

Write or update notes that explain:

- what each module is responsible for
- what data moves between modules
- where false positives or false negatives are most likely
- which modules must change for thesis-scale growth

## Default Files To Inspect

- `aegis_sast/cli.py`
- `aegis_sast/analysis/`
- `aegis_sast/plugins/`
- `aegis_sast/ai/`
- `aegis_sast/reporting/`
- `rules/`
- `tests/`


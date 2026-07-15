---
name: aegis-sast-triage
description: Chuẩn hóa findings, chấm điểm bằng chứng, giảm false positives, và tách confirmed risks khỏi noisy matches cho Aegis-SAST. Use when converting raw scanner output into thesis-grade evidence, AI triage, or reviewer-friendly reports.
---

# Aegis SAST Triage

Read `references/triage-schema.md` before triaging findings.

## Triage Raw Findings Into Evidence Classes

Classify findings into:

- `confirmed`
- `likely`
- `needs-review`
- `suppressed`

## Score Evidence, Not Just Pattern Matches

For each finding, check:

- source credibility
- propagation clarity
- sink exploitability
- mitigation presence
- AI agreement
- dynamic test feasibility

## Keep AI In A Supporting Role

- Use AI to explain, compare, and rank.
- Do not let AI silently overwrite deterministic evidence.
- Preserve raw scanner evidence alongside AI commentary.

## Produce Useful Triage Artifacts

- normalized finding schema
- evidence notes
- suppression rationale
- severity rationale
- follow-up action list


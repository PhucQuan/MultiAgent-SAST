# Evaluation Plan Reference

## Core Questions

1. Does Aegis-SAST find meaningful vulnerabilities on curated samples?
2. Where does it outperform or underperform against Semgrep and CodeQL?
3. How much does AI triage improve report usefulness?
4. Is the system good enough to justify a thesis contribution?

## Suggested Experiment Tracks

- Track A: current Aegis-SAST core scanner on local examples
- Track B: Aegis-SAST plus improved triage workflow
- Track C: Aegis-SAST against Semgrep on overlapping rules
- Track D: Aegis-SAST against CodeQL on supported languages and classes

## What To Report

- exact dataset names
- exact command lines
- scanner configuration
- class coverage limits
- interpretation caveats

## Important Warning

Do not oversell multi-language depth if the implementation quality differs sharply between languages.
Use benchmark results to support nuanced claims instead of marketing-style claims.


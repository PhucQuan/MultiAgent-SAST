# Rule Design Guide

## Use The Existing Repo Structure

- Put declarative patterns in `rules/*.yaml`.
- Keep language-specific AST extraction in `aegis_sast/plugins/`.
- Keep shared scan coordination in `aegis_sast/analysis/vulnerability_detector.py`.

## Evaluate Rule Quality With Four Questions

1. Does the pattern match a true untrusted source or a real dangerous sink?
2. Can the current plugin extract it reliably from the AST?
3. Does the severity align with practical exploitability?
4. Is there a realistic sanitizer or allowlist pattern that should reduce confidence?

## Common Upgrade Directions

- stronger sink categorization
- framework-aware sources
- sanitizer effectiveness by vulnerability class
- dynamic identifier handling
- better severity mapping

## Thesis Value

Good rule work supports both:

- engineering depth through scanner quality
- research depth through measurable precision and recall changes


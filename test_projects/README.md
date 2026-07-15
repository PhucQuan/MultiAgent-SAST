# Test Projects

This directory contains local scan targets used for quick manual testing.

## Role in the repo

- smoke-test targets for CLI scanning
- cross-file validation targets
- small local apps for debugging taint propagation

## Difference from other folders

- `examples/`: user-facing demo samples
- `tests/fixtures/`: unit-test fixtures
- `benchmarks/fixtures/`: evaluation-grade benchmark assets

## Note

Over time, benchmark-quality cases should move into `benchmarks/fixtures/`.
This folder can stay focused on developer debugging and quick manual checks.

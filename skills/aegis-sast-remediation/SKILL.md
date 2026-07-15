---
name: aegis-sast-remediation
description: Lập kế hoạch sửa lỗi và viết remediation proposals cho Aegis-SAST findings, ưu tiên patch tối thiểu, đúng framework, dễ review, và có test strategy. Use when turning confirmed vulnerabilities into safe code changes, patch plans, or PR-ready notes.
---

# Aegis SAST Remediation

Read `references/fix-playbook.md` before proposing fixes.

## Fix Conservatively

- Preserve behavior unless the vulnerability requires a breaking change.
- Prefer the framework-native secure pattern.
- Keep patches minimal and reviewable.

## Explain The Fix In Three Layers

1. What is vulnerable now
2. What the secure pattern is
3. Why the new code is safer

## Always Pair Fixes With Validation

Include:

- unit or regression tests
- scanner rerun expectation
- any manual verification step

## Favor Remediation Patterns That Scale

- parameterized queries
- allowlists for identifiers
- safer subprocess invocation
- output encoding
- authorization checks
- safer deserialization and parser settings


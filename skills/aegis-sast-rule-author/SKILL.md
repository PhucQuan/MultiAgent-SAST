---
name: aegis-sast-rule-author
description: Thiết kế, mở rộng, và tinh chỉnh rule cho Aegis-SAST, bao gồm sources, sinks, sanitizers, severity logic, plugin extraction, và plan mở rộng đa ngôn ngữ. Use when adding new detections, improving precision, or planning support beyond Python-heavy flows.
---

# Aegis SAST Rule Author

Read `references/rule-design.md` before editing rules or plugins.

## Start From The Detection Contract

1. Identify the vulnerability class.
2. Define the source, sink, sanitizer, and propagation expectations.
3. Decide whether the change belongs in:
   - YAML rules
   - plugin extraction logic
   - taint tracking logic
   - severity logic
   - tests

## Prefer Small, Testable Changes

- Add or refine one vulnerability family at a time.
- Update the matching language rule file first.
- Modify plugin code only when the rule schema cannot express the need.
- Add or update tests immediately after rule changes.

## Keep Multi-Language Claims Conservative

- Do not claim deep support for a language unless propagation and sinks are actually covered.
- Distinguish:
  - syntax recognition
  - sink matching
  - taint propagation
  - cross-file capability

## Default Deliverables

- updated rule strategy
- explanation of why a detection belongs where it does
- regression test ideas
- notes for thesis reporting about coverage and limitations


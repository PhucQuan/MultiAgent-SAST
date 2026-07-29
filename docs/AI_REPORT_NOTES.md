# AI Report Notes

## Architecture Argument

The AI layer is intentionally placed behind the deterministic scanner. It does not parse repositories, reconstruct ASTs, or invent new source-to-sink evidence. Its input is limited to `AITriageInput`: `NormalizedFinding`, `EvidenceBundle`, and optional `BenchmarkMetadata`.

This keeps the scanner responsible for recall and technical evidence, while AI contributes evidence review, knowledge-assisted triage, false-positive analysis, explanations, remediation, route logging, and benchmark metadata.

## Hallucination Controls

- Pydantic contracts use `extra="forbid"`.
- Finding and evidence IDs must match.
- Node prompts separate observed evidence, inference, missing evidence, and final assessment.
- Prompts explicitly forbid repository reads and invented source lines.
- Invalid structured output is retried and then falls back to `needs-review`.
- Suppression requires sanitizer, dead-path, or false-positive evidence.

## Why Multi-Node Workflow

The workflow separates roles:

- Planner selects route and evidence gaps.
- KnowledgeLoader selects a small CWE/language/framework section.
- Auditor checks evidence strength.
- Skeptic looks for false-positive indicators.
- Judge assigns one of four final statuses.
- Reporter enriches explanation/remediation without changing status.

This separation makes route decisions and failure modes measurable for ablation E3.

## Benchmark Story

E1 compares static-only labels with static plus AI triage.

E2 compares no-knowledge behavior with CWE knowledge-assisted behavior.

E3 compares a single prompt against the multi-node workflow.

Raw rows store:

- `experiment_id`
- `finding_id`
- `language`
- `vuln_type`
- `ground_truth`
- `predicted_status`
- `route_taken`
- `model_name`
- `prompt_version`
- `knowledge_version`
- `token_usage`
- `latency_ms`
- `error`
- `run_index`

## Defense Answers

**AI hallucination:** The system validates structured output and only passes normalized evidence to prompts.

**Why not one prompt:** Multi-node routing exposes where decisions are made and enables E3 ablation on consistency, invalid-output rate, latency, and status quality.

**Knowledge-card bias:** E2 measures knowledge-assisted behavior separately. Knowledge cards are versioned with `knowledge_version`.

**Gemini failure:** The structured client retries invalid JSON/schema output and falls back to `needs-review`.

**Recall risk:** Suppression is conservative. Ambiguous cases go to `needs-review` instead of suppressed.

**Capability parity:** The same AI schema is used for Python, JavaScript, Java, and PHP. Any language capability gap is measured in evidence quality, not hidden by schema changes.

## Remaining Inputs Needed

Real thesis metrics still require a fixed labeled dataset from Quân and a locked Gemini model/API configuration.

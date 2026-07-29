# AI Triage Contract

This document locks the boundary between the deterministic SAST core and the AI triage layer.

## Boundary

AI nodes must only consume normalized data produced by the deterministic core:

- `NormalizedFinding`
- `EvidenceBundle`
- `BenchmarkMetadata`

AI nodes must not read the repository directly, re-parse source files, run AST analysis, or reconstruct taint flow. Repository intake, parsing, AST, CFG, DFG, taint propagation, source-to-sink path construction, sanitizer detection, and benchmark labeling belong to the deterministic core.

The AI layer receives `AITriageInput` from `aegis_sast.triage.schema`:

- `finding`: the full normalized finding.
- `evidence`: source, sink, snippets, data-flow path, sanitizer information, cross-file flag, and call-chain depth.
- `benchmark`: optional benchmark metadata for evaluation.

## Required Finding Fields

Every AI-facing `NormalizedFinding` requires:

- `finding_id`
- `language`
- `vuln_type`
- `cwe_id`
- `severity`
- `confidence`
- `static_confidence`
- `source_location`
- `sink_location`
- `evidence_snippets`
- `data_flow_path`
- `sanitizer_info`
- `graph_metadata`
- `cross_file`
- `call_chain_depth`
- `rule_id`

The same schema is used for Python, JavaScript, Java, and PHP. Language-specific analysis detail should be represented in deterministic evidence fields or metadata, not by changing the AI payload shape.

## Final Triage States

| Status | Meaning |
| --- | --- |
| `confirmed` | Evidence is strong enough and includes a valid source-to-sink path. |
| `likely` | The finding is probably exploitable but one part of the evidence is incomplete. |
| `needs-review` | AI cannot conclude confidently and a security reviewer must inspect it. |
| `suppressed` | The finding is a false positive, effectively sanitized, or not reachable. |

## Node Outputs

Each node must return a structured Pydantic model. Free-form text is not a valid node output.

### Auditor

`AuditorResult`:

- `is_exploitable`
- `confidence`
- `evidence_strength`
- `sanitizer_effective`
- `reasoning_summary`
- `missing_evidence`

Workflow implementations may use `AuditorReview`, which extends this contract with routing metadata and source-context windows loaded by deterministic orchestration.

### Skeptic

`SkepticResult`:

- `objections`
- `false_positive_indicators`
- `sanitizer_found`
- `dead_code_suspected`
- `recommended_status`
- `confidence`

Workflow implementations may use `SkepticReview`, which extends this contract with execution metadata and confidence caps.

### Judge

The final judge emits `TriageDecision`:

- `status`
- `confidence`
- `ai_confidence`
- `vulnerability_explanation`
- `remediation_note`
- `supporting_evidence`
- `limitations`
- `route_taken`
- `token_usage`
- `latency_ms`
- `model_name`

The allowed final statuses are exactly `confirmed`, `likely`, `needs-review`, and `suppressed`.

## Validation Rules

Contracts use Pydantic with `extra="forbid"`. Missing required fields and unexpected free-text fields fail validation before an agent result can enter workflow state or reporting.

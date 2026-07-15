# Finding Triage Schema

## Required Fields

- `finding_id`
- `tool`
- `language`
- `vulnerability_type`
- `severity`
- `status`
- `file_path`
- `line_number`
- `source_summary`
- `sink_summary`
- `evidence_summary`
- `mitigation_summary`
- `ai_confidence`
- `review_notes`

## Suggested Status Meanings

- `confirmed`: deterministic path and strong exploitability evidence
- `likely`: meaningful evidence, but one step is still indirect or weakly modeled
- `needs-review`: incomplete path or ambiguous mitigation
- `suppressed`: duplicate, irrelevant, or convincingly mitigated

## Triage Heuristics For Aegis-SAST

- Promote findings when the dataflow is clear and the sink is high impact.
- Demote findings when the source is synthetic and the mitigation is strong.
- Keep a finding visible if it matters for thesis discussion, even when not fully confirmed.


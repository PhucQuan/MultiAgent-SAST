# AI Implementation Status

Date: 2026-07-29

## Completed in Code

| Phase | Status | Evidence |
| --- | --- | --- |
| 0 Gap analysis | Complete | `docs/AI_GAP_ANALYSIS.md` |
| 1 AI contract | Complete | `aegis_sast/triage/schema.py`, `aegis_sast/orchestration/contracts.py` |
| 2 Mock fixtures | Complete seed set plus generator | `tests/fixtures/ai_findings/`, `aegis_sast/ai/fixtures.py`, `scripts/generate_ai_mock_fixtures.py` |
| 3 Knowledge layer | Complete seed layer | `aegis_sast/knowledge/schema.py`, `aegis_sast/knowledge/cards/*.yaml` |
| 4 Structured LLM output | Complete testable wrappers | `StructuredGroqClient`, `StructuredGeminiClient`, retry/parser/token metadata tests, optional smoke scripts |
| 5 Core nodes | Complete deterministic AI nodes | Planner, KnowledgeLoader, Auditor, Skeptic, Judge, Reporter |
| 6 Workflow/routing | Complete LangGraph-ready workflow | `AITriageWorkflow`, optional `langgraph_adapter.py` |
| 7 Mock E2E tests | Complete for seed set | `tests/test_ai_workflow_e2e.py` |
| 8 Deterministic-core integration | Contract-ready | Existing scanner workflow remains compatible; real batch depends on Quân output |
| 9 Pipeline hardening | Partial alpha | Execution summary, route distribution, per-finding errors, token/latency fields |
| 10 Ablation study | Reproducible mock runner and evaluator | `scripts/run_ai_experiments.py`, `scripts/evaluate_ai_results.py`, configs under `benchmarks/ai_experiments/` |
| 11 Report/demo prep | Partial | Status docs, raw experiment fields, defense-oriented contract docs |

## How to Run

Run focused AI tests:

```bash
/opt/anaconda3/bin/python -m pytest \
  tests/test_ai_fixtures.py \
  tests/test_knowledge_selection.py \
  tests/test_gemini_client.py \
  tests/test_ai_workflow_e2e.py \
  tests/test_ai_experiments.py
```

Run an experiment:

```bash
/opt/anaconda3/bin/python scripts/run_ai_experiments.py \
  --config benchmarks/ai_experiments/e3_workflow_ablation.json
```

Output:

- raw JSONL: `benchmarks/ai_experiments/results/<experiment_id>.jsonl`
- summary JSON: `benchmarks/ai_experiments/results/<experiment_id>.summary.json`

Generate a 25-case synthetic fixture set:

```bash
/opt/anaconda3/bin/python scripts/generate_ai_mock_fixtures.py \
  --out /tmp/aegis_ai_findings_25
```

Evaluate raw results:

```bash
/opt/anaconda3/bin/python scripts/evaluate_ai_results.py \
  --raw benchmarks/ai_experiments/results/E3-workflow-ablation-mock.jsonl \
  --out benchmarks/ai_experiments/results/E3-workflow-ablation-mock.evaluation.json
```

Optional real Gemini smoke test:

```bash
GEMINI_API_KEY=... /opt/anaconda3/bin/python scripts/smoke_gemini_structured.py
```

Optional real Groq smoke test:

```bash
export GROQ_API_KEY="gsk_..."
export GROQ_MODEL="llama-3.1-8b-instant"
/opt/anaconda3/bin/python scripts/smoke_groq_structured.py
```

## Remaining External Dependencies

The following cannot be completed truthfully without external inputs:

- 25-35 labeled findings from Quân. A synthetic 25-case generator is available until that dataset arrives.
- Real Groq or Gemini API smoke run with a configured API key.
- Real E1/E2/E3 metrics on a stable benchmark dataset.
- Final thesis charts based on real raw results.

The code paths are present so those inputs can be plugged in without changing the AI contract.

"""Optional real Groq structured-output smoke test."""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis_sast.ai.fixtures import load_ai_fixture_directory
from aegis_sast.ai.groq_client import DEFAULT_GROQ_MODEL, StructuredGroqClient
from aegis_sast.ai.prompts import get_judge_structured_prompt
from aegis_sast.ai.schemas import StructuredAIRequest


def main() -> None:
    if not os.getenv("GROQ_API_KEY"):
        print("Skipping real Groq smoke test: GROQ_API_KEY is not set.")
        return

    model_name = os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL)
    fixture = load_ai_fixture_directory(ROOT / "tests" / "fixtures" / "ai_findings" / "python")[0]
    prompt = get_judge_structured_prompt(fixture, ["planner", "auditor", "judge"])
    request = StructuredAIRequest(
        node_name="judge",
        model_name=model_name,
        prompt=prompt,
        response_schema_name="TriageDecision",
    )
    result = StructuredGroqClient(model_name=model_name).generate_triage_decision(
        request=request,
        fallback_finding_id=fixture.finding.finding_id,
    )
    print(json.dumps(result.parsed.to_dict(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

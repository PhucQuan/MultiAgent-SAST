"""Optional real Gemini structured-output smoke test."""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis_sast.ai.fixtures import load_ai_fixture_directory
from aegis_sast.ai.gemini_client import StructuredGeminiClient
from aegis_sast.ai.prompts import get_judge_structured_prompt
from aegis_sast.ai.schemas import StructuredAIRequest


def main() -> None:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("Skipping real Gemini smoke test: GEMINI_API_KEY/GOOGLE_API_KEY is not set.")
        return

    try:
        from google import genai
        from google.genai import types
    except ImportError:
        print("Skipping real Gemini smoke test: google-genai is not installed.")
        return

    model_name = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    fixture = load_ai_fixture_directory(ROOT / "tests" / "fixtures" / "ai_findings" / "python")[0]
    prompt = get_judge_structured_prompt(fixture, ["planner", "auditor", "judge"])
    client = genai.Client(api_key=api_key)

    def transport(request: StructuredAIRequest) -> str:
        response = client.models.generate_content(
            model=model_name,
            contents=request.prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
            ),
        )
        return response.text

    result = StructuredGeminiClient(
        model_name=model_name,
        transport=transport,
    ).generate_triage_decision(
        request=StructuredAIRequest(
            node_name="judge",
            model_name=model_name,
            prompt=prompt,
            response_schema_name="TriageDecision",
        ),
        fallback_finding_id=fixture.finding.finding_id,
    )
    print(json.dumps(result.parsed.to_dict(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

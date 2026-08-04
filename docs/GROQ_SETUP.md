# Groq Setup

The AI triage layer supports Groq through its OpenAI-compatible chat completions API.

## 1. Add API Key

In the terminal:

```bash
export GROQ_API_KEY="gsk_your_key_here"
```

Optional model override:

```bash
export GROQ_MODEL="llama-3.1-8b-instant"
```

If `GROQ_MODEL` is not set, the code defaults to `llama-3.1-8b-instant`.

## 2. Run Local Tests

These tests do not call Groq:

```bash
/opt/anaconda3/bin/python -m pytest tests/test_groq_client.py
```

## 3. Run Real Groq Smoke Test

This calls Groq using the first Python AI fixture:

```bash
/opt/anaconda3/bin/python scripts/smoke_groq_structured.py
```

Expected behavior:

- If `GROQ_API_KEY` is missing, the script prints a skip message.
- If the key is set, the script prints a validated `TriageDecision` JSON object.

## 4. Provider Details

- Base URL: `https://api.groq.com/openai/v1`
- Endpoint: `/chat/completions`
- Auth header: `Authorization: Bearer $GROQ_API_KEY`
- Response mode: JSON object via `response_format={"type": "json_object"}`

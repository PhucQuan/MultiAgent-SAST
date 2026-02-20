import os
from dotenv import load_dotenv
from google import genai
from google.genai.errors import APIError

load_dotenv()

key = os.environ.get("GEMINI_API_KEY")
print(f"Key loaded: {bool(key)}")

if key:
    client = genai.Client(api_key=key)
    try:
        print("Sending request to Gemini-1.5-flash...")
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents="Hello! Are you working?"
        )
        print("Response:", response.text)
    except APIError as e:
        print(f"APIError caught: {e.code} - {e.message}")
    except Exception as e:
        print(f"Unknown Exception: {type(e).__name__} - {e}")

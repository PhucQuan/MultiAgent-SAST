import os
from dotenv import load_dotenv
from google import genai

load_dotenv()
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

print("Available models:")
for model in client.models.list():
    if "flash" in model.name:
        print(model.name)

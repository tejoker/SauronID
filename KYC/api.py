import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

# Initialize the client with AI Studio API key
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Loop through and print the available model names
for model in client.models.list():
    print(model.name)
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# === API Keys ===
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENCTI_API_KEY = os.getenv("OPENCTI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# === URLs ===
OPENCTI_BASE_URL = os.getenv("OPENCTI_BASE_URL")

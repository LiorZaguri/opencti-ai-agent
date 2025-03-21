import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# === Logger ===
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# === API Keys ===
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_MODEL = os.getenv("OPENAI_BASE_MODEL")

# === OpenCTI ===
OPENCTI_API_KEY = os.getenv("OPENCTI_API_KEY")
OPENCTI_BASE_URL = os.getenv("OPENCTI_BASE_URL")

# === Enrichments ===
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

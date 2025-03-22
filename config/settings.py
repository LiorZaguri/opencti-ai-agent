import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# === Logger ===
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# === API Keys ===
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_MODEL = os.getenv("OPENAI_BASE_MODEL")

# Token Usage Limits
AGENT_DEFAULT_TOKEN_LIMIT = int(os.getenv("AGENT_DEFAULT_TOKEN_LIMIT", "10000"))
SYSTEM_DAILY_TOKEN_LIMIT = int(os.getenv("SYSTEM_DAILY_TOKEN_LIMIT", "100000"))

# === OpenCTI ===
OPENCTI_API_KEY = os.getenv("OPENCTI_API_KEY")
OPENCTI_BASE_URL = os.getenv("OPENCTI_BASE_URL")

# === Enrichments ===
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not OPENCTI_API_KEY or not OPENCTI_BASE_URL:
    raise ValueError("OpenCTI configuration is incomplete")

if not OPENAI_API_KEY:
    raise ValueError("OpenAI API key is required")
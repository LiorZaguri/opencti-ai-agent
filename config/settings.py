import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# === LLM ===
LLM_API_KEY = os.getenv("LLM_API_KEY")
LLM_API_URL = os.getenv("LLM_API_URL", "https://api.openai.com")
LLM_BASE_MODEL = os.getenv("LLM_BASE_MODEL")

if not LLM_BASE_MODEL or not LLM_API_KEY:
    raise ValueError("LLM configuration is required")

# === OpenCTI ===
OPENCTI_API_KEY = os.getenv("OPENCTI_API_KEY")
OPENCTI_BASE_URL = os.getenv("OPENCTI_BASE_URL")

if not OPENCTI_API_KEY or not OPENCTI_BASE_URL:
    raise ValueError("OpenCTI configuration is incomplete")

# Token Usage Limits
AGENT_DEFAULT_TOKEN_LIMIT = int(os.getenv("AGENT_DEFAULT_TOKEN_LIMIT", "10000"))
SYSTEM_DAILY_TOKEN_LIMIT = int(os.getenv("SYSTEM_DAILY_TOKEN_LIMIT", "100000"))

# === Logger ===
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# === Enrichments ===
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
from config.settings import LLM_API_KEY, LLM_BASE_MODEL, LLM_API_URL
from autogen import LLMConfig

# Create a standard LLMConfig for the agents
default_llm_config = LLMConfig(
    api_type="openai",
    model=LLM_BASE_MODEL,
    api_key=LLM_API_KEY,
    base_url=LLM_API_URL,
    temperature=0.2,
)

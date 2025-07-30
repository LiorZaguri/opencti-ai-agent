from config.settings import LLM_API_KEY, LLM_BASE_MODEL, LLM_API_URL
from autogen import LLMConfig

# Create a standard LLMConfig for the agents
default_llm_config = LLMConfig(
    api_type="openai",
    model=LLM_BASE_MODEL,
    api_key="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",
    base_url=LLM_API_URL,
    temperature=0.2,
)

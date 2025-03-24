from config.settings import LLM_API_KEY, LLM_BASE_MODEL, LLM_API_URL

default_config_list = [
    {
        "model": LLM_BASE_MODEL,
        "api_key": LLM_API_KEY,
        "base_url": LLM_API_URL,
        "api_type": "openai",
    }
]

default_llm_config = {
    "temperature": 0.2,
    "max_tokens": 1024,
    "config_list": default_config_list,
    "seed": 42,
}

from config.settings import OPENAI_API_KEY, OPENAI_BASE_MODEL

default_config_list = [
    {
        "model": OPENAI_BASE_MODEL,
        "api_key": OPENAI_API_KEY
    }
]

default_llm_config = {
    "temperature": 0.2,
    "max_tokens": 1024,
    "config_list": default_config_list,
    "seed": 42,
}

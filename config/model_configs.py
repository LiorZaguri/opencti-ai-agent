from config.settings import OPENAI_API_KEY

default_config_list = [
    {
        "model": "gpt-3.5-turbo",
        "api_key": OPENAI_API_KEY,
    }
]

default_llm_config = {
    "temperature": 0.2,
    "max_tokens": 1024,
    "config_list": default_config_list,
    "seed": 42,
    "top_p": 1.0,
    "presence_penalty": 0.0,
    "frequency_penalty": 0.0
}

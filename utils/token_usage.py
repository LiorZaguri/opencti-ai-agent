from typing import Dict
import os
import tiktoken

from config.settings import AGENT_DEFAULT_TOKEN_LIMIT, SYSTEM_DAILY_TOKEN_LIMIT
from utils.logger import setup_logger

logger = setup_logger(name="token_usage", component_type="token_usage")


class TokenUsage:
    """
    Singleton class to track and enforce token usage per agent and system-wide,
    with support for per-agent custom limits via environment variables.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TokenUsage, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.usage: Dict[str, Dict[str, int]] = {}

    def log_tokens(self, agent_name: str, input_tokens: int, output_tokens: int):
        total_new = input_tokens + output_tokens

        # Enforce per-agent limit
        agent_total = self.get_usage(agent_name)["total"] + total_new
        agent_limit = self.get_agent_limit(agent_name)

        if agent_total > agent_limit:
            raise Exception(f"Token limit exceeded for agent '{agent_name}' ({agent_total}/{agent_limit})")

        # Enforce system-wide limit
        system_total = self.get_total_usage()["total"] + total_new
        if system_total > SYSTEM_DAILY_TOKEN_LIMIT:
            raise Exception(f"System-wide token limit exceeded ({system_total}/{SYSTEM_DAILY_TOKEN_LIMIT})")

        # Warnings at 80%
        if agent_total >= 0.8 * agent_limit:
            logger.warning(f"[{agent_name}] Nearing agent token limit ({agent_total}/{agent_limit})")
        if system_total >= 0.8 * SYSTEM_DAILY_TOKEN_LIMIT:
            logger.warning(f"[System] Nearing daily token limit ({system_total}/{SYSTEM_DAILY_TOKEN_LIMIT})")

        # Track usage
        if agent_name not in self.usage:
            self.usage[agent_name] = {"input": 0, "output": 0, "total": 0}
        self.usage[agent_name]["input"] += input_tokens
        self.usage[agent_name]["output"] += output_tokens
        self.usage[agent_name]["total"] += total_new

        logger.info(f"[{agent_name}] Token usage - Input: {input_tokens}, Output: {output_tokens}, Total: {total_new}")

    def get_usage(self, agent_name: str) -> Dict[str, int]:
        return self.usage.get(agent_name, {"input": 0, "output": 0, "total": 0})

    def get_total_usage(self) -> Dict[str, int]:
        total_input = sum(agent["input"] for agent in self.usage.values())
        total_output = sum(agent["output"] for agent in self.usage.values())
        return {
            "input": total_input,
            "output": total_output,
            "total": total_input + total_output
        }

    def estimate_tokens(self, text: str, model: str = "gpt-3.5-turbo") -> int:
        try:
            encoding = tiktoken.encoding_for_model(model)
            token_count = len(encoding.encode(text))
            logger.debug(f"Estimated {token_count} tokens for model '{model}'")
            return token_count
        except Exception as e:
            logger.warning(f"Token estimation failed for model '{model}': {e}")
            return len(text.split())

    def get_agent_limit(self, agent_name: str) -> int:
        env_key = f"AGENT_{agent_name.upper()}_LIMIT"
        return int(os.getenv(env_key, AGENT_DEFAULT_TOKEN_LIMIT))

    def reset(self):
        self.usage.clear()
        logger.info("Token usage statistics reset.")

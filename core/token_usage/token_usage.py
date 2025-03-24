import os
import threading
from typing import Dict, Any, Optional
from datetime import datetime

from config.settings import AGENT_DEFAULT_TOKEN_LIMIT, SYSTEM_DAILY_TOKEN_LIMIT
from core.utils.logger import setup_logger

from .models import TokenStats
from .storage import TokenUsageStorage
from .estimator import TokenEstimator
from .validators import validate_agent_name, validate_token_counts

logger = setup_logger(name="token_usage", component_type="token_usage")

def get_agent_limit(agent_name: str) -> int:
    """Get token limit for an agent, with input validation"""
    if not agent_name or not isinstance(agent_name, str):
        logger.warning(f"Invalid agent name: {agent_name}, using default token limit")
        return AGENT_DEFAULT_TOKEN_LIMIT
        
    env_var = f"{agent_name.upper()}_TOKEN_LIMIT"
    limit_str = os.getenv(env_var, str(AGENT_DEFAULT_TOKEN_LIMIT))
    
    try:
        limit = int(limit_str)
        if limit <= 0:
            logger.warning(f"Invalid token limit ({limit}) for agent '{agent_name}', using default")
            return AGENT_DEFAULT_TOKEN_LIMIT
        return limit
    except (ValueError, TypeError):
        logger.warning(f"Invalid token limit format for agent '{agent_name}', using default")
        return AGENT_DEFAULT_TOKEN_LIMIT

class TokenUsage:
    _instance: Optional['TokenUsage'] = None
    _lock = threading.RLock()  # Reentrant lock for thread safety

    def __new__(cls) -> 'TokenUsage':
        if cls._instance is None:
            cls._instance = super(TokenUsage, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    @classmethod
    def reset_for_testing(cls) -> None:
        """Reset the singleton instance (for testing only)"""
        cls._instance = None

    def _init(self) -> None:
        """Initialize or reset the instance state"""
        self.usage: Dict[str, TokenStats] = {}
        self.storage = TokenUsageStorage(os.getenv("TOKEN_USAGE_PATH", "data/token_usage.json"))
        self.estimator = TokenEstimator()
        self._load_usage()

    def log_tokens_from_openrouter(self, agent_name: str, response: Dict[str, Any]) -> None:
        """Log tokens from an OpenRouter API response"""
        if not validate_agent_name(agent_name):
            return
            
        try:
            if not isinstance(response, dict):
                raise TypeError(f"Expected dict response, got {type(response)}")
                
            usage = response.get("usage", {})
            if not isinstance(usage, dict):
                raise TypeError(f"Expected dict for usage, got {type(usage)}")
                
            # Check for required fields
            if "prompt_tokens" not in usage or "completion_tokens" not in usage:
                raise KeyError("Missing token fields in response usage data")
                
            input_tokens = usage.get("prompt_tokens", 0)
            output_tokens = usage.get("completion_tokens", 0)
            
            if not isinstance(input_tokens, (int, float)) or not isinstance(output_tokens, (int, float)):
                raise TypeError("Token counts must be numeric")
                
            self.log_tokens(agent_name, int(input_tokens), int(output_tokens))
            
        except (KeyError, TypeError, ValueError) as e:
            logger.error(f"Malformed OpenRouter response: {e}")
            logger.debug(f"Response structure: {response}")
            # Continue with best-effort tracking
            self.log_tokens(agent_name, 0, 0)

    def log_tokens(self, agent_name: str, input_tokens: int, output_tokens: int) -> None:
        """Log token usage for an agent"""
        if not validate_agent_name(agent_name):
            return
            
        with self._lock:
            try:
                # Validate and normalize token counts
                input_tokens, output_tokens = validate_token_counts(input_tokens, output_tokens)
                total_new = input_tokens + output_tokens

                # Prune expired usage (older than 24 hours)
                self._prune_expired_usage()

                # Enforce per-agent limit
                agent_total = self.get_usage(agent_name)["total"] + total_new
                agent_limit = get_agent_limit(agent_name)

                if agent_total > agent_limit:
                    logger.error(f"Token limit exceeded for agent '{agent_name}' ({agent_total}/{agent_limit})")
                    raise Exception(f"Token limit exceeded for agent '{agent_name}' ({agent_total}/{agent_limit})")

                # Enforce system-wide limit
                system_total = self.get_total_usage()["total"] + total_new
                if system_total > SYSTEM_DAILY_TOKEN_LIMIT:
                    logger.error(f"System-wide token limit exceeded ({system_total}/{SYSTEM_DAILY_TOKEN_LIMIT})")
                    raise Exception(f"System-wide token limit exceeded ({system_total}/{SYSTEM_DAILY_TOKEN_LIMIT})")

                # Warnings at 80%
                if agent_total >= 0.8 * agent_limit:
                    logger.warning(f"[{agent_name}] Nearing agent token limit ({agent_total}/{agent_limit})")
                if system_total >= 0.8 * SYSTEM_DAILY_TOKEN_LIMIT:
                    logger.warning(f"[System] Nearing daily token limit ({system_total}/{SYSTEM_DAILY_TOKEN_LIMIT})")

                # Track usage
                now = datetime.now().isoformat()
                if agent_name not in self.usage:
                    self.usage[agent_name] = {"input": 0, "output": 0, "total": 0, "last_updated": now}

                self.usage[agent_name]["input"] += input_tokens
                self.usage[agent_name]["output"] += output_tokens
                self.usage[agent_name]["total"] += total_new
                self.usage[agent_name]["last_updated"] = now

                logger.info(f"[{agent_name}] Tokens logged - Input: {input_tokens}, Output: {output_tokens}, Total: {total_new}")
                
                # Persist usage to disk
                self._save_usage()
                
            except Exception as e:
                # Only catch and log non-limit related exceptions
                if "Token limit exceeded" not in str(e):
                    logger.error(f"Error in log_tokens: {e}")
                raise

    def get_usage(self, agent_name: str) -> TokenStats:
        """Get token usage for a specific agent"""
        if not validate_agent_name(agent_name):
            now = datetime.now().isoformat()
            return {"input": 0, "output": 0, "total": 0, "last_updated": now}
            
        with self._lock:
            if agent_name not in self.usage:
                now = datetime.now().isoformat()
                return {"input": 0, "output": 0, "total": 0, "last_updated": now}
            return self.usage[agent_name]

    def get_total_usage(self) -> TokenStats:
        """Get total token usage across all agents within the rolling window"""
        with self._lock:
            try:
                self._prune_expired_usage()
                total_input = sum(agent["input"] for agent in self.usage.values())
                total_output = sum(agent["output"] for agent in self.usage.values())
                now = datetime.now().isoformat()
                return {
                    "input": total_input,
                    "output": total_output,
                    "total": total_input + total_output,
                    "last_updated": now
                }
            except Exception as e:
                logger.error(f"Error in get_total_usage: {e}")
                now = datetime.now().isoformat()
                return {"input": 0, "output": 0, "total": 0, "last_updated": now}

    def estimate_tokens(self, text: str, model: str = "gpt-3.5-turbo") -> int:
        """Estimate token count for text using tiktoken"""
        return self.estimator.estimate(text, model)

    def reset_daily_usage(self) -> None:
        """Reset all usage data (for testing)"""
        with self._lock:
            self.usage.clear()
            self._save_usage()

    def _prune_expired_usage(self) -> None:
        """Remove usage data older than 24 hours"""
        with self._lock:
            self.usage = self.storage.prune_expired(self.usage)
            self._save_usage()

    def _save_usage(self) -> None:
        """Save current usage to disk"""
        with self._lock:
            self.storage.save(self.usage)

    def _load_usage(self) -> None:
        """Load usage data from disk"""
        with self._lock:
            self.usage = self.storage.load()
            self._prune_expired_usage() 
import os
import json
from autogen import ConversableAgent
from config.model_configs import default_config_list, default_llm_config
from typing import Any, Dict
from utils.logger import setup_logger
from memory.cache_manager import get_agent_cache
from abc import ABC, abstractmethod

logger = setup_logger(name="base_agent", component_type="agents")

def load_company_profile():
    path = os.path.join("data", "company_profile.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


class BaseAgent(ConversableAgent, ABC):
    """
    Base class for all AI agents. Uses default LLM config unless overridden.
    Integrates logging and caching for efficiency.
    """
    def __init__(
            self,
            name: str,
            system_message: str = "",
            config_list: list = None,
            llm_config: Dict[str, Any] = None,
            use_cache: bool = True,
            **kwargs
        ):

        self.use_cache = use_cache
        self._cache = get_agent_cache(name) if use_cache else None
        self.company_profile = load_company_profile()
        if not system_message:
            system_message = self.generate_default_system_prompt()

        # Prepare configuration
        llm_config = llm_config or default_llm_config.copy()

        # Add config_list to llm_config
        if config_list:
            llm_config['config_list'] = config_list
        elif 'config_list' not in llm_config and default_config_list:
            llm_config['config_list'] = default_config_list

        super().__init__(
            name=name,
            system_message=system_message,
            llm_config=llm_config,
            **kwargs
        )
        logger.info(f"Initialized agent: {name} (cache enabled: {use_cache})")

    def execute_task(self, task: str, context=None) -> str:
        """Execute a task with caching support"""
        if context is None:
            context = {}
        logger.info("-" * 60)
        logger.info(f"[{self.name}] Running task: {task}")

        # Check cache first if enabled
        if self.use_cache and self._cache.has(task, self.name):
            result = self._cache.get(task, self.name)
            logger.debug(f"[{self.name}] Cache hit for task: {task}")
            return result

        # Execute task and cache the result
        logger.debug(f"[{self.name}] Cache miss, executing task: {task}")
        result = self.handle_task(task, context)

        # Cache the result if caching is enabled
        if self.use_cache:
            self._cache.save(task, self.name, result)
            logger.debug(f"[{self.name}] Cached result for task: {task}")

        return result

    @abstractmethod
    def handle_task(self, task: str, context: Dict[str, Any]) -> str:
        """
        Process a specific task and return the result.
        Must be implemented by subclasses.
        """
        pass

    def generate_default_system_prompt(self):
        profile = self.company_profile
        industry = profile.get("industry", "unknown sector")
        region = profile.get("region", "global")
        return f"You are an AI agent specialized in threats for the {industry} industry, operating in the {region} region. Act accordingly."


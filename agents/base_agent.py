from autogen import ConversableAgent
from config.model_configs import default_config_list, default_llm_config
from typing import Any, Dict
from utils.logger import setup_logger
from memory.cache_manager import get_agent_cache
from abc import ABC, abstractmethod

logger = setup_logger(name="base_agent", component_type="agents")

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
        # Prepare configuration
        llm_config = llm_config or default_llm_config.copy()

        # Remove unsupported parameters if they exist
        unsupported_params = ['top_p', 'presence_penalty', 'frequency_penalty']
        for param in unsupported_params:
            if param in llm_config:
                llm_config.pop(param)

        # Add config_list to llm_config
        if config_list:
            llm_config['config_list'] = config_list
        elif 'config_list' not in llm_config and default_config_list:
            llm_config['config_list'] = default_config_list

        super().__init__(
            name=name,
            system_message=system_message or f"I am agent {name}.",
            llm_config=llm_config,
            **kwargs
        )

        self.use_cache = use_cache
        self._cache = get_agent_cache(name) if use_cache else None
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
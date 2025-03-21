from autogen import ConversableAgent
from config.model_configs import default_config_list, default_llm_config
from typing import Any, Dict

class BaseAgent(ConversableAgent):
    """
    Base class for all AI agents. Uses default LLM config unless overridden.
    """

    def __init__(
        self,
        name: str,
        system_message: str = "",
        config_list: list = None,
        llm_config: Dict[str, Any] = None,
        **kwargs
    ):
        config_list = config_list or default_config_list
        llm_config = llm_config or default_llm_config

        super().__init__(
            name=name,
            system_message=system_message or f"I am agent {name}.",
            config_list=config_list,
            llm_config=llm_config,
            **kwargs
        )

    def run(self, task: str, context: Dict[str, Any] = {}) -> str:
        print(f"[{self.name}] Running task: {task}")
        return self.handle_task(task, context)

    def handle_task(self, task: str, context: Dict[str, Any]) -> str:
        raise NotImplementedError("handle_task must be implemented by the subclass.")

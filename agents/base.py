import os
import sys
from typing import Callable, Dict, Any, List, Optional, Set

# Add the project root directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Imports derived strictly from agent definitions in .md examples
from autogen import ConversableAgent, LLMConfig

# Local imports needed for functionality
from config.model_configs import default_llm_config
from agents.tools import get_tool_function

# Imports needed for the run method, using primitives from .md files
from autogen import UserProxyAgent
from autogen.agentchat import initiate_group_chat
from autogen.agentchat.group.patterns import DefaultPattern

class BaseAgent:
    """
    Base class for agents, derived from patterns in example.md and tools_agent_example.md.
    Provides common functionality for initializing and interacting with an AutoGen ConversableAgent.
    Strictly uses components shown in the markdown examples.
    """

    def __init__(
        self,
        name: str,
        system_message: str,
        llm_config: Optional[LLMConfig] = None,
        tools: Optional[List[str]] = None,
        human_input_mode: str = "NEVER"
    ):
        """
        Initializes a new BaseAgent instance based on markdown examples.

        Args:
            name: The name of the agent.
            system_message: The system message defining the agent's role and instructions.
            llm_config: Configuration for the language model (AutoGen LLMConfig object).
                       Defaults to the configuration loaded from config.model_configs.
            tools: Optional list of tool function names to register with the agent.
                   These tools must be defined in the `agents.tools` package.
            human_input_mode: Mode for human input ("NEVER", "ALWAYS", "TERMINATE").
        """
        self.name = name
        self.system_message = system_message
        self.llm_config: LLMConfig = llm_config or default_llm_config
        self.human_input_mode = human_input_mode
        self.agent: Optional[ConversableAgent] = None
        self.registered_tools: Set[str] = set()
        self.tool_functions: Dict[str, Callable] = {}

        if tools:
            for tool_name in tools:
                self.register_tool(tool_name)

        self._initialize_agent()

    def _initialize_agent(self):
        """
        Initializes or re-initializes the internal ConversableAgent
        based on the current configuration and registered tools.
        Passes llm_config directly as shown in tools_agent_example.md.
        """
        functions = [func for func in self.tool_functions.values()]
        self.agent = ConversableAgent(
            name=self.name,
            system_message=self.system_message,
            llm_config=self.llm_config,
            functions=functions if functions else None,
            human_input_mode=self.human_input_mode,
        )

    def register_tool(self, tool_name: str) -> bool:
        """
        Registers a tool (function) with the agent by its name.
        Retrieves the function using `get_tool_function`.
        Args:
            tool_name: Name of the tool function (must exist in agents.tools).
        Returns:
            True if successful, False otherwise.
        """
        if tool_name in self.registered_tools:
            return True
        tool_function = get_tool_function(tool_name)
        if not tool_function:
            print(f"Error: Tool function '{tool_name}' not found.")
            return False
        self.registered_tools.add(tool_name)
        self.tool_functions[tool_name] = tool_function
        if self.agent:
            self._initialize_agent()
        return True

    def unregister_tool(self, tool_name: str) -> bool:
        """
        Unregisters a tool from the agent.
        Args:
            tool_name: Name of the tool to unregister.
        Returns:
            True if successful, False otherwise.
        """
        if tool_name not in self.registered_tools:
            return False
        self.registered_tools.remove(tool_name)
        if tool_name in self.tool_functions:
            del self.tool_functions[tool_name]
        if self.agent:
            self._initialize_agent()
        return True

    def run(self, prompt: str) -> str:
        """
        Runs a prompt through the agent and returns the final text reply.
        Uses initiate_group_chat with a DefaultPattern, mirroring .md examples.

        Args:
            prompt: The input prompt/message for the agent.

        Returns:
            The agent's final text response.
        """
        if not self.agent:
            return "Error: Agent not initialized."

        # Create a temporary UserProxyAgent to initiate the group chat
        # This agent represents the user sending the prompt.
        temp_user_proxy = UserProxyAgent(
            name="temp_runner_proxy", # Distinct name
            human_input_mode="NEVER",
            max_consecutive_auto_reply=0,
            code_execution_config=False,
            llm_config=False # No LLM needed for this proxy
        )

        # Use DefaultPattern, adapting the multi-agent example for 1-on-1 interaction
        pattern = DefaultPattern(
            # The agent that receives the initial message from the user_agent
            initial_agent=self.agent,
            # List only the worker agents
            agents=[self.agent],
            # The agent representing the user sending the prompt
            user_agent=temp_user_proxy
        )

        # Use initiate_group_chat, the function shown in the .md files
        # IMPORTANT: Unpack the tuple returned by initiate_group_chat
        chat_result_tuple = initiate_group_chat(
            pattern=pattern,
            messages=prompt, # The initial message from the user
            max_rounds=5 # Increase rounds to allow for tool execution cycle
        )

        # The actual result object is the first element of the tuple
        chat_result_obj = chat_result_tuple[0]

        # Extract the last message from the target agent using the result object
        if chat_result_obj and chat_result_obj.chat_history:
            # Search backwards for the last message from our BaseAgent
            for msg in reversed(chat_result_obj.chat_history):
                if msg.get('name') == self.name or msg.get('role') == 'assistant':
                    return msg.get('content', 'Error: Could not extract final reply content.')
            # If no message from the target agent is found (e.g., only proxy message)
            return "Error: Agent did not provide a reply in the allowed turns."
        else:
            return "Error: Chat failed or produced no reply history."

    def get_registered_tools(self) -> Set[str]:
        """
        Returns the set of names of currently registered tools.
        """
        return self.registered_tools

    @property
    def conversable_agent(self) -> Optional[ConversableAgent]:
        """Provides access to the underlying AutoGen ConversableAgent instance."""
        return self.agent

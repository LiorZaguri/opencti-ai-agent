import os
import sys
from typing import Callable, Dict, Any, List, Optional, Set

# Add the project root directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from autogen import (
    ConversableAgent,
    UpdateSystemMessage
)
from config.model_configs import default_llm_config
from agents.tools import get_tool_function, get_tool_description, get_tool_parameters

class BaseAgent:
    """
    Base class for all agents in the CTI AI Agent system.
    This class provides common functionality and can be extended to create specialized agents.
    """

    def __init__(
        self,
        name: str,
        system_message: str,
        llm_config: Optional[Dict[str, Any]] = None,
        update_function: Optional[Callable] = None,
        human_input_mode: str = "NEVER",
        tools: Optional[List[str]] = None
    ):
        """
        Initialize a new agent.

        Args:
            name: The name of the agent
            system_message: The system message that defines the agent's role and capabilities
            llm_config: Configuration for the language model
            update_function: Function to call when updating the agent's state
            human_input_mode: Mode for human input ("NEVER", "ALWAYS", or "TERMINATE")
            tools: List of tool names to register with the agent
        """
        self.name = name
        self.system_message = system_message
        self.llm_config = llm_config or default_llm_config
        self.update_function = update_function
        self.human_input_mode = human_input_mode
        self.agent = None
        self.registered_tools = set()
        self.tool_functions = {}
        self.tool_descriptions = {}
        self.tool_parameters = {}

        # Register tools if provided
        if tools:
            for tool_name in tools:
                self.register_tool(tool_name)

        # Initialize the agent
        self._initialize_agent()

    def _initialize_agent(self):
        """Initialize the ConversableAgent with the provided configuration."""
        # Create a state update function if an update function is provided
        state_update = None
        if self.update_function:
            state_update = UpdateSystemMessage(self._update_system_message)

        # Prepare functions for the agent
        functions = []
        if self.update_function:
            functions.append(self.update_function)

        # Add tool functions to the functions list
        for func in self.tool_functions.values():
            functions.append(func)

        # Format tool functions for the LLM config
        if self.tool_functions and "tools" not in self.llm_config:
            self.llm_config["tools"] = []

        # Add tool definitions to LLM config
        for tool_name, func in self.tool_functions.items():
            # Create function definition
            formatted_func = {
                "name": tool_name,
                "description": self.tool_descriptions.get(tool_name, ""),
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }

            # Add parameters
            params = self.tool_parameters.get(tool_name, {})
            for param_name, param_info in params.items():
                formatted_func["parameters"]["properties"][param_name] = {
                    "type": param_info.get("type", "string"),
                    "description": param_info.get("description", "")
                }
                if param_info.get("required", False):
                    formatted_func["parameters"]["required"].append(param_name)

            # Add to tools list
            self.llm_config["tools"].append({"type": "function", "function": formatted_func})

        # Create the agent
        self.agent = ConversableAgent(
            name=self.name,
            system_message=self.system_message,
            llm_config=self.llm_config,
            functions=functions if functions else None,
            update_agent_state_before_reply=[state_update] if state_update else None,
            human_input_mode=self.human_input_mode
        )

    def _update_system_message(self, _agent: ConversableAgent, _messages) -> str:
        """
        Update the system message based on the current context.
        This method can be overridden by subclasses to provide custom behavior.

        Args:
            _agent: The agent instance (unused in base implementation)
            _messages: The current message history (unused in base implementation)

        Returns:
            The updated system message
        """
        # Default implementation just returns the original system message
        # Subclasses can override this to provide dynamic system messages
        return self.system_message

    def register_tool(self, tool_name: str) -> bool:
        """
        Register a tool with the agent.

        Args:
            tool_name: Name of the tool to register

        Returns:
            True if the tool was registered successfully, False otherwise
        """
        if tool_name in self.registered_tools:
            return True  # Already registered

        tool_function = get_tool_function(tool_name)
        if not tool_function:
            return False  # Tool not found

        # Get tool description and parameters
        tool_description = get_tool_description(tool_name)
        tool_parameters = get_tool_parameters(tool_name)

        # Add to registered tools set
        self.registered_tools.add(tool_name)

        # Store the function and metadata
        self.tool_functions[tool_name] = tool_function
        self.tool_descriptions[tool_name] = tool_description
        self.tool_parameters[tool_name] = tool_parameters

        # Reinitialize the agent if already initialized
        if self.agent:
            self._initialize_agent()

        return True

    def unregister_tool(self, tool_name: str) -> bool:
        """
        Unregister a tool from the agent.

        Args:
            tool_name: Name of the tool to unregister

        Returns:
            True if the tool was unregistered successfully, False otherwise
        """
        if tool_name not in self.registered_tools:
            return False  # Not registered

        # Remove from registered tools set
        self.registered_tools.remove(tool_name)

        # Remove the function and metadata
        if tool_name in self.tool_functions:
            del self.tool_functions[tool_name]
        if tool_name in self.tool_descriptions:
            del self.tool_descriptions[tool_name]
        if tool_name in self.tool_parameters:
            del self.tool_parameters[tool_name]

        # Reinitialize the agent
        if self.agent:
            self._initialize_agent()

        return True

    def get_registered_tools(self) -> Set[str]:
        """
        Get the names of all tools registered with the agent.

        Returns:
            Set of tool names
        """
        return self.registered_tools

    def has_tool(self, tool_name: str) -> bool:
        """
        Check if the agent has a specific tool registered.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if the tool is registered, False otherwise
        """
        return tool_name in self.registered_tools

    @property
    def conversable_agent(self) -> ConversableAgent:
        """Get the underlying ConversableAgent instance."""
        return self.agent

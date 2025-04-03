from autogen import ConversableAgent
from config.model_configs import default_config_list, default_llm_config
from typing import Any, Dict, List, Optional, Union
from core.utils.logger import setup_logger
from core.memory import get_agent_cache
from core.token_usage.token_usage import TokenUsage, get_agent_limit
from abc import ABC, abstractmethod
from core.utils.company_profile import load_company_profile
import asyncio

logger = setup_logger(name="base_agent", component_type="agents")
token_tracker = TokenUsage()

class BaseAgent(ConversableAgent, ABC):
    """
    Base class for all AI agents in the OpenCTI ecosystem. Uses default LLM config unless overridden.
    Integrates logging, caching, token usage tracking, and inter-agent communication.
    """

    # Class-level registry to enable agent discovery
    _registry = {}

    def __init__(
            self,
            name: str,
            system_message: str = "",
            config_list: list = None,
            llm_config: Dict[str, Any] = None,
            use_cache: bool = True,
            description: str = "",
            **kwargs
    ):
        self.use_cache = use_cache
        self._cache = get_agent_cache(name) if use_cache else None
        self.company_profile = {}  # Will be populated in async init
        self.description = description
        self._collaborators = {}
        
        if not system_message:
            system_message = self.generate_default_system_prompt()

        # Prepare configuration
        llm_config = llm_config or default_llm_config.copy()

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
        
        # Register the agent
        BaseAgent._registry[name] = self
        
        logger.info(f"Initialized agent: {name} with token limit: {get_agent_limit(self.name)} "
                    f"(cache: {use_cache})")

    async def async_init(self):
        """
        Async initialization method.
        
        Override this in derived classes for async initialization.
        Returns self for method chaining.
        """
        self.company_profile = load_company_profile()
        return self

    async def execute_task(self, task: Any, context=None) -> str:
        """Execute a task with caching and token tracking support"""
        if context is None:
            context = {}
        
        # --- Safely create log preview for task --- 
        log_task_preview = ""
        if isinstance(task, (str, bytes)):
            log_task_preview = str(task)[:100] + ("..." if len(str(task)) > 100 else "")
        elif isinstance(task, dict):
            try:
                import json
                log_task_preview = json.dumps(task)[:100] + "..."
            except TypeError:
                 log_task_preview = f"<dict with keys: {list(task.keys())[:5]}... >"
        else:
            log_task_preview = f"<{type(task).__name__}>"
        # --- End safe log preview --- 
        
        logger.info("-" * 60)
        # Use the safe preview without the format specifier
        logger.info(f"[{self.name}] Running task: {log_task_preview}")

        # Check cache (Need to handle non-string keys if task is not string)
        cache_key = task if isinstance(task, str) else repr(task) # Use repr for non-string cache keys
        if self.use_cache and self._cache.has(cache_key, self.name):
            result = self._cache.get(cache_key, self.name)
            logger.debug(f"[{self.name}] Cache hit for task key: {log_task_preview}")
            return result

        # Cache miss → handle the task
        logger.debug(f"[{self.name}] Cache miss, executing task: {log_task_preview}")
        result = await self.handle_task(task, context) # Pass original task

        # Track token usage estimate
        # Convert task to string representation for estimation
        task_str = str(task) if task is not None else ""
        result_str = str(result) if result is not None else ""
        
        try:
            prompt_tokens = token_tracker.estimate_tokens(task_str)
            result_tokens = token_tracker.estimate_tokens(result_str)
            token_tracker.log_tokens(self.name, prompt_tokens, result_tokens)
        except Exception as e:
            logger.error(f"[{self.name}] Error tracking tokens: {e}")

        # Save to cache using the same key logic
        if self.use_cache:
            self._cache.save(cache_key, self.name, result)
            logger.debug(f"[{self.name}] Cached result for task key: {log_task_preview}")
            
        return result

    @abstractmethod
    async def handle_task(self, task: Any, context: Dict[str, Any]) -> str:
        """
        Process a specific task and return the result.
        Must be implemented by subclasses.
        """
        pass

    def generate_default_system_prompt(self):
        profile = self.company_profile
        industry = profile.get("industry", "unknown sector")
        region = profile.get("region", "global")
        return (f"You are an AI agent specialized in threats for the {industry} industry, "
                f"operating in the {region} region. Act accordingly.")
    
    # Inter-agent communication methods
    async def send_message_to_agent(self, target_agent_name: str, message: Any, context: Dict[str, Any] = None) -> str:
        """Send a message to another agent and wait for a response"""
        if context is None:
            context = {}
            
        target_agent = self.get_agent(target_agent_name)
        if not target_agent:
            logger.error(f"[{self.name}] Failed to send message: Agent '{target_agent_name}' not found")
            return f"Error: Agent '{target_agent_name}' not found"
            
        # --- Safely create log preview --- 
        log_message_preview = ""
        if isinstance(message, (str, bytes)):
            log_message_preview = str(message)[:100] + "..."
        elif isinstance(message, dict):
            # Try to show keys or a short JSON representation for dicts
            try:
                import json
                log_message_preview = json.dumps(message)[:100] + "..."
            except TypeError:
                 log_message_preview = f"<dict with keys: {list(message.keys())[:5]}... >"
        else:
            # Fallback for other types
            log_message_preview = f"<{type(message).__name__}>"
        # --- End safe log preview --- 
        
        logger.info(f"[{self.name}] Sending message to [{target_agent_name}]: {log_message_preview}")
        
        # Add sender information to context
        context['sender'] = self.name
        context['message_type'] = 'inter_agent_communication'
        
        # Send task to target agent
        # The 'message' here is passed to the target agent's handle_task
        response = await target_agent.execute_task(message, context)
        
        # Safely log response preview
        log_response_preview = str(response)[:100] + "..." if isinstance(response, (str, bytes)) else f"<{type(response).__name__}>"
        logger.info(f"[{self.name}] Received response from [{target_agent_name}]: {log_response_preview}")
        
        return response
    
    async def broadcast_message(self, message: str, exclude: List[str] = None, context: Dict[str, Any] = None) -> Dict[str, str]:
        """Send a message to all registered agents except those in the exclude list"""
        if exclude is None:
            exclude = [self.name]  # Don't send to self by default
        else:
            exclude.append(self.name)  # Always add self to exclude list
            
        if context is None:
            context = {}
            
        context['sender'] = self.name
        context['message_type'] = 'broadcast'
        
        responses = {}
        tasks = []
        
        # Create tasks for sending messages to all agents except excluded ones
        for agent_name, agent in BaseAgent._registry.items():
            if agent_name not in exclude:
                tasks.append(agent.execute_task(message, context))
                
        # Wait for all responses
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, agent_name in enumerate([name for name in BaseAgent._registry if name not in exclude]):
                if isinstance(results[i], Exception):
                    responses[agent_name] = f"Error: {str(results[i])}"
                else:
                    responses[agent_name] = results[i]
                    
        return responses
    
    def register_collaborator(self, agent_name: str, role: str = "collaborator"):
        """Register an agent as a collaborator with a specific role"""
        if agent_name in BaseAgent._registry:
            self._collaborators[agent_name] = role
            logger.info(f"[{self.name}] Registered {agent_name} as {role}")
        else:
            logger.warning(f"[{self.name}] Failed to register collaborator: Agent '{agent_name}' not found")
    
    def get_collaborators(self) -> Dict[str, str]:
        """Get dictionary of registered collaborators and their roles"""
        return self._collaborators.copy()
    
    @classmethod
    def get_agent(cls, agent_name: str) -> Optional['BaseAgent']:
        """Get an agent by name from the registry"""
        return cls._registry.get(agent_name)
    
    @classmethod
    def get_all_agents(cls) -> Dict[str, 'BaseAgent']:
        """Get all registered agents"""
        return cls._registry.copy()
    
    async def collaborate(self, task: str, collaborator_names: List[str] = None, context: Dict[str, Any] = None) -> Dict[str, str]:
        """Collaborate with specific agents on a task"""
        if collaborator_names is None:
            collaborator_names = list(self._collaborators.keys())
            
        if context is None:
            context = {}
            
        context['collaboration_task'] = True
        context['initiator'] = self.name
        
        responses = {}
        for agent_name in collaborator_names:
            response = await self.send_message_to_agent(agent_name, task, context)
            responses[agent_name] = response
            
        return responses
    
    async def integrate_pycti(self, method_name: str, *args, **kwargs):
        """
        Integration point for pyCTI operations
        Override in derived classes that need to work with OpenCTI via pyCTI
        """
        logger.warning(f"[{self.name}] pyCTI integration not implemented for method: {method_name}")
        return None
# Agent Tools

This module provides tools that can be registered with agents to extend their capabilities.

## OpenCTI Tools

The OpenCTI tools provide access to data in the OpenCTI platform. These tools can be registered with agents to allow them to fetch and manipulate data in OpenCTI.

### Available Tools

- `get_threat_actors`: Retrieve threat actors from OpenCTI
- `get_indicators`: Retrieve indicators from OpenCTI
- `get_observables`: Retrieve observables from OpenCTI
- `get_vulnerabilities`: Retrieve vulnerabilities from OpenCTI
- `get_reports`: Retrieve reports from OpenCTI
- `get_relationships`: Retrieve relationships from OpenCTI
- `get_entities`: Retrieve entities of a specific type from OpenCTI
- `create_report`: Create a new report in OpenCTI
- `create_indicator`: Create a new indicator in OpenCTI

## Usage

### Registering Tools with an Agent

You can register tools with an agent in two ways:

1. During initialization:

```python
from agents.base import BaseAgent

# Create an agent with tools
agent = BaseAgent(
    name="my_agent",
    system_message="You are an agent with OpenCTI tools.",
    tools=["get_threat_actors", "get_indicators", "get_reports"]
)
```

2. After initialization:

```python
from agents.base import BaseAgent

# Create an agent
agent = BaseAgent(
    name="my_agent",
    system_message="You are an agent."
)

# Register tools
agent.register_tool("get_threat_actors")
agent.register_tool("get_indicators")
agent.register_tool("get_reports")
```

### Using Tools

Once tools are registered, they are automatically available to the agent through the LLM's function calling capabilities. The agent can use these tools to fetch data from OpenCTI and provide responses based on that data.

You can also access the tool functions directly:

```python
# Get the tool function
get_reports_func = agent.tool_functions["get_reports"]

# Call the function
reports = get_reports_func(limit=5)
```

### Example

See the `examples/opencti_tools_example.py` and `examples/opencti_agent_conversation.py` files for complete examples of using OpenCTI tools with agents.

## Adding New Tools

To add new tools:

1. Create a new module in the `agents/tools` directory
2. Define your tool functions
3. Add the tools to the `AVAILABLE_TOOLS` dictionary in `agents/tools/__init__.py`
4. Register the tools with your agents

## Tool Categories

Tools are organized into categories:

- `opencti`: Tools for accessing data in OpenCTI

You can get all tools in a category using the `get_tools_by_category` function:

```python
from agents.tools import get_tools_by_category

# Get all OpenCTI tools
opencti_tools = get_tools_by_category("opencti")
```

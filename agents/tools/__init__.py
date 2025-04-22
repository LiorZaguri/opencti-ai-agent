"""
Tools for Agents.

This package provides tools that can be registered with agents to extend their capabilities.
"""

from typing import Dict, Any, List, Callable, Optional
from core.utils.logger import setup_logger

logger = setup_logger(name="agent_tools", component_type="tools")

# Import tool modules
from agents.tools.opencti_tools import (
    get_threat_actors,
    get_indicators,
    get_observables,
    get_vulnerabilities,
    get_reports,
    get_relationships,
    get_entities,
    create_report,
    create_indicator,
    entity_counts,
    clear_opencti_caches
)

# Define tool categories
TOOL_CATEGORIES = {
    "opencti": "OpenCTI data access tools",
    # Add more categories as needed
}

# Define available tools with metadata
AVAILABLE_TOOLS = {
    # OpenCTI Tools
    "get_threat_actors": {
        "function": get_threat_actors,
        "category": "opencti",
        "description": "Retrieve threat actors from OpenCTI. Threat actors are individuals, groups, or organizations believed to be operating with malicious intent.",
        "parameters": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of threat actors to return",
                "default": 50
            }
        }
    },
    "get_indicators": {
        "function": get_indicators,
        "category": "opencti",
        "description": "Retrieve indicators from OpenCTI. Example filters: [{ 'key': 'created_at', 'values': ['now-30d'], 'operator': 'gte' }]",
        "parameters": {
            "filters": {
                "type": "array",
                "description": "List of filter objects. Each should be a dict with 'key', 'values', and optionally 'operator'. Example: [{ 'key': 'created_at', 'values': ['now-30d'], 'operator': 'gte' }]. Can also be a string that will be parsed.",
                "default": None
            },
            "days_back": {
                "type": "integer",
                "description": "Number of days to look back for indicators (used if no filters provided)",
                "default": 30
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of indicators to return",
                "default": 100
            }
        }
    },
    "get_observables": {
        "function": get_observables,
        "category": "opencti",
        "description": "Retrieve observables (IPs, domains, hashes, etc.) from OpenCTI. Example filters: [{ 'key': 'entity_type', 'values': ['IPv4-Addr'] }]",
        "parameters": {
            "filters": {
                "type": "array",
                "description": "List of filter objects. Each should be a dict with 'key', 'values', and optionally 'operator'. Example: [{ 'key': 'entity_type', 'values': ['IPv4-Addr'] }]. Can also be a string that will be parsed.",
                "default": None
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of observables to return",
                "default": 100
            }
        }
    },
    "get_vulnerabilities": {
        "function": get_vulnerabilities,
        "category": "opencti",
        "description": "Retrieve vulnerabilities from OpenCTI. Vulnerabilities are weaknesses in systems that can be exploited by threat actors. Often includes CVE IDs.",
        "parameters": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of vulnerabilities to return",
                "default": 50
            }
        }
    },
    "get_reports": {
        "function": get_reports,
        "category": "opencti",
        "description": "Retrieve threat intelligence reports from OpenCTI. Reports contain analysis of threats, campaigns, incidents, and other intelligence findings.",
        "parameters": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of reports to return",
                "default": 20
            },
            "days_back": {
                "type": "integer",
                "description": "Number of days to look back for reports",
                "default": 90
            }
        }
    },
    "get_relationships": {
        "function": get_relationships,
        "category": "opencti",
        "description": "Retrieve relationships between entities from OpenCTI. Relationships connect entities like 'uses' (Threat Actor uses Malware), 'targets' (Malware targets Vulnerability), etc.",
        "parameters": {
            "entity_id": {
                "type": "string",
                "description": "Optional ID of entity to get relationships for. Use this to find all relationships connected to a specific entity.",
                "default": None
            },
            "relationship_type": {
                "type": "string",
                "description": "Optional type of relationship to filter by (e.g., 'uses', 'targets', 'indicates', 'mitigates').",
                "default": None
            },
            "filters": {
                "type": "array",
                "description": "Optional additional filters to apply. Example: [{ 'key': 'created_at', 'values': ['now-30d'], 'operator': 'gte' }]. Can also be a string that will be parsed.",
                "default": None
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of relationships to return",
                "default": 100
            },
            "days_back": {
                "type": "integer",
                "description": "Number of days to look back for relationships",
                "default": 90
            }
        }
    },
    "get_entities": {
        "function": get_entities,
        "category": "opencti",
        "description": "Retrieve entities of a specific type from OpenCTI. Common entity types include: 'Malware', 'Attack-Pattern', 'Tool', 'Intrusion-Set', 'Campaign', 'Incident'.",
        "parameters": {
            "entity_type": {
                "type": "string",
                "description": "Type of entity to retrieve. Common types: 'Malware', 'Attack-Pattern', 'Tool', 'Intrusion-Set', 'Campaign', 'Incident', 'Course-of-Action'.",
                "required": True
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of entities to return",
                "default": 50
            }
        }
    },
    "create_report": {
        "function": create_report,
        "category": "opencti",
        "description": "Create a new report in OpenCTI with threat intelligence findings",
        "parameters": {
            "name": {
                "type": "string",
                "description": "The title of the report.",
                "required": True
            },
            "description": {
                "type": "string",
                "description": "A detailed description of the report.",
                "required": True
            },
            "published": {
                "type": "string",
                "description": "ISO-8601 timestamp when the report was published.",
                "required": True
            },
            "report_class": {
                "type": "string",
                "description": "The class/type of report (e.g., 'threat-report').",
                "default": "threat-report"
            }
        }
    },
    "create_indicator": {
        "function": create_indicator,
        "category": "opencti",
        "description": "Create a new indicator in OpenCTI (e.g., file hash, IP, domain, URL pattern)",
        "parameters": {
            "name": {
                "type": "string",
                "description": "The indicator's name (e.g., 'Malicious IP').",
                "required": True
            },
            "pattern": {
                "type": "string",
                "description": "STIX pattern to detect the IOC (e.g., \"[ipv4-addr:value = '1.2.3.4']\").",
                "required": True
            },
            "pattern_type": {
                "type": "string",
                "description": "Pattern syntax type (e.g., 'stix').",
                "required": True
            },
            "valid_from": {
                "type": "string",
                "description": "ISO‑8601 timestamp when this IOC becomes valid.",
                "required": True
            },
            "x_opencti_main_observable_type": {
                "type": "string",
                "description": "The main observable type (e.g., 'IPv4-Addr', 'File').",
                "required": True
            }
        }
    },
    "entity_counts": {
        "function": entity_counts,
        "category": "opencti",
        "description": "Get counts of different entity types in OpenCTI. This helps understand what data is available in the platform.",
        "parameters": {
            "limit": {
                "type": "integer",
                "description": "Sample size for counting entities",
                "default": 10
            }
        }
    },
    "clear_opencti_caches": {
        "function": clear_opencti_caches,
        "category": "opencti",
        "description": "Clear all OpenCTI data caches to ensure fresh data is retrieved from the server.",
        "parameters": {}
    }
    # Add more tools as needed
}

def get_tool_by_name(tool_name: str) -> Optional[Dict[str, Any]]:
    """
    Get a tool by name.

    Args:
        tool_name: Name of the tool to retrieve

    Returns:
        Tool metadata dictionary or None if not found
    """
    return AVAILABLE_TOOLS.get(tool_name)

def get_tools_by_category(category: str) -> List[Dict[str, Any]]:
    """
    Get all tools in a specific category.

    Args:
        category: Category name

    Returns:
        List of tool metadata dictionaries
    """
    return {name: tool for name, tool in AVAILABLE_TOOLS.items()
            if tool.get("category") == category}

def get_tool_function(tool_name: str) -> Optional[Callable]:
    """
    Get the function for a specific tool.

    Args:
        tool_name: Name of the tool

    Returns:
        Tool function or None if not found
    """
    tool = get_tool_by_name(tool_name)
    if tool:
        return tool.get("function")
    return None

def get_tool_description(tool_name: str) -> str:
    """
    Get the description for a specific tool.

    Args:
        tool_name: Name of the tool

    Returns:
        Tool description or empty string if not found
    """
    tool = get_tool_by_name(tool_name)
    if tool:
        return tool.get("description", "")
    return ""

def get_tool_parameters(tool_name: str) -> Dict[str, Any]:
    """
    Get the parameters for a specific tool.

    Args:
        tool_name: Name of the tool

    Returns:
        Tool parameters dictionary or empty dict if not found
    """
    tool = get_tool_by_name(tool_name)
    if tool:
        return tool.get("parameters", {})
    return {}

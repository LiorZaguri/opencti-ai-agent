import re
from pathlib import Path
from typing import Union
from core.utils.logger import setup_logger

logger = setup_logger(name="token_usage", component_type="token_validators")

def validate_agent_name(agent_name: str) -> bool:
    """Validate agent name to prevent injection and ensure proper format"""
    if not agent_name or not isinstance(agent_name, str):
        logger.warning(f"Invalid agent name: {agent_name}")
        return False
    
    # Alphanumeric, underscore, hyphen only - prevents injection into logs and other systems
    if not re.match(r'^[a-zA-Z0-9_-]+$', agent_name):
        logger.warning(f"Invalid agent name format: {agent_name}")
        return False
    
    return True

def validate_token_counts(input_tokens: Union[int, float], output_tokens: Union[int, float]) -> tuple[int, int]:
    """Validate and normalize token counts"""
    try:
        input_tokens = int(input_tokens)
        output_tokens = int(output_tokens)
    except (ValueError, TypeError):
        logger.warning(f"Invalid token values: input={input_tokens}, output={output_tokens}. Setting to 0.")
        return 0, 0
    
    if input_tokens < 0 or output_tokens < 0:
        logger.warning(f"Negative token values received: input={input_tokens}, output={output_tokens}. Setting to 0.")
        input_tokens = max(0, input_tokens)
        output_tokens = max(0, output_tokens)
    
    return input_tokens, output_tokens

def sanitize_path(path_str: str) -> Path:
    """Sanitize and validate a path string to prevent path traversal"""
    # Convert to Path object
    path = Path(path_str).resolve()
    
    # Ensure it's within the data directory
    data_dir = Path("data").resolve()
    if not str(path).startswith(str(data_dir)):
        logger.warning(f"Path traversal attempt blocked: {path_str}")
        return data_dir / "token_usage.json"
    
    return path 
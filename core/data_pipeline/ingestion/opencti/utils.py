from typing import Dict, Any
from core.utils.logger import setup_logger

logger = setup_logger(name="opencti_utils", component_type="utils")

def assign_priority(score: float) -> str:
    """Assign priority level based on score"""
    if score >= 0.7:
        return "high"
    elif score >= 0.4:
        return "medium"
    else:
        return "low" 
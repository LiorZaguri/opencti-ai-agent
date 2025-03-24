import json
import os
from typing import Dict, Any
from datetime import datetime, timedelta

from core.utils.logger import setup_logger
from .validators import sanitize_path

logger = setup_logger(name="token_usage", component_type="token_storage")

class TokenUsageStorage:
    def __init__(self, storage_path: str = "data/token_usage.json"):
        self.storage_path = sanitize_path(storage_path)
        os.makedirs(self.storage_path.parent, exist_ok=True)

    def save(self, usage_data: Dict[str, Any]) -> None:
        """Save token usage to disk with atomic write"""
        try:
            temp_path = self.storage_path.with_suffix('.tmp')
            
            with open(temp_path, 'w') as f:
                json.dump(usage_data, f, indent=4)
                
            # Atomic replace
            temp_path.replace(self.storage_path)
        except Exception as e:
            logger.error(f"Failed to save token usage data: {e}")
            raise

    def load(self) -> Dict[str, Any]:
        """Load token usage from disk"""
        try:
            if not self.storage_path.exists():
                return {}
                
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
                
            if not isinstance(data, dict):
                logger.error(f"Invalid data format in {self.storage_path}")
                return {}
                
            return data
        except Exception as e:
            logger.error(f"Failed to load token usage data: {e}")
            return {}

    def prune_expired(self, data: Dict[str, Any], window_hours: int = 24) -> Dict[str, Any]:
        """Remove entries older than the specified window"""
        try:
            cutoff = datetime.now() - timedelta(hours=window_hours)
            pruned_data = {}
            
            for agent, stats in data.items():
                try:
                    last_updated = datetime.fromisoformat(stats["last_updated"])
                    if last_updated >= cutoff:
                        pruned_data[agent] = stats
                except (ValueError, KeyError) as e:
                    logger.warning(f"Invalid timestamp for agent {agent}: {e}")
                    continue
                    
            return pruned_data
        except Exception as e:
            logger.error(f"Error pruning expired data: {e}")
            return data  # Return original data on error 
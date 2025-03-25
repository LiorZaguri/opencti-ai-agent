from typing import Dict, Any, Optional, List
import time
from core.utils.logger import setup_logger

logger = setup_logger(name="opencti_cache", component_type="utils")

# In-memory cache storage
_data_cache = {}
_cache_expiry = {}
DEFAULT_CACHE_TTL = 1800  # 30 minutes in seconds

def get_from_cache(cache_key: str, use_cache: bool = True) -> Optional[List[Dict[str, Any]]]:
    """Get data from cache if available and not expired"""
    if not use_cache:
        return None
        
    current_time = time.time()
    if cache_key in _data_cache and current_time < _cache_expiry.get(cache_key, 0):
        logger.debug(f"Cache hit for {cache_key}")
        return _data_cache[cache_key]
    return None

def store_in_cache(cache_key: str, data: List[Dict[str, Any]], 
                  use_cache: bool = True, cache_ttl: int = DEFAULT_CACHE_TTL) -> None:
    """Store data in cache with expiry time"""
    if not use_cache:
        return
        
    _data_cache[cache_key] = data
    _cache_expiry[cache_key] = time.time() + cache_ttl
    logger.debug(f"Cached data for {cache_key}, expires in {cache_ttl}s")

def invalidate_cache_prefix(prefix: str) -> None:
    """Clear cache entries with specific prefix"""
    keys_to_delete = [k for k in list(_data_cache.keys()) if k.startswith(prefix)]
    for key in keys_to_delete:
        if key in _data_cache:
            del _data_cache[key]
        if key in _cache_expiry:
            del _cache_expiry[key]
    logger.info(f"Invalidated cache for {prefix}, {len(keys_to_delete)} entries removed")

def clear_all_caches() -> None:
    """Clear all in-memory caches for ingestors"""
    global _data_cache, _cache_expiry
    _data_cache = {}
    _cache_expiry = {}
    logger.info("Cleared all data ingestor caches") 
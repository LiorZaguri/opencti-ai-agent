import os
from core.memory.short_term.cache_store import CacheStore
import threading
from utils.logger import setup_logger

# Create a memory-specific logger
logger = setup_logger(name="CacheManager", component_type="memory")

# Add a lock for thread safety
_registry_lock = threading.Lock()

# Use a shared cache file for all agents (can scale later)
SHARED_CACHE_PATH = "data/cache/shared_cache.json"
_shared_cache = CacheStore(cache_path=SHARED_CACHE_PATH)

# Registry for flexibility if future per-agent caches are needed
_cache_registry = {"default": _shared_cache}


def get_agent_cache(agent_name: str) -> CacheStore:
    with _registry_lock:
        if agent_name in _cache_registry:
            logger.debug(f"Retrieved dedicated cache for agent '{agent_name}'")
            return _cache_registry[agent_name]
        logger.debug(f"No dedicated cache found for agent '{agent_name}', using shared cache")
        return _shared_cache


def list_all_caches() -> list:
    with _registry_lock:
        cache_list = list(_cache_registry.keys())
        logger.debug(f"Listed all caches: {cache_list}")
        return cache_list


def clear_all_caches():
    with _registry_lock:
        for cache_name, cache in _cache_registry.items():
            logger.info(f"Clearing cache: {cache_name}")
            cache.clear()


def register_cache(alias: str, cache_path: str = None) -> CacheStore:
    with _registry_lock:
        if alias in _cache_registry:
            logger.debug(f"Cache alias '{alias}' already exists, returning existing instance")
            return _cache_registry[alias]

        if cache_path is None:
            # Store all cache files in the data/cache directory
            cache_dir = "data/cache"
            os.makedirs(cache_dir, exist_ok=True)
            cache_path = f"{cache_dir}/{alias}_cache.json"

        logger.info(f"Registering new cache with alias '{alias}' at path '{cache_path}'")
        new_cache = CacheStore(cache_path=cache_path)
        _cache_registry[alias] = new_cache
        return new_cache


def unregister_cache(alias: str) -> bool:
    with _registry_lock:
        if alias == "default":
            logger.warning("Cannot unregister default cache")
            return False  # Protect the default cache

        if alias in _cache_registry:
            logger.info(f"Unregistering cache with alias '{alias}'")
            del _cache_registry[alias]
            return True

        logger.debug(f"Cannot unregister cache '{alias}': not found")
        return False


def get_cache_stats() -> dict:
    with _registry_lock:
        stats = {name: cache.size() for name, cache in _cache_registry.items()}
        logger.debug(f"Cache stats: {stats}")
        return stats


def get_cache_registry() -> dict:
    with _registry_lock:
        logger.debug("Retrieved cache registry copy")
        return _cache_registry.copy()
        
        
def initialize_cache():
    """
    Ensure the cache directory is created and initialize the cache system.
    Should be called during application startup.
    """
    cache_dir = os.path.dirname(SHARED_CACHE_PATH)
    os.makedirs(cache_dir, exist_ok=True)
    logger.info(f"Cache directory initialized at {cache_dir}")
    # The shared cache is already initialized at module level
    return _shared_cache 
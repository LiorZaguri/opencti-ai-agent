import os
from memory.cache_store import CacheStore
import threading

# Add a lock for thread safety
_registry_lock = threading.Lock()

# Use a shared cache file for all agents (can scale later)
SHARED_CACHE_PATH = "memory/cache/shared_cache.json"
_shared_cache = CacheStore(cache_path=SHARED_CACHE_PATH)

# Registry for flexibility if future per-agent caches are needed
_cache_registry = {"default": _shared_cache}

def get_agent_cache(agent_name: str) -> CacheStore:
    with _registry_lock:
        if agent_name in _cache_registry:
            return _cache_registry[agent_name]
        return _shared_cache

def list_all_caches() -> list:
    with _registry_lock:
        return list(_cache_registry.keys())

def clear_all_caches():
    with _registry_lock:
        for cache_name, cache in _cache_registry.items():
            cache.clear()

def register_cache(alias: str, cache_path: str = None) -> CacheStore:
    with _registry_lock:
        if alias in _cache_registry:
            return _cache_registry[alias]

        if cache_path is None:
            # Store all cache files in the memory/cache directory
            cache_dir = "memory/cache"
            os.makedirs(cache_dir, exist_ok=True)
            cache_path = f"{cache_dir}/{alias}_cache.json"

        new_cache = CacheStore(cache_path=cache_path)
        _cache_registry[alias] = new_cache
        return new_cache


def unregister_cache(alias: str) -> bool:
    with _registry_lock:
        if alias == "default":
            return False  # Protect the default cache

        if alias in _cache_registry:
            del _cache_registry[alias]
            return True
        return False

def get_cache_stats() -> dict:
    with _registry_lock:
        return {name: cache.size() for name, cache in _cache_registry.items()}

def get_cache_registry() -> dict:
    with _registry_lock:
        return _cache_registry.copy()
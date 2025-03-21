import os
import json
import hashlib
import tempfile
import logging
from threading import Lock
from typing import Optional

# Default path for persistent cache file
CACHE_FILE_PATH = "memory/cache/shared_cache.json"

class CacheStore:
    """
    A thread-safe, file-backed cache system for storing AI agent inputs and outputs.
    Prevents redundant LLM calls and saves on token usage.
    """

    def __init__(self, cache_path: str = CACHE_FILE_PATH):
        self.cache_path = cache_path
        self.lock = Lock()
        self.cache = self._load_cache()

    def _load_cache(self) -> dict:
        if os.path.exists(self.cache_path):
            with open(self.cache_path, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON from {self.cache_path}: {e}")
                    return {}
        return {}

    def _save_cache(self):
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        # Write to a temporary file first for atomicity
        dir_name = os.path.dirname(self.cache_path)
        with tempfile.NamedTemporaryFile("w", delete=False, dir=dir_name, encoding="utf-8") as tmp_file:
            json.dump(self.cache, tmp_file, indent=2)
            temp_name = tmp_file.name
        os.replace(temp_name, self.cache_path)

    def compute_hash(self, task: str, agent_name: str) -> str:
        """
        Create a unique, deterministic hash for a task and agent identity.
        """
        raw_input = f"{agent_name}::{task}"
        return hashlib.sha256(raw_input.encode()).hexdigest()

    def get(self, task: str, agent_name: str) -> Optional[str]:
        key = self.compute_hash(task, agent_name)
        with self.lock:
            return self.cache.get(key)

    def save(self, task: str, agent_name: str, result: str):
        key = self.compute_hash(task, agent_name)
        with self.lock:
            self.cache[key] = result
            self._save_cache()

    def has(self, task: str, agent_name: str) -> bool:
        key = self.compute_hash(task, agent_name)
        with self.lock:
            return key in self.cache

    def clear(self):
        with self.lock:
            self.cache = {}
            self._save_cache()

    def size(self) -> int:
        with self.lock:
            return len(self.cache)

    def keys(self) -> list:
        """Return all keys in the cache."""
        with self.lock:
            return list(self.cache.keys())

    def values(self) -> list:
        """Return all cached results."""
        with self.lock:
            return list(self.cache.values())

    def items(self):
        """Return all key-value pairs in the cache."""
        with self.lock:
            return list(self.cache.items())

    def remove(self, task: str, agent_name: str) -> bool:
        """Remove a specific entry from the cache."""
        key = self.compute_hash(task, agent_name)
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                self._save_cache()
                return True
            return False
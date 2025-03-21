import os
import sys
import json
import shutil
import tempfile
import threading
import unittest
from memory.cache_store import CacheStore
import memory.cache_manager as cache_manager

TEST_CACHE_DIR = "tests/test_memory/"

class TestCacheStore(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for cache files
        self.test_dir = tempfile.mkdtemp()
        self.cache_path = os.path.join(self.test_dir, "test_cache.json")
        self.cache = CacheStore(cache_path=self.cache_path)

    def tearDown(self):
        # Remove temporary directory and files after each test
        shutil.rmtree(self.test_dir)

    def test_save_and_get(self):
        task = "sample task"
        agent = "agent1"
        result = "result data"
        self.cache.save(task, agent, result)
        self.assertTrue(self.cache.has(task, agent))
        self.assertEqual(self.cache.get(task, agent), result)

    def test_remove(self):
        task = "task to remove"
        agent = "agent2"
        result = "to be removed"
        self.cache.save(task, agent, result)
        self.assertTrue(self.cache.remove(task, agent))
        self.assertFalse(self.cache.has(task, agent))

    def test_clear(self):
        self.cache.save("task1", "agent1", "result1")
        self.cache.save("task2", "agent2", "result2")
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)

    def test_persistence(self):
        task = "persistent task"
        agent = "agent3"
        result = "persistent result"
        self.cache.save(task, agent, result)
        # Create a new CacheStore instance with the same file to verify persistence
        new_cache = CacheStore(cache_path=self.cache_path)
        self.assertEqual(new_cache.get(task, agent), result)


class TestCacheManager(unittest.TestCase):
    def setUp(self):
        # Clear all caches before each test to ensure a clean slate.
        cache_manager.clear_all_caches()

    def test_get_agent_cache_default(self):
        cache = cache_manager.get_agent_cache("non_existing")
        self.assertIsNotNone(cache)
        # Calling get_agent_cache with the same non-existing agent should return the same default cache.
        self.assertEqual(cache, cache_manager.get_agent_cache("non_existing"))

    def test_register_and_unregister_cache(self):
        alias = "test_alias"
        new_cache = cache_manager.register_cache(alias)
        self.assertIn(alias, cache_manager.list_all_caches())
        self.assertTrue(cache_manager.unregister_cache(alias))
        self.assertNotIn(alias, cache_manager.list_all_caches())
        # Ensure that the default cache cannot be unregistered.
        self.assertFalse(cache_manager.unregister_cache("default"))

    def test_cache_stats(self):
        # Register additional caches.
        cache_manager.register_cache("cache1")
        cache_manager.register_cache("cache2")
        stats = cache_manager.get_cache_stats()
        self.assertIn("default", stats)
        self.assertIn("cache1", stats)
        self.assertIn("cache2", stats)


class TestCacheStoreConcurrency(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache_path = os.path.join(self.test_dir, "concurrent_cache.json")
        self.cache = CacheStore(cache_path=self.cache_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def worker(self, task_prefix, agent_name, count):
        for i in range(count):
            task = f"{task_prefix} task {i}"
            result = f"result {i}"
            self.cache.save(task, agent_name, result)
            # Optionally, perform some get/check operations
            self.assertEqual(self.cache.get(task, agent_name), result)

    def test_concurrent_access(self):
        threads = []
        for t in range(5):
            thread = threading.Thread(
                target=self.worker, args=(f"Thread{t}", f"agent{t}", 10)
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Verify that the total number of entries is as expected (5 threads * 10 entries each)
        self.assertEqual(self.cache.size(), 50)


if __name__ == "__main__":
    unittest.main()

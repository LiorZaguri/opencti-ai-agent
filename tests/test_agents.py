import asyncio
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from agents.base import BaseAgent
from core.memory.short_term.cache_manager import clear_all_caches


# Concrete implementation of BaseAgent for testing
class TestAgent(BaseAgent):
    async def handle_task(self, task, context):
        return f"Processed: {task}"


class TestBaseAgent(unittest.TestCase):
    def setUp(self):
        # Set up a temporary directory for test cache files
        self.temp_dir = tempfile.mkdtemp()
        self.original_cache_path = os.environ.get('CACHE_FILE_PATH')
        os.environ['CACHE_FILE_PATH'] = os.path.join(self.temp_dir, 'test_cache.json')
        clear_all_caches()

    def tearDown(self):
        # Clean up after tests
        if self.original_cache_path:
            os.environ['CACHE_FILE_PATH'] = self.original_cache_path
        else:
            del os.environ['CACHE_FILE_PATH']
        shutil.rmtree(self.temp_dir)

    def test_initialization(self):
        # Test default initialization
        agent = TestAgent(name="test_agent")
        self.assertEqual(agent.name, "test_agent")
        self.assertTrue(agent.use_cache)

        # Test custom initialization
        custom_llm_config = {"temperature": 0.7}
        agent2 = TestAgent(
            name="custom_agent",
            system_message="Custom message",
            llm_config=custom_llm_config,
            use_cache=False
        )
        self.assertEqual(agent2.name, "custom_agent")
        self.assertEqual(agent2.system_message, "Custom message")
        self.assertFalse(agent2.use_cache)

    @patch('agents.base.logger')
    def test_logging(self, mock_logger):
        agent = TestAgent(name="logging_agent")
        # Check initialization log
        mock_logger.info.assert_called_with("Initialized agent: logging_agent with token limit: 10000 "
                                            "(cache: True)")

        # Check task execution logs
        asyncio.run(agent.execute_task("test task"))
        mock_logger.info.assert_called_with("[logging_agent] Running task: test task")

    def test_caching(self):
        agent = TestAgent(name="cache_agent")

        # First execution should store in cache
        result1 = asyncio.run(agent.execute_task("sample task"))
        self.assertEqual(result1, "Processed: sample task")

        # Second execution should use cache
        with patch.object(agent, 'handle_task') as mock_handle:
            mock_handle.return_value = "This should not be returned"
            result2 = asyncio.run(agent.execute_task("sample task"))

            # Should return cached result
            self.assertEqual(result2, "Processed: sample task")
            # Shouldn't call handle_task
            mock_handle.assert_not_called()

    def test_no_cache(self):
        agent = TestAgent(name="no_cache_agent", use_cache=False)

        # Task execution without cache
        result1 = asyncio.run(agent.execute_task("test task"))
        self.assertEqual(result1, "Processed: test task")

        # Should call handle_task every time
        with patch.object(agent, 'handle_task') as mock_handle:
            async def mock_async_handle(*args, **kwargs):
                return "New result"

            mock_handle.side_effect = mock_async_handle
            result2 = asyncio.run(agent.execute_task("test task"))
            self.assertEqual(result2, "New result")
            mock_handle.assert_called_once()

    def test_abstract_method(self):
        # BaseAgent without handle_task implementation should raise error
        with self.assertRaises(TypeError):
            BaseAgent(name="abstract_test")

    def test_async_init(self):
        # Test async initialization
        agent = TestAgent(name="async_init_agent")
        # Run async_init
        agent = asyncio.run(agent.async_init())
        # Check that company_profile was loaded
        self.assertIsInstance(agent.company_profile, dict)


if __name__ == '__main__':
    unittest.main()
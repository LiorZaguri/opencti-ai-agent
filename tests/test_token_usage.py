import unittest
import os
import json
import time
import threading
import datetime
from unittest.mock import patch, Mock
from pathlib import Path
from core.token_usage.token_usage import TokenUsage, get_agent_limit
from config.settings import SYSTEM_DAILY_TOKEN_LIMIT, AGENT_DEFAULT_TOKEN_LIMIT


def mock_openrouter_response(input_tokens, output_tokens):
    return {
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }
    }


class TestTokenUsage(unittest.TestCase):

    def setUp(self):
        # Reset the singleton before each test to ensure isolation
        TokenUsage.reset_for_testing()
        
        # Use a test-specific storage path for each test
        test_name = self.id().split('.')[-1]
        self.test_storage_path = Path(f"data/test_token_usage_{test_name}.json")
        
        # Ensure directory exists
        os.makedirs(self.test_storage_path.parent, exist_ok=True)
        
        # Clear any existing test file
        if self.test_storage_path.exists():
            self.test_storage_path.unlink()
            
        # Create new instance with test-specific path
        with patch.dict('os.environ', {'TOKEN_USAGE_PATH': str(self.test_storage_path)}):
            self.token_usage = TokenUsage()

    def tearDown(self):
        # Clean up test files
        if self.test_storage_path.exists():
            try:
                self.test_storage_path.unlink()
            except:
                pass

    def test_singleton_pattern(self):
        # Test that multiple instances point to the same object
        instance1 = TokenUsage()
        instance2 = TokenUsage()
        self.assertIs(instance1, instance2)

        # Verify state is shared
        instance1.log_tokens("test_agent", 10, 20)
        self.assertEqual(instance2.get_usage("test_agent")["total"], 30)

    def test_log_tokens_from_openrouter(self):
        agent_name = "test_agent"
        response = mock_openrouter_response(100, 150)

        self.token_usage.log_tokens_from_openrouter(agent_name, response)
        usage = self.token_usage.get_usage(agent_name)

        self.assertEqual(usage["input"], 100)
        self.assertEqual(usage["output"], 150)
        self.assertEqual(usage["total"], 250)
        self.assertTrue("last_updated" in usage)

    @patch.dict('os.environ', {'LIMITED_AGENT_TOKEN_LIMIT': '300'})
    def test_agent_token_limit(self):
        agent_name = "limited_agent"

        response_within_limit = mock_openrouter_response(100, 100)
        self.token_usage.log_tokens_from_openrouter(agent_name, response_within_limit)

        response_exceed_limit = mock_openrouter_response(101, 100)
        with self.assertRaises(Exception) as context:
            self.token_usage.log_tokens_from_openrouter(agent_name, response_exceed_limit)
        self.assertIn("Token limit exceeded", str(context.exception))

    @patch.dict('os.environ', {'AGENT_ONE_TOKEN_LIMIT': '100000', 'AGENT_TWO_TOKEN_LIMIT': '100000'})
    def test_system_wide_token_limit(self):
        agent_one = "agent_one"
        agent_two = "agent_two"

        half_limit = SYSTEM_DAILY_TOKEN_LIMIT // 2
        response_half_limit = mock_openrouter_response(half_limit // 2, half_limit // 2)

        self.token_usage.log_tokens_from_openrouter(agent_one, response_half_limit)
        self.token_usage.log_tokens_from_openrouter(agent_two, response_half_limit)

        response_exceed_limit = mock_openrouter_response(10, 10)
        with self.assertRaises(Exception) as context:
            self.token_usage.log_tokens_from_openrouter(agent_two, response_exceed_limit)
        self.assertIn("System-wide token limit exceeded", str(context.exception))

    @patch.dict('os.environ', {'WARNING_AGENT_TOKEN_LIMIT': '1000'})
    def test_nearing_agent_token_limit_warning(self):
        agent_name = "warning_agent"

        with self.assertLogs('token_usage', level='WARNING') as log:
            response_below_warning = mock_openrouter_response(400, 399)  # 799 tokens, below 80%
            self.token_usage.log_tokens_from_openrouter(agent_name, response_below_warning)

            response_trigger_warning = mock_openrouter_response(1, 0)  # exactly 800 tokens (80%)
            self.token_usage.log_tokens_from_openrouter(agent_name, response_trigger_warning)
            self.assertTrue(any("Nearing agent token limit" in message for message in log.output))

    @patch.dict('os.environ', {'SYSTEM_WARNING_AGENT_TOKEN_LIMIT': '100000'})
    def test_nearing_system_token_limit_warning(self):
        agent_name = "system_warning_agent"
        threshold = int(0.8 * SYSTEM_DAILY_TOKEN_LIMIT)

        with self.assertLogs('token_usage', level='WARNING') as log:
            response_below_warning = mock_openrouter_response(threshold // 2 - 10, threshold // 2 - 10)
            self.token_usage.log_tokens_from_openrouter(agent_name, response_below_warning)

            response_trigger_warning = mock_openrouter_response(10, 10)  # exactly 80% threshold
            self.token_usage.log_tokens_from_openrouter(agent_name, response_trigger_warning)
            self.assertTrue(any("Nearing daily token limit" in message for message in log.output))

    def test_get_total_usage(self):
        # Test across multiple agents
        self.token_usage.log_tokens("agent1", 100, 200)
        self.token_usage.log_tokens("agent2", 300, 400)

        total = self.token_usage.get_total_usage()
        self.assertEqual(total["input"], 400)
        self.assertEqual(total["output"], 600)
        self.assertEqual(total["total"], 1000)
        self.assertTrue("last_updated" in total)

    def test_edge_cases(self):
        # Test with zero tokens
        self.token_usage.log_tokens("zero_agent", 0, 0)
        self.assertEqual(self.token_usage.get_usage("zero_agent")["total"], 0)

        # Test non-existent agent
        usage = self.token_usage.get_usage("non_existent")
        self.assertEqual(usage["input"], 0)
        self.assertEqual(usage["output"], 0)
        self.assertEqual(usage["total"], 0)
        self.assertTrue("last_updated" in usage)

    @patch('tiktoken.encoding_for_model')
    def test_estimate_tokens(self, mock_encoding):
        # Setup mock encoder
        mock_encoder = Mock()
        mock_encoder.encode.return_value = [1, 2, 3, 4, 5]  # 5 tokens
        mock_encoding.return_value = mock_encoder
        
        # Test with tiktoken working normally
        self.assertEqual(self.token_usage.estimate_tokens("some text"), 5)
        mock_encoder.encode.assert_called_with("some text")
        
        # Test empty string
        self.assertEqual(self.token_usage.estimate_tokens(""), 0)
        
        # Test fallback when tiktoken fails
        mock_encoder.encode.side_effect = Exception("Tiktoken error")
        # Force the fallback path - 10 chars / 4 = 2 tokens
        result = self.token_usage.estimate_tokens("1234567890")
        self.assertEqual(result, 2)

    @patch.dict('os.environ', {'AGENT_NAME_TOKEN_LIMIT': '500'})
    def test_get_agent_limit(self):
        # Test environment variable override
        self.assertEqual(get_agent_limit("AGENT_NAME"), 500)

        # Test default value
        self.assertEqual(get_agent_limit("UNKNOWN_AGENT"), AGENT_DEFAULT_TOKEN_LIMIT)

    def test_negative_token_values(self):
        # Test with negative input tokens
        with self.assertLogs('token_usage', level='WARNING') as log:
            self.token_usage.log_tokens("test_agent", -10, 20)
            self.assertTrue(any("Negative token values" in message for message in log.output))
        
        usage = self.token_usage.get_usage("test_agent")
        self.assertEqual(usage["input"], 0)  # Should be set to 0 instead of -10
        self.assertEqual(usage["output"], 20)
        self.assertEqual(usage["total"], 20)

        # Test with negative output tokens
        with self.assertLogs('token_usage', level='WARNING') as log:
            self.token_usage.log_tokens("test_agent", 30, -40)
            self.assertTrue(any("Negative token values" in message for message in log.output))
        
        usage = self.token_usage.get_usage("test_agent")
        self.assertEqual(usage["input"], 30)
        self.assertEqual(usage["output"], 20)  # Still 20, not decreased by -40
        self.assertEqual(usage["total"], 50)

    def test_malformed_openrouter_response(self):
        # Test with missing usage field
        with self.assertLogs('token_usage', level='ERROR') as log:
            self.token_usage.log_tokens_from_openrouter("test_agent", {})
            self.assertTrue(any("Malformed OpenRouter response" in message for message in log.output))
        
        # Test with missing prompt_tokens field
        with self.assertLogs('token_usage', level='ERROR') as log:
            self.token_usage.log_tokens_from_openrouter("test_agent", {"usage": {"completion_tokens": 10}})
            self.assertTrue(any("Malformed OpenRouter response" in message for message in log.output))

    def test_persistence(self):
        # Write some usage data
        self.token_usage.log_tokens("persistence_agent", 100, 200)
        
        # Check if file was created
        self.assertTrue(self.test_storage_path.exists())
        
        # Read the data directly from the file
        with open(self.test_storage_path, 'r') as f:
            stored_data = json.load(f)
        
        self.assertTrue("persistence_agent" in stored_data)
        self.assertEqual(stored_data["persistence_agent"]["input"], 100)
        self.assertEqual(stored_data["persistence_agent"]["output"], 200)
        self.assertEqual(stored_data["persistence_agent"]["total"], 300)
        
        # Create a new instance that should load the data
        with patch.dict('os.environ', {'TOKEN_USAGE_PATH': str(self.test_storage_path)}):
            TokenUsage.reset_for_testing()  # Reset singleton
            new_instance = TokenUsage()
            usage = new_instance.get_usage("persistence_agent")
            self.assertEqual(usage["total"], 300)

    def test_reset_daily_usage(self):
        # Add some usage
        self.token_usage.log_tokens("test_agent", 100, 200)
        self.assertEqual(self.token_usage.get_total_usage()["total"], 300)
        
        # Reset usage
        self.token_usage.reset_daily_usage()
        
        # Check that usage is reset
        self.assertEqual(self.token_usage.get_total_usage()["total"], 0)
        
        # Check that file was updated
        with open(self.test_storage_path, 'r') as f:
            stored_data = json.load(f)
        self.assertEqual(stored_data, {})

    def test_token_expiration(self):
        # Create a custom TokenUsage instance for this test
        with patch.dict('os.environ', {'TOKEN_USAGE_PATH': str(self.test_storage_path)}):
            TokenUsage.reset_for_testing()
            token_usage = TokenUsage()
            
            # Add usage with a past timestamp (25 hours ago)
            now = datetime.datetime.now()
            past = now - datetime.timedelta(hours=25)
            
            old_agent_stats = {
                "input": 100,
                "output": 200,
                "total": 300,
                "last_updated": past.isoformat()
            }
            
            # Directly modify usage data to set past timestamp
            token_usage.usage["old_agent"] = old_agent_stats
            
            # Now log some new usage
            token_usage.log_tokens("new_agent", 300, 400)
            
            # The prune_expired_usage should have removed old_agent
            self.assertEqual(token_usage.get_usage("old_agent")["total"], 0)
            self.assertEqual(token_usage.get_usage("new_agent")["total"], 700)
            self.assertEqual(token_usage.get_total_usage()["total"], 700)

    def test_concurrent_access(self):
        # Test that thread safety mechanisms prevent race conditions
        def worker(agent):
            # Each thread adds 1000 tokens for its agent
            for _ in range(10):
                self.token_usage.log_tokens(f"agent_{agent}", 50, 50)
                time.sleep(0.01)  # Small delay to increase chance of race conditions
        
        # Create and start all threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # Check that all tokens were counted correctly
        total = 0
        for i in range(5):
            usage = self.token_usage.get_usage(f"agent_{i}")
            self.assertEqual(usage["total"], 1000)
            total += usage["total"]
        
        # Check total across all agents
        self.assertEqual(self.token_usage.get_total_usage()["total"], 5000)


if __name__ == '__main__':
    unittest.main()
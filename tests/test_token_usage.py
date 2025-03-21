import unittest
from utils.token_usage import TokenUsage
from config.settings import AGENT_DEFAULT_TOKEN_LIMIT, SYSTEM_DAILY_TOKEN_LIMIT

class TestTokenUsage(unittest.TestCase):
    def setUp(self):
        self.token_tracker = TokenUsage()
        self.token_tracker.reset()

    def test_log_tokens_basic(self):
        self.token_tracker.log_tokens("agent1", 50, 100)
        usage = self.token_tracker.get_usage("agent1")
        self.assertEqual(usage["input"], 50)
        self.assertEqual(usage["output"], 100)
        self.assertEqual(usage["total"], 150)

    def test_total_usage(self):
        self.token_tracker.log_tokens("agent1", 100, 200)
        self.token_tracker.log_tokens("agent2", 50, 50)
        total = self.token_tracker.get_total_usage()
        self.assertEqual(total["input"], 150)
        self.assertEqual(total["output"], 250)
        self.assertEqual(total["total"], 400)

    def test_reset(self):
        self.token_tracker.log_tokens("agent1", 200, 200)
        self.token_tracker.reset()
        self.assertEqual(self.token_tracker.get_usage("agent1")["total"], 0)

    def test_estimate_tokens(self):
        text = "Estimate how many tokens this string has."
        estimated = self.token_tracker.estimate_tokens(text)
        self.assertTrue(isinstance(estimated, int))
        self.assertGreater(estimated, 0)

    def test_agent_token_limit_exceeded(self):
        with self.assertRaises(Exception) as context:
            self.token_tracker.log_tokens("agent1", AGENT_DEFAULT_TOKEN_LIMIT + 1, 0)
        self.assertIn("Token limit exceeded for agent", str(context.exception))

    def test_system_token_limit_exceeded(self):
        self.token_tracker.reset()
        used = SYSTEM_DAILY_TOKEN_LIMIT - 100

        # Spread usage across many agents
        num_agents = 10
        for i in range(num_agents):
            self.token_tracker.log_tokens(f"agent{i}", used // num_agents, 0)

        # This push will exceed the system-wide limit
        with self.assertRaises(Exception) as context:
            self.token_tracker.log_tokens("agentX", 50, 51)

        self.assertIn("System-wide token limit exceeded", str(context.exception))

if __name__ == '__main__':
    unittest.main()

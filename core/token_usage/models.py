from typing import TypedDict

class TokenStats(TypedDict):
    input: int
    output: int
    total: int
    last_updated: str  # ISO format timestamp

class TokenLimits:
    def __init__(self, agent_limit: int, system_limit: int):
        self.agent_limit = agent_limit
        self.system_limit = system_limit 
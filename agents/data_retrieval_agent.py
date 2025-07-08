from agents.base import BaseAgent
import json

class DataRetrievalAgent(BaseAgent):
    def __init__(self):
        system_message = (
            "You are DataRetrievalAgent. Your job is to fetch the top 100 Malware and top 100 Indicators from OpenCTI. "
            "Return both lists as a dictionary with keys 'malware' and 'indicators'."
        )
        tools = [
            "get_entities",  # for Malware
            "get_indicators"
        ]
        super().__init__(
            name="DataRetrievalAgent",
            system_message=system_message,
            tools=tools
        )

    def run(self, prompt: str = None) -> str:
        # Fetch top 100 Malware
        malware = self.tool_functions["get_entities"](entity_type="Malware", limit=100)
        # Fetch top 100 Indicators
        indicators = self.tool_functions["get_indicators"](limit=100)
        result = {
            "malware": malware,
            "indicators": indicators
        }
        return json.dumps(result) 
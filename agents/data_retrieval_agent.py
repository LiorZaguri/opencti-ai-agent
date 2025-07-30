import os
from agents.base import BaseAgent
import json

class DataRetrievalAgent(BaseAgent):
    def __init__(self, profile_path="data/company_profile.json"):
        system_message = (
            "You are DataRetrievalAgent. Your job is to fetch comprehensive threat intelligence data from OpenCTI "
            "including Threat Actors, Malware, Attack Patterns, and Campaigns. Retrieve detailed information "
            "to enable AI-powered analysis rather than basic keyword filtering."
        )
        tools = [
            "get_entities",  # for Malware, Attack Pattern, Campaign
            "get_threat_actors"
        ]
        super().__init__(
            name="DataRetrievalAgent",
            system_message=system_message,
            tools=tools
        )
        self.profile_path = profile_path
        self.profile = self._load_profile()

    def _load_profile(self):
        if os.path.exists(self.profile_path):
            with open(self.profile_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def run(self, prompt: str = None) -> str:
        """
        Retrieve comprehensive threat data for AI analysis.
        Fetch data like a real threat intelligence analyst would - multiple entity types with higher limits.
        """
        # Query comprehensive threat data with higher limits for better AI analysis
        result = {}
        
        # Define entity types to fetch with their limits
        entity_configs = [
            ("malware", "get_entities", 100, "Malware"),
            ("attack_patterns", "get_entities", 20, "Attack-Pattern"),
            ("campaigns", "get_entities", 20, "Campaign"),
            ("intrusion_sets", "get_entities", 20, "Intrusion-Set"),
            ("vulnerabilities", "get_entities", 20, "Vulnerability"),
            ("threat_reports", "get_entities", 20, "Report")
        ]
        
        for entity_name, tool_name, limit, *args in entity_configs:
            try:
                if tool_name == "get_threat_actors":
                    entities = self.tool_functions[tool_name](limit=limit)
                else:
                    entity_type = args[0]
                    entities = self.tool_functions[tool_name](entity_type=entity_type, limit=limit)
                result[entity_name] = entities
            except Exception as e:
                # If a specific entity type fails, log it but continue with others
                print(f"Warning: Failed to fetch {entity_name}: {str(e)}")
                result[entity_name] = []
        
        return json.dumps(result) 
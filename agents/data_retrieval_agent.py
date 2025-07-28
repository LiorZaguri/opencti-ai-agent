import os
from agents.base import BaseAgent
import json

class DataRetrievalAgent(BaseAgent):
    def __init__(self, profile_path="data/company_profile.json"):
        system_message = (
            "You are DataRetrievalAgent. Your job is to fetch relevant Threat Actors, Malware, Attack Patterns, and Campaigns from OpenCTI, based on the organization profile in company_profile.json. "
            "Return a dictionary with keys for each entity type."
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

    def _extract_keywords(self):
        # Extract keywords from relevant profile fields
        profile = self.profile
        keywords = set()
        for field in ["threat_priority", "tech_stack", "critical_assets", "past_incidents", "industry", "region"]:
            val = profile.get(field)
            if isinstance(val, list):
                keywords.update([v.lower() for v in val])
            elif isinstance(val, str):
                keywords.add(val.lower())
        return keywords

    def _filter_entities(self, entities):
        # Filter entities by keyword match in name/description/labels
        keywords = self._extract_keywords()
        filtered = []
        for ent in entities:
            text = " ".join([
                str(ent.get("name", "")),
                str(ent.get("description", "")),
                " ".join(ent.get("labels", []))
            ]).lower()
            if any(kw in text for kw in keywords):
                filtered.append(ent)
        return filtered

    def run(self, prompt: str = None) -> str:
        # Query all relevant entity types
        result = {}
        # Threat Actors
        threat_actors = self.tool_functions["get_threat_actors"](limit=100)
        result["threat_actors"] = self._filter_entities(threat_actors)
        # Malware
        malware = self.tool_functions["get_entities"](entity_type="Malware", limit=100)
        result["malware"] = self._filter_entities(malware)
        # Attack Patterns
        attack_patterns = self.tool_functions["get_entities"](entity_type="Attack-Pattern", limit=100)
        result["attack_patterns"] = self._filter_entities(attack_patterns)
        # Campaigns
        campaigns = self.tool_functions["get_entities"](entity_type="Campaign", limit=100)
        result["campaigns"] = self._filter_entities(campaigns)
        return json.dumps(result) 
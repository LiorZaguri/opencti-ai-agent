from agents.base import BaseAgent
import json

class ThreatFilteringAgent(BaseAgent):
    def __init__(self):
        system_message = (
            "You are ThreatFilteringAgent. Your job is to receive lists of malware and indicators, "
            "filter and rank them by relevance to the company profile (using keywords in name, description, labels, etc.), "
            "and output the top 10 most relevant threats as a JSON list."
        )
        super().__init__(
            name="ThreatFilteringAgent",
            system_message=system_message,
            tools=[]
        )

    def run(self, threat_data: dict, company_profile: dict) -> str:
        # Combine malware and indicators
        malware = threat_data.get("malware", [])
        indicators = threat_data.get("indicators", [])
        all_threats = malware + indicators
        
        # Build keyword set from profile
        keywords = set()
        for field in ["threat_priority", "tech_stack", "critical_assets", "past_incidents", "industry", "region"]:
            val = company_profile.get(field)
            if isinstance(val, list):
                keywords.update([v.lower() for v in val])
            elif isinstance(val, str):
                keywords.add(val.lower())
        
        # Score each threat by keyword matches and score/confidence
        def score_threat(threat):
            text = " ".join([
                str(threat.get("name", "")),
                str(threat.get("description", "")),
                " ".join(threat.get("labels", []))
            ]).lower()
            match_count = sum(1 for kw in keywords if kw in text)
            score = threat.get("score", threat.get("confidence", 0))
            return (match_count, score)
        
        # Rank and select top 10
        ranked = sorted(all_threats, key=score_threat, reverse=True)
        top_10 = [t for t in ranked if score_threat(t)[0] > 0][:10]
        return json.dumps(top_10) 
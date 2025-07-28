from agents.base import BaseAgent
import json
from datetime import datetime

class ThreatFilteringAgent(BaseAgent):
    def __init__(self):
        system_message = (
            "You are ThreatFilteringAgent. Your job is to receive lists of threat actors, malware, attack patterns, and campaigns, "
            "filter and rank them by relevance to the company profile (using keywords in name, description, labels, etc.), score, and recency, "
            "and output the top 10 most relevant threats as a JSON list."
        )
        super().__init__(
            name="ThreatFilteringAgent",
            system_message=system_message,
            tools=[]
        )

    def run(self, threat_data: dict, company_profile: dict) -> str:
        # Combine all threat types
        all_threats = []
        for key in ["threat_actors", "malware", "attack_patterns", "campaigns"]:
            all_threats.extend(threat_data.get(key, []))
        
        # Build keyword set from profile
        keywords = set()
        for field in ["threat_priority", "tech_stack", "critical_assets", "past_incidents", "industry", "region"]:
            val = company_profile.get(field)
            if isinstance(val, list):
                keywords.update([v.lower() for v in val])
            elif isinstance(val, str):
                keywords.add(val.lower())

        # Score each threat by keyword matches, score/confidence, and recency
        def score_threat(threat):
            text = " ".join([
                str(threat.get("name", "")),
                str(threat.get("description", "")),
                " ".join(threat.get("labels", []))
            ]).lower()
            match_count = sum(1 for kw in keywords if kw in text)
            score = threat.get("score", threat.get("confidence", 0))
            # Recency: prefer more recent (created_at or modified)
            date_str = threat.get("modified") or threat.get("created_at")
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00")) if date_str else datetime.min
            except Exception:
                dt = datetime.min
            return (match_count, score, dt)

        # Rank and select top 10
        ranked = sorted(all_threats, key=score_threat, reverse=True)
        top_10 = [t for t in ranked if score_threat(t)[0] > 0][:10]
        return json.dumps(top_10) 
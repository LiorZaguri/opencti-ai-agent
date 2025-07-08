from agents.base import BaseAgent
import json

class ThreatEnrichmentAgent(BaseAgent):
    def __init__(self):
        system_message = (
            "You are ThreatEnrichmentAgent. Your job is to receive the top 10 threats, "
            "enrich each with public information (e.g., MITRE ATT&CK, security blogs), and provide recommendations for mitigation and response. "
            "Output a structured, human-readable summary for each threat."
        )
        super().__init__(
            name="ThreatEnrichmentAgent",
            system_message=system_message,
            tools=[]
        )

    def run(self, top_threats: list) -> str:
        """
        Receives the top 10 threats, enriches each, and returns a structured summary per threat.
        """
        llm_prompt = (
            f"Top 10 threats: {json.dumps(top_threats)}\n"
            "For each threat, enrich with public information (e.g., MITRE ATT&CK, security blogs) and provide recommendations for mitigation and response. "
            "Output a structured, human-readable summary for each threat."
        )
        return super().run(llm_prompt) 
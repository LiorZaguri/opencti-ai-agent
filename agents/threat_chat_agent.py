from agents.base import BaseAgent
import json

class ThreatChatAgent(BaseAgent):
    def __init__(self, threat: dict, company_profile: dict):
        system_message = (
            "You are a cybersecurity assistant. Answer questions and provide recommendations about the following threat in the context of the given company profile. "
            "Be specific, actionable, and clear. If the question is not about this threat, politely redirect the user.\n"
            f"Threat details: {json.dumps(threat)}\n"
            f"Company profile: {json.dumps(company_profile)}"
        )
        super().__init__(
            name="ThreatChatAgent",
            system_message=system_message,
            tools=[]
        )

    def run(self, user_message: str) -> str:
        return super().run(user_message) 
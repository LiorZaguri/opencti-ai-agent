from agents.base import BaseAgent
import json

class ThreatEnrichmentAgent(BaseAgent):
    def __init__(self):
        system_message = (
            "You are ThreatEnrichmentAgent, an expert in cyber threat intelligence and security analysis. "
            "Your job is to enrich threat data with comprehensive intelligence including recent attack patterns, "
            "Indicators of Compromise (IOCs), specific mitigation strategies, and detection methods. "
            "For each threat, include a brief 'Detection Trigger' section explaining what about the company profile triggered this threat detection. "
            "Provide actionable intelligence that security teams can use immediately. "
            "IMPORTANT: You must analyze ALL threats completely. Do not cut off your analysis or use phrases like 'continued for other threats'."
        )
        super().__init__(
            name="ThreatEnrichmentAgent",
            system_message=system_message,
            tools=[]
        )

    def run(self, top_threats: list) -> str:
        """
        Receives the top threats and enriches them with comprehensive threat intelligence.
        """
        # Limit the number of threats to prevent token overflow
        max_threats = min(len(top_threats), 10)  # Limit to 10 threats max
        threats_to_analyze = top_threats[:max_threats]
        
        llm_prompt = (
            f"Analyze the following {len(threats_to_analyze)} threats and provide comprehensive enrichment for EACH ONE:\n\n"
            f"Threats to analyze: {json.dumps([t.get('name', 'Unknown') for t in threats_to_analyze])}\n\n"
            "For EACH threat, provide the following sections (be concise but complete):\n"
            "1. **Detection Trigger**: What about the company profile triggered this threat detection\n"
            "2. **Recent Attack Patterns**: Latest TTPs and attack methods\n"
            "3. **MITRE ATT&CK Mapping**: Specific techniques and tactics\n"
            "4. **Indicators of Compromise (IOCs)**: File hashes, IP addresses, domains, etc.\n"
            "5. **Targeting Analysis**: Who this threat typically targets and why\n"
            "6. **Attack Lifecycle**: How this threat operates from initial access to impact\n"
            "7. **Detection Methods**: How to detect this threat in your environment\n"
            "8. **Mitigation Strategies**: Specific steps to defend against this threat\n"
            "9. **Incident Response**: What to do if you detect this threat\n"
            "10. **Risk Assessment**: Likelihood and potential impact for this specific company\n\n"
            "Format each threat analysis with markdown headers like:\n"
            "### **1. [Threat Name]**\n"
            "**Detection Trigger**: [explanation]\n"
            "#### **Recent Attack Patterns**:\n"
            "#### **MITRE ATT&CK Mapping**:\n"
            "#### **IOCs**:\n"
            "#### **Targeting Analysis**:\n"
            "#### **Attack Lifecycle**:\n"
            "#### **Detection Methods**:\n"
            "#### **Mitigation Strategies**:\n"
            "#### **Incident Response**:\n"
            "#### **Risk Assessment**:\n"
            "---\n\n"
            "CRITICAL: You must complete the analysis for ALL threats. Do not use phrases like 'continued for other threats' or 'let me know if you'd like the full analysis'. "
            "Provide complete analysis for each threat in the list."
        )
        return super().run(llm_prompt) 
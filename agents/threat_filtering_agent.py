from agents.base import BaseAgent
import json
from datetime import datetime

class ThreatFilteringAgent(BaseAgent):
    def __init__(self):
        system_message = (
            "You are ThreatFilteringAgent, an AI expert in cyber threat intelligence and risk assessment. "
            "Your job is to analyze comprehensive threat data against company profiles and determine which threats are most relevant. "
            "You should consider factors like: industry targeting, technology stack vulnerabilities, critical assets, "
            "geographic region, company size, past security incidents, threat actor motivations, "
            "vulnerability exposure, infrastructure risks, and attack patterns. "
            "Provide intelligent, contextual analysis rather than simple keyword matching. "
            "Consider all threat intelligence entities: threat actors, malware, attack patterns, campaigns, "
            "intrusion sets, tools, vulnerabilities, infrastructure, and threat reports."
        )
        super().__init__(
            name="ThreatFilteringAgent",
            system_message=system_message,
            tools=[]
        )

    def run(self, threat_data: dict, company_profile: dict) -> str:
        # Combine all threat types - now including additional analyst-relevant entities
        all_threats = []
        for entity_type, threats in threat_data.items():
            if isinstance(threats, list):
                all_threats.extend(threats)
        # Smart pre-filtering
        pre_filtered = self._smart_pre_filter(all_threats, company_profile)
        analysis_prompt = self._build_analysis_prompt(pre_filtered, company_profile)
        analysis_result = super().run(analysis_prompt)
        parsed_result = self._parse_ai_analysis(analysis_result, pre_filtered)  # Use pre_filtered, not all_threats
        return json.dumps(parsed_result)
    
    def _smart_pre_filter(self, threats: list, company_profile: dict) -> list:
        """
        Smart pre-filtering to reduce the number of threats sent to AI analysis.
        Uses efficient scoring to select only the most promising candidates.
        """
        # Build comprehensive keyword set from company profile
        keywords = set()
        for field in ["threat_priority", "tech_stack", "critical_assets", "past_incidents", "industry", "region"]:
            val = company_profile.get(field)
            if isinstance(val, list):
                keywords.update([v.lower() for v in val])
            elif isinstance(val, str):
                keywords.add(val.lower())

        # Score each threat using multiple factors
        scored_threats = []
        for threat in threats:
            score = self._calculate_pre_filter_score(threat, keywords, company_profile)
            if score > 0:  # Only include threats with some relevance
                scored_threats.append((score, threat))
        
        # Sort by score and take top candidates for AI analysis
        scored_threats.sort(key=lambda x: x[0], reverse=True)
        pre_filtered = [threat for score, threat in scored_threats[:100]]  # Top 100 for AI analysis
        
        return pre_filtered
    
    def _calculate_pre_filter_score(self, threat: dict, keywords: set, company_profile: dict) -> float:
        """
        Calculate a pre-filter score based on multiple factors.
        Higher score = more likely to be relevant for AI analysis.
        """
        threat_text = " ".join([
            str(threat.get("name", "")),
            str(threat.get("description", "")),
            " ".join(threat.get("labels", []))
        ]).lower()
        
        score = 0.0
        
        # Factor 1: Keyword matches (weight: 80%) - Most important
        threat_terms = threat_text.split()
        keyword_matches = sum(1 for term in threat_terms if any(kw in term or term in kw for kw in keywords))
        
        # For minimal profiles, require at least some keyword matches
        if len(keywords) > 0 and keyword_matches == 0:
            return 0.0  # No score if no keyword matches and we have keywords
        
        # Require minimum keyword matches for any score (reduced from 2 to 1)
        if keyword_matches < 1:  # Require at least 1 keyword match
            return 0.0
        
        score += keyword_matches * 0.8
        
        # Factor 2: Threat score/confidence (weight: 15%) - Only if we have keyword matches
        if keyword_matches >= 1:
            threat_score = threat.get("score", threat.get("confidence", 0))
            if isinstance(threat_score, (int, float)):
                score += min(threat_score / 100.0, 1.0) * 0.15
        
        # Factor 3: Recency (weight: 5%) - Only if we have keyword matches
        if keyword_matches >= 1:
            date_str = threat.get("modified") or threat.get("created_at")
            try:
                if date_str:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    days_old = (datetime.now() - dt).days
                    recency_score = max(0, 1 - (days_old / 365))  # Prefer threats from last year
                    score += recency_score * 0.05
            except Exception:
                pass
        
        return score
    
    def _build_analysis_prompt(self, threats: list, company_profile: dict) -> str:
        """Build a comprehensive prompt for AI analysis with risk scoring."""
        
        # Format company profile for analysis
        profile_summary = f"""
Company Profile:
- Industry: {company_profile.get('industry', 'Unknown')}
- Region: {company_profile.get('region', 'Unknown')}
- Technology Stack: {', '.join(company_profile.get('tech_stack', []))}
- Critical Assets: {', '.join(company_profile.get('critical_assets', []))}
- Past Incidents: {', '.join(company_profile.get('past_incidents', []))}
- Threat Priority: {', '.join(company_profile.get('threat_priority', []))}
- Compliance: {', '.join(company_profile.get('compliance', []))}
- Security Maturity: {company_profile.get('security_maturity', 'Unknown')}
- Risk Tolerance: {company_profile.get('risk_tolerance', 'Unknown')}
- Has Internal SOC: {company_profile.get('has_internal_soc', False)}
"""
        
        # Format threats for analysis (now much fewer threats)
        threats_summary = []
        for i, threat in enumerate(threats):
            threat_info = f"""
Threat {i+1}: {threat.get('name', 'Unknown')}
- Type: {threat.get('entity_type', 'Unknown')}
- Description: {threat.get('description', 'No description')}
- Labels: {', '.join(threat.get('labels', []))}
- Score: {threat.get('score', threat.get('confidence', 0))}
- Modified: {threat.get('modified', threat.get('created_at', 'Unknown'))}
"""
            threats_summary.append(threat_info)
        
        return f"""
You are an expert cyber threat intelligence analyst. Analyze the following threats against this company profile and provide comprehensive risk assessment.

{profile_summary}

Available Threats (Pre-filtered for relevance):
{''.join(threats_summary)}

CRITICAL: You are analyzing threats for a SPECIFIC company. Only include threats that have DIRECT, SPECIFIC, and UNIQUE connections to THIS company's profile. Generic threats that could apply to any company should be EXCLUDED.

STRICT FILTERING RULES:
1. **NO GENERIC THREATS**: If a threat could apply to any company with basic security, EXCLUDE it
2. **NO SPECULATIVE REASONING**: If reasoning contains "could be", "might be", "if", "maybe", EXCLUDE it
3. **REQUIRE SPECIFIC EVIDENCE**: Must have concrete evidence this threat targets companies like this one
4. **UNIQUE CHARACTERISTICS**: Threat must target something UNIQUE about this company, not generic characteristics
5. **INDUSTRY SPECIFIC**: Threat must specifically target this industry, not generic attacks
6. **TECHNOLOGY SPECIFIC**: Threat must exploit specific technologies the company uses, not generic vulnerabilities

EXAMPLES OF WHAT TO EXCLUDE:
- "Basic computers make it vulnerable to phishing" → EXCLUDE (too generic)
- "Lack of SOC makes it vulnerable to RMM attacks" → EXCLUDE (too generic)
- "Low security maturity makes it vulnerable to unpatched vulnerabilities" → EXCLUDE (too generic)
- "Could be targeted by malware" → EXCLUDE (speculative)

EXAMPLES OF WHAT TO INCLUDE:
- Threat specifically targets "Local Services" industry → INCLUDE
- Threat exploits specific technology the company uses → INCLUDE
- Threat operates specifically in "Small Town" regions → INCLUDE
- Threat targets companies with "Local Business License" compliance → INCLUDE

Your analysis should consider:

1. **Threat Relevance**: Does this threat SPECIFICALLY target this company's UNIQUE characteristics?
2. **Attack Likelihood**: Is there CONCRETE EVIDENCE this threat targets companies like this one?
3. **Potential Impact**: What would be the business impact if this threat successfully attacks?
4. **Mitigation Difficulty**: How easy/hard would it be for this company to defend against this threat?
5. **Threat Sophistication**: How advanced is this threat actor/malware?
6. **Geographic Relevance**: Does this threat operate specifically in the company's region?
7. **Industry Targeting**: Does this threat specifically target this industry?
8. **Technology Targeting**: Does this threat exploit technologies the company ACTUALLY uses?

For each threat, assess:
- **Relevance Score** (1-10): How relevant is this threat to this specific company? (Only 8+ if truly relevant)
- **Attack Likelihood** (High/Medium/Low): Probability of being targeted
- **Potential Impact** (High/Medium/Low): Business impact if attacked
- **Risk Level** (High/Medium/Low): Overall risk assessment
- **Confidence** (High/Medium/Low): How confident are you in this assessment?

Output your analysis as a JSON object with this structure:
{{
    "threats": [
        {{
            "threat_index": <index of threat in original list>,
            "name": "<threat name>",
            "relevance_score": <8-10 only if truly relevant>,
            "attack_likelihood": "High|Medium|Low",
            "potential_impact": "High|Medium|Low", 
            "risk_level": "High|Medium|Low",
            "confidence": "High|Medium|Low",
            "reasoning": "<detailed explanation of SPECIFIC evidence why this threat is relevant to this specific company>",
            "targeting_factors": ["<specific factor1>", "<specific factor2>", ...],
            "mitigation_difficulty": "Easy|Medium|Hard",
            "threat_sophistication": "Low|Medium|High"
        }}
    ],
    "analysis_summary": "<brief overview of the threat landscape for this company>",
    "overall_risk_assessment": "High|Medium|Low",
    "key_vulnerabilities": ["<vulnerability1>", "<vulnerability2>", ...],
    "recommended_focus_areas": ["<area1>", "<area2>", ...]
}}

REMEMBER: It's better to return NO threats than to return generic ones. Only include threats with clear, specific, and direct connections to this company's UNIQUE profile characteristics.
"""
    
    def _parse_ai_analysis(self, analysis_result: str, original_threats: list) -> dict:
        """Parse the AI analysis result and extract the top threats."""
        try:
            # Debug: Print the pre-filtered threat names
            print("Pre-filtered threat names:", [t.get("name") for t in original_threats])
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{.*\}', analysis_result, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
            else:
                parsed = json.loads(analysis_result)
            
            # Extract the top threats based on AI ranking
            ai_threats = parsed.get("threats", [])
            top_threats = []
            threat_objects = []
            reasoning = {}
            
            for ai_threat in ai_threats[:10]:  # Top 10
                print(f"AI returned index: {ai_threat.get('threat_index')}, name: {ai_threat.get('name')}")
                threat_index = ai_threat.get("threat_index", 0) - 1  # Adjust for 1-based index
                if 0 <= threat_index < len(original_threats):
                    threat = original_threats[threat_index]
                    top_threats.append(ai_threat)
                    threat_objects.append(threat)
                    # Store the AI reasoning using the actual threat name from the original threat
                    threat_name = threat.get("name", "Unknown")
                    ai_reasoning = ai_threat.get("reasoning", f"AI analysis determined that {threat_name} is relevant to this company.")
                    reasoning[threat_name] = {
                        "matched_keywords": ai_threat.get("targeting_factors", []),
                        "relevance_score": ai_threat.get("relevance_score", 0),
                        "confidence": ai_threat.get("confidence", "Medium"),
                        "risk_level": ai_threat.get("risk_level", "Medium"),
                        "reason": ai_reasoning
                    }
            print("Mapped threat objects:", [t.get("name") for t in threat_objects])
            return {
                "threats": top_threats,  # AI summary
                "threat_objects": threat_objects,  # Actual OpenCTI objects
                "reasoning": reasoning,
                "analysis_summary": parsed.get("analysis_summary", "")
            }
        except Exception as e:
            # If parsing fails, fall back to basic analysis
            return self._fallback_analysis(original_threats, {})
    
    def _fallback_analysis(self, threats: list, company_profile: dict) -> str:
        """Fallback analysis using basic scoring when AI parsing fails."""
        # Simple scoring based on company profile keywords
        keywords = set()
        for field in ["threat_priority", "tech_stack", "critical_assets", "past_incidents", "industry", "region"]:
            val = company_profile.get(field)
            if isinstance(val, list):
                keywords.update([v.lower() for v in val])
            elif isinstance(val, str):
                keywords.add(val.lower())

        def score_threat(threat):
            threat_text = " ".join([
                str(threat.get("name", "")),
                str(threat.get("description", "")),
                " ".join(threat.get("labels", []))
            ]).lower()
            
            # Basic keyword matching as fallback
            threat_terms = threat_text.split()
            match_count = sum(1 for term in threat_terms if any(kw in term or term in kw for kw in keywords))
            
            score = threat.get("score", threat.get("confidence", 0))
            date_str = threat.get("modified") or threat.get("created_at")
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00")) if date_str else datetime.min
            except Exception:
                dt = datetime.min
            return (match_count, score, dt)

        ranked = sorted(threats, key=score_threat, reverse=True)
        top_10 = [t for t in ranked if score_threat(t)[0] > 0][:10]
        
        reasoning = {}
        for threat in top_10:
            threat_name = threat.get("name", "Unknown")
            reasoning[threat_name] = {
                "matched_keywords": [],
                "relevance_score": score_threat(threat)[0],
                "confidence": "Low",
                "risk_level": "Medium",
                "reason": "Fallback analysis: Basic keyword matching was used due to AI parsing issues."
            }
        
        return json.dumps({
            "threats": top_10,
            "reasoning": reasoning,
            "analysis_summary": "Fallback analysis used due to AI parsing issues."
        }) 
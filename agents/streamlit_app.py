import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
import json
from agents.data_retrieval_agent import DataRetrievalAgent
from agents.threat_filtering_agent import ThreatFilteringAgent
from agents.threat_enrichment_agent import ThreatEnrichmentAgent

st.set_page_config(page_title="Threat Intelligence Pipeline", layout="wide")
st.title("🔎 Threat Intelligence Automation Pipeline")

# --- Profile selection UI ---
profile_options = {
    "SecureHealth Corp (with insights)": "data/company_profile.json",
    "Clear Manufacturing Inc (no relevant threats)": "data/company_profile_clear.json"
}

if 'selected_profile' not in st.session_state:
    st.session_state.selected_profile = list(profile_options.keys())[0]

selected_profile = st.selectbox(
    "Select Company Profile:",
    options=list(profile_options.keys()),
    index=list(profile_options.keys()).index(st.session_state.selected_profile)
)

if selected_profile != st.session_state.selected_profile:
    st.session_state.selected_profile = selected_profile
    st.rerun()

def load_company_profile(path):
    with open(path, "r") as f:
        return json.load(f)

company_profile = load_company_profile(profile_options[st.session_state.selected_profile])

# Helper to clean and parse LLM output
def parse_llm_json(output):
    if not isinstance(output, str):
        return output
    cleaned = output.strip()
    # Remove markdown code fences
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    if cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except Exception:
        return None

# Initialize agents
@st.cache_resource(show_spinner=False)
def get_agents():
    return (
        DataRetrievalAgent(),
        ThreatFilteringAgent(),
        ThreatEnrichmentAgent()
    )

data_agent, filter_agent, enrich_agent = get_agents()

st.header("1. Company Profile")

col1, col2 = st.columns(2)
with col1:
    st.subheader("General Info")
    st.write(f"**Company Name:** {company_profile['company_name']}")
    st.write(f"**Industry:** {company_profile['industry'].capitalize()}")
    st.write(f"**Region:** {company_profile['region']}")
    st.write(f"**Organization Size:** {company_profile['organization_size'].capitalize()}")
    st.write(f"**Business Model:** {company_profile['business_model']}")
    st.write(f"**Security Maturity:** {company_profile['security_maturity'].capitalize()}")
    st.write(f"**Risk Tolerance:** {company_profile['risk_tolerance'].capitalize()}")
    st.write(f"**Internal SOC:** {'Yes' if company_profile['has_internal_soc'] else 'No'}")
    st.write(f"**Preferred Language:** {company_profile['preferred_language']}")

with col2:
    st.subheader("Technology & Compliance")
    st.write("**Tech Stack:**")
    st.markdown(", ".join(f"`{tech}`" for tech in company_profile["tech_stack"]))
    st.write("**Compliance:**")
    st.markdown(", ".join(f"`{c}`" for c in company_profile["compliance"]))
    st.write("**Critical Assets:**")
    st.markdown(", ".join(f"`{asset}`" for asset in company_profile["critical_assets"]))
    st.write("**Threat Priorities:**")
    st.markdown(", ".join(f"`{t}`" for t in company_profile["threat_priority"]))
    st.write("**Past Incidents:**")
    st.markdown(", ".join(f"`{i}`" for i in company_profile["past_incidents"]))

st.subheader("Operating Hours")
op = company_profile["operating_hours"]
st.write(f"**Timezone:** {op['timezone']}")
st.write(f"**Business Days:** {', '.join(op['business_days'])}")
st.write(f"**Open Hours:** {op['open_hours'][0]} - {op['open_hours'][1]}")

if st.button("Run Threat Intelligence Pipeline", type="primary"):
    with st.spinner("Retrieving threats from OpenCTI..."):
        raw_threats_str = data_agent.run()
        raw_threats = parse_llm_json(raw_threats_str)
    st.subheader("2. Raw Threat Entities (from OpenCTI)")
    if raw_threats is not None:
        st.json(raw_threats)
    else:
        st.warning("Could not parse threats as JSON. Showing raw output:")
        st.code(raw_threats_str)

    with st.spinner("Filtering and ranking threats..."):
        filtered_threats_str = filter_agent.run(
            threat_data=raw_threats if isinstance(raw_threats, dict) else {},
            company_profile=company_profile
        )
        filtered_threats = parse_llm_json(filtered_threats_str)
    st.subheader("3. Top 10 Most Relevant Threats")
    if filtered_threats is not None and len(filtered_threats) > 0:
        # Enrich all threats at once
        with st.spinner("Enriching all threats and generating recommendations..."):
            enriched_summaries_str = enrich_agent.run(top_threats=filtered_threats)
            try:
                enriched_summaries = json.loads(enriched_summaries_str)
            except Exception:
                enriched_summaries = enriched_summaries_str
        # Two-column layout
        col_left, col_right = st.columns([1, 3])
        with col_left:
            st.markdown("**Select a threat to view details and chat:**")
            threat_names = [t.get("name", f"Threat {i+1}") for i, t in enumerate(filtered_threats)]
            selected_idx = st.radio("Threats", options=list(range(len(threat_names))), format_func=lambda i: threat_names[i], key="threat_radio")
        with col_right:
            threat = filtered_threats[selected_idx]
            st.markdown(f"### Enrichment & Recommendations for: {threat.get('name', 'Unknown')}")
            # Show enrichment for the selected threat
            if isinstance(enriched_summaries, list) and len(enriched_summaries) > selected_idx:
                st.write(enriched_summaries[selected_idx])
            elif isinstance(enriched_summaries, dict) and threat.get('name') in enriched_summaries:
                st.write(enriched_summaries[threat.get('name')])
            else:
                st.write(enriched_summaries)
            st.markdown("---")
            st.markdown("**Chat with the AI about this threat:**")
            from agents.threat_chat_agent import ThreatChatAgent
            chat_key = f"chat_history_{threat.get('name', str(selected_idx))}"
            if chat_key not in st.session_state:
                st.session_state[chat_key] = []
            # Display chat history
            for msg in st.session_state[chat_key]:
                with st.chat_message(msg["role"]):
                    st.write(msg["content"])
            # Chat input
            user_input = st.chat_input(f"Ask about {threat.get('name', 'this threat')}...", key=f"input_{selected_idx}")
            if user_input:
                st.session_state[chat_key].append({"role": "user", "content": user_input})
                with st.chat_message("user"):
                    st.write(user_input)
                with st.spinner("AI is thinking..."):
                    chat_agent = ThreatChatAgent(threat, company_profile)
                    ai_reply = chat_agent.run(user_input)
                st.session_state[chat_key].append({"role": "assistant", "content": ai_reply})
                with st.chat_message("assistant"):
                    st.write(ai_reply)
    elif filtered_threats is not None and len(filtered_threats) == 0:
        st.success("No relevant threats found for this company profile.")
    else:
        st.warning("Could not parse filtered threats as JSON. Showing raw output:")
        st.code(filtered_threats_str)

else:
    st.info("Click the button above to run the full threat intelligence pipeline.") 
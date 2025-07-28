import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
import json
import copy
from agents.data_retrieval_agent import DataRetrievalAgent
from agents.threat_filtering_agent import ThreatFilteringAgent
from agents.threat_enrichment_agent import ThreatEnrichmentAgent

st.set_page_config(page_title="Threat Intelligence Pipeline", layout="wide")

# Profile selection
profile_options = {
    "SecureHealth Corp (with insights)": "data/company_profile.json",
    "Clear Manufacturing Inc (no relevant threats)": "data/company_profile_clear.json"
}

if 'selected_profile' not in st.session_state:
    st.session_state.selected_profile = list(profile_options.keys())[0]

if 'edited_profile' not in st.session_state:
    st.session_state.edited_profile = None

def load_company_profile(path):
    with open(path, "r") as f:
        return json.load(f)

def save_profile(profile_data, file_path):
    with open(file_path, 'w') as f:
        json.dump(profile_data, f, indent=2)

# Load selected profile
company_profile = load_company_profile(profile_options[st.session_state.selected_profile])

# Add sidebar styling
st.markdown("""
    <style>
    /* Global Styles */
    .main .block-container {
        max-width: 1200px;
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
    }

    /* AI Theme Colors - Purple */
    :root {
        --ai-primary: rgba(107, 70, 193, 0.2);
        --ai-secondary: rgba(139, 92, 246, 0.15);
        --ai-accent: rgba(167, 139, 250, 0.1);
        --ai-border: rgba(139, 92, 246, 0.2);
        --ai-subtle: rgba(139, 92, 246, 0.05);
    }

    /* Modern Card Styling with AI aesthetics */
    .stCard {

    }

    .stCard:hover {
        border-color: rgba(139, 92, 246, 0.3);
        transform: translateY(-2px);
    }

    /* Section Headers with AI style */
    .section-header {
        color: #E0E0E0;
        font-size: 1.3rem;
        font-weight: 600;
        margin: 2rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--ai-border);
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .section-header::before {
        content: "🧠";
        font-size: 1.2rem;
    }

    /* AI-styled Stats Cards */
    .stat-card {
        text-align: center;
        padding: 1.2rem;
        background: linear-gradient(165deg, 
            rgba(30, 25, 40, 0.97) 0%,
            rgba(17, 23, 33, 0.97) 100%);
        border-radius: 12px;
        border: 1px solid var(--ai-border);
        transition: all 0.3s ease;
        height: 100%;
        margin-bottom: 1rem;
    }

    .stat-card:hover {
        transform: translateY(-2px);
        border-color: rgba(139, 92, 246, 0.3);
        background: linear-gradient(165deg, 
            rgba(35, 30, 45, 0.97) 0%,
            rgba(22, 28, 38, 0.97) 100%);
    }

    .stat-value {
        font-size: 1.5rem;
        font-weight: bold;
        margin: 0.5rem 0;
        color: #E0E0E0;
    }

    .stat-label {
        color: #9E9E9E;
        font-size: 0.9rem;
    }

    /* AI-styled Tags */
    .tag {
        background: var(--ai-subtle);
        color: #E0E0E0;
        padding: 0.4rem 1rem;
        border-radius: 20px;
        display: inline-block;
        margin: 0.3rem;
        font-size: 0.9rem;
        border: 1px solid var(--ai-border);
        transition: all 0.2s ease;
    }

    .tag:hover {
        background: var(--ai-primary);
        transform: translateY(-1px);
        border-color: rgba(139, 92, 246, 0.3);
    }

    /* Threat Items with AI styling */
    .threat-item {
        display: flex;
        align-items: center;
        padding: 0.8rem;
        margin-bottom: 0.5rem;
        border-radius: 8px;
        background: var(--ai-subtle);
        border: 1px solid var(--ai-border);
        transition: all 0.2s ease;
    }

    .threat-item:hover {
        background: var(--ai-primary);
        border-color: rgba(139, 92, 246, 0.3);
    }

    /* Status Indicators */
    .status-indicator {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 8px;
    }
    .status-high { 
        background-color: #dc2626;
    }
    .status-medium { 
        background-color: #f59e0b;
    }
    .status-low { 
        background-color: #10b981;
    }

    /* Column styling */
    [data-testid="column"] {
        background: transparent;
        border-radius: 12px;
        padding: 0.5rem !important;
        margin: 0 0.5rem !important;
    }

    /* Streamlit selectbox AI styling */
    .stSelectbox > div > div {
        background: linear-gradient(165deg, 
            rgba(30, 25, 40, 0.97) 0%,
            rgba(17, 23, 33, 0.97) 100%) !important;
        border: 1px solid var(--ai-border) !important;
        border-radius: 8px !important;
    }

    .stSelectbox > div > div:hover {
        border-color: rgba(139, 92, 246, 0.3) !important;
    }

    /* AI-styled Button */
    .stButton > button {
        background: linear-gradient(165deg, #8B5CF6, #6B46C1) !important;
        color: white !important;
        border: none !important;
        padding: 0.6rem 1.2rem !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 12px rgba(139, 92, 246, 0.2) !important;
    }

    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 16px rgba(139, 92, 246, 0.3) !important;
    }

    /* Title styling */
    h1 {
        background: linear-gradient(90deg, #8B5CF6, #A78BFA);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 700 !important;
        margin-bottom: 2rem !important;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: rgba(30, 25, 40, 0.97);
        padding: 2rem 1rem;
        border-right: 1px solid var(--ai-border);
    }
    
    section[data-testid="stSidebar"] .block-container {
        padding-top: 1rem !important;
    }

    /* Sidebar Header */
    .sidebar-header {
        color: #E0E0E0;
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--ai-border);
    }

    /* Sidebar Section */
    .sidebar-section {

    }

    /* Sidebar Info Text */
    .sidebar-info {
        color: #9E9E9E;
        font-size: 0.9rem;
        margin: 0.5rem 0;
    }

    /* Sidebar Stats */
    .sidebar-stat {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.5rem 0;
        border-bottom: 1px solid var(--ai-border);
    }

    .sidebar-stat:last-child {
        border-bottom: none;
    }

    .sidebar-stat-label {
        color: #E0E0E0;
        font-size: 0.9rem;
    }

    .sidebar-stat-value {
        color: #A78BFA;
        font-weight: 500;
    }

    /* Edit Mode Styles */
    .edit-section {
        background: var(--ai-subtle);
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }

    .edit-header {
        color: #A78BFA;
        font-size: 0.9rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }

    /* Edit buttons */
    .stButton.edit-button button {
        background: transparent !important;
        border: 1px solid var(--ai-border) !important;
        color: #A78BFA !important;
    }

    .stButton.save-button button {
        background: linear-gradient(165deg, #8B5CF6, #6B46C1) !important;
    }

    .stButton.reset-button button {
        background: transparent !important;
        border: 1px solid #dc2626 !important;
        color: #dc2626 !important;
    }

    /* Dashboard Grid Layout */
    .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1rem;
        margin: 1rem 0;
    }

    /* Card Variations */
    .card-tech {
        grid-column: span 1;
        background: linear-gradient(165deg, rgba(30, 25, 40, 0.97), rgba(17, 23, 33, 0.97));
    }

    .card-assets {
        grid-column: span 1;
        background: linear-gradient(165deg, rgba(35, 30, 45, 0.97), rgba(22, 28, 38, 0.97));
    }

    .card-compliance {
        grid-column: span 1;
        background: linear-gradient(165deg, rgba(40, 35, 50, 0.97), rgba(27, 33, 43, 0.97));
    }

    .card-threats {
        grid-column: span 1;
        background: linear-gradient(165deg, rgba(45, 40, 55, 0.97), rgba(32, 38, 48, 0.97));
    }

    /* Unified Card Style */
    .dashboard-card {
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 1rem;
        height: 100%;
        transition: all 0.2s ease;
    }

    .dashboard-card:hover {
        border-color: rgba(139, 92, 246, 0.3);
        transform: translateY(-2px);
    }

    /* Card Header */
    .card-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 0.8rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--ai-border);
    }

    .card-header h4 {
        margin: 0;
        color: #A78BFA;
        font-size: 0.9rem;
        font-weight: 600;
    }

    .card-header .icon {
        color: #A78BFA;
        font-size: 1rem;
    }

    /* Tag Cloud */
    .tag-cloud {
        display: flex;
        flex-wrap: wrap;
        gap: 0.3rem;
    }

    .tag-cloud .tag {
        padding: 0.2rem 0.5rem;
        font-size: 0.75rem;
        border-radius: 4px;
        margin: 0;
    }

    /* Threat List */
    .threat-list {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        padding-top: 0.5rem;
    }

    /* Threat List Item Styling */
    .threat-item-card {
        background: transparent;
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 0.75rem 1rem;
        display: flex;
        flex-direction: column;
        gap: 0.2rem;
        transition: all 0.2s ease;
        margin-bottom: 0.5rem; /* For spacing */
    }

    .threat-item-card:hover {
        border-color: rgba(139, 92, 246, 0.4);
        background: var(--ai-subtle);
    }
    
    .threat-header {
        display: flex;
        align-items: center;
        gap: 0.6rem;
    }

    .threat-title {
        font-weight: 600;
        font-size: 0.9rem;
        color: #E0E0E0;
    }

    .threat-subtitle {
        font-size: 0.8rem;
        color: #9E9E9E;
        padding-left: 1.2rem; /* Aligns with title */
    }

    /* Severity Colors */
    .severity-high { color: #ef4444; }
    .severity-medium { color: #f59e0b; }
    .severity-low { color: #10b981; }

    /* Section Container */
    .section-container {
        margin: 0.5rem 0;
    }

    /* Collapsible Section */
    .section-header {
        background: rgba(30, 25, 40, 0.97);
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 0.7rem 1rem;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 0.5rem;
    }

    .section-header:hover {
        border-color: rgba(139, 92, 246, 0.3);
        background: rgba(35, 30, 45, 0.97);
    }

    .section-header .icon {
        color: #A78BFA;
        font-size: 1.1rem;
    }

    .section-header .title {
        color: #E0E0E0;
        font-size: 0.95rem;
        font-weight: 500;
        flex-grow: 1;
    }

    .section-header .count {
        background: var(--ai-subtle);
        color: #A78BFA;
        padding: 0.2rem 0.5rem;
        border-radius: 12px;
        font-size: 0.8rem;
        min-width: 1.5rem;
        text-align: center;
    }

    /* Content Area */
    .section-content {
        background: rgba(25, 20, 35, 0.97);
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 0.8rem;
        margin-top: -0.3rem;
        margin-bottom: 0.5rem;
        display: flex;
        flex-wrap: wrap;
        gap: 0.3rem;
    }

    /* Tags */
    .tag {
        background: var(--ai-subtle);
        color: #E0E0E0;
        padding: 0.3rem 0.6rem;
        border-radius: 4px;
        font-size: 0.8rem;
        display: flex;
        align-items: center;
        gap: 0.3rem;
        border: 1px solid var(--ai-border);
    }

    .tag:hover {
        border-color: rgba(139, 92, 246, 0.3);
        background: rgba(35, 30, 45, 0.97);
    }

    /* Threat Items */
    .threat-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.3rem 0.6rem;
        border-radius: 4px;
        font-size: 0.8rem;
        background: var(--ai-subtle);
        border: 1px solid var(--ai-border);
        width: calc(50% - 0.3rem);
    }

    .threat-item .status {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        flex-shrink: 0;
    }

    .threat-item .name {
        flex-grow: 1;
    }

    .status.high { background: #ef4444; }
    .status.medium { background: #f59e0b; }
    .status.low { background: #10b981; }

    /* Two-column layout for threats */
    .threats-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 0.3rem;
        width: 100%;
    }

    /* Base styles and colors */
    :root {
        --ai-primary: rgba(107, 70, 193, 0.2);
        --ai-secondary: rgba(139, 92, 246, 0.15);
        --ai-accent: rgba(167, 139, 250, 0.1);
        --ai-border: rgba(139, 92, 246, 0.2);
        --ai-subtle: rgba(139, 92, 246, 0.05);
    }

    /* Compact tags */
    .tag {
        background: var(--ai-subtle);
        color: #E0E0E0;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        margin: 0.1rem;
        display: inline-block;
        border: 1px solid var(--ai-border);
    }

    /* Streamlit Expander Customization */
    .streamlit-expanderHeader {
        background: rgba(30, 25, 40, 0.97) !important;
        border: 1px solid var(--ai-border) !important;
        border-radius: 8px !important;
        padding: 0.7rem 1rem !important;
        font-size: 0.95rem !important;
        color: #E0E0E0 !important;
    }

    .streamlit-expanderHeader:hover {
        border-color: rgba(139, 92, 246, 0.3) !important;
        background: rgba(35, 30, 45, 0.97) !important;
    }
    
    .streamlit-expanderContent {
        border: none !important;
        background: transparent !important;
        padding-left: 0.5rem !important;
    }

    /* Threat Items */
    .threat-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        gap: 0.3rem;
        padding: 0.2rem;
    }

    .threat-item {
        display: flex;
        align-items: center;
        gap: 0.4rem;
        padding: 0.3rem 0.5rem;
        background: var(--ai-subtle);
        border: 1px solid var(--ai-border);
        border-radius: 4px;
        font-size: 0.75rem;
    }

    .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        flex-shrink: 0;
    }

    .status-high { background: #ef4444; }
    .status-medium { background: #f59e0b; }
    .status-low { background: #10b981; }

    /* Remove extra padding from main container */
    .main .block-container {
        padding-top: 1rem !important;
        padding-bottom: 1rem !important;
    }

    /* Adjust spacing between sections */
    .stExpander {
        margin-bottom: 0.5rem !important;
    }
    /* Threat Card Grid */
    .threat-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
        gap: 0.75rem;
        padding-top: 0.5rem;
    }

    .threat-card {
        background: var(--ai-subtle);
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 1rem;
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
        transition: all 0.2s ease;
    }

    .threat-card:hover {
        border-color: rgba(139, 92, 246, 0.4);
        transform: translateY(-2px);
        background: var(--ai-primary);
    }

    .threat-header {
        display: flex;
        align-items: center;
        gap: 0.6rem;
    }

    .threat-title {
        font-weight: 600;
        font-size: 0.9rem;
        color: #E0E0E0;
    }

    .threat-subtitle {
        font-size: 0.8rem;
        color: #9E9E9E;
        padding-left: 1.2rem; /* Aligns with title */
    }
    /* Remove duplicate threat styles and implement clean grid */
    .threat-list-grid {
        display: grid;
        grid-template-columns: 1fr;
        gap: 0.75rem;
        padding: 0.5rem 0;
    }

    .threat-item-card {
        background: var(--ai-subtle);
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 1rem;
        display: flex;
        flex-direction: column;
        gap: 0.4rem;
        transition: all 0.2s ease;
    }

    .threat-item-card:hover {
        border-color: rgba(139, 92, 246, 0.4);
        background: var(--ai-primary);
        transform: translateY(-2px);
    }

    .threat-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }

    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        flex-shrink: 0;
    }

    .threat-title {
        font-weight: 500;
        font-size: 0.95rem;
        color: #E0E0E0;
        flex-grow: 1;
    }

    .threat-subtitle {
        font-size: 0.85rem;
        color: #9E9E9E;
        padding-left: 1.5rem;
    }

    .status-high { background: #ef4444; }
    .status-medium { background: #f59e0b; }
    .status-low { background: #10b981; }
    </style>
""", unsafe_allow_html=True)

# Main content
st.markdown("# 🧠 Threat Intelligence Automation Pipeline")

# Sidebar
with st.sidebar:
    st.markdown('<div class="sidebar-header">🧠 AI Pipeline Settings</div>', unsafe_allow_html=True)
    
    # Profile Selection Section
    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("#### Company Profile")
    
    # Add Edit Mode Toggle
    edit_mode = st.toggle("Enable Edit Mode", key="edit_mode")
    
    selected_profile = st.selectbox(
        "Select organization to analyze",
        options=list(profile_options.keys()),
        index=list(profile_options.keys()).index(st.session_state.selected_profile),
        key="profile_selector"
    )

    # Initialize edited profile if needed
    if st.session_state.edited_profile is None or selected_profile != st.session_state.selected_profile:
        st.session_state.edited_profile = copy.deepcopy(company_profile)
    
    if edit_mode:
        st.markdown("### Edit Profile")
        
        # Business Information
        with st.expander("Business Information"):
            st.session_state.edited_profile['business_model'] = st.text_input(
                "Business Model",
                st.session_state.edited_profile['business_model']
            )
            st.session_state.edited_profile['security_maturity'] = st.selectbox(
                "Security Maturity",
                ["basic", "intermediate", "advanced"],
                index=["basic", "intermediate", "advanced"].index(st.session_state.edited_profile['security_maturity'])
            )
            st.session_state.edited_profile['risk_tolerance'] = st.selectbox(
                "Risk Tolerance",
                ["low", "medium", "high"],
                index=["low", "medium", "high"].index(st.session_state.edited_profile['risk_tolerance'])
            )
            st.session_state.edited_profile['has_internal_soc'] = st.checkbox(
                "Has Internal SOC",
                st.session_state.edited_profile['has_internal_soc']
            )

        # Technology Stack
        with st.expander("Technology Stack"):
            tech_stack = st.text_area(
                "Technology Stack (one per line)",
                "\n".join(st.session_state.edited_profile['tech_stack'])
            )
            st.session_state.edited_profile['tech_stack'] = [x.strip() for x in tech_stack.split("\n") if x.strip()]

        # Critical Assets
        with st.expander("Critical Assets"):
            critical_assets = st.text_area(
                "Critical Assets (one per line)",
                "\n".join(st.session_state.edited_profile['critical_assets'])
            )
            st.session_state.edited_profile['critical_assets'] = [x.strip() for x in critical_assets.split("\n") if x.strip()]

        # Compliance Requirements
        with st.expander("Compliance"):
            compliance = st.text_area(
                "Compliance Requirements (one per line)",
                "\n".join(st.session_state.edited_profile['compliance'])
            )
            st.session_state.edited_profile['compliance'] = [x.strip() for x in compliance.split("\n") if x.strip()]

        # Threat Priorities
        with st.expander("Threat Priorities"):
            threat_priority = st.text_area(
                "Threat Priorities (one per line)",
                "\n".join(st.session_state.edited_profile['threat_priority'])
            )
            st.session_state.edited_profile['threat_priority'] = [x.strip() for x in threat_priority.split("\n") if x.strip()]

        # Past Incidents
        with st.expander("Past Incidents"):
            past_incidents = st.text_area(
                "Past Incidents (one per line)",
                "\n".join(st.session_state.edited_profile['past_incidents'])
            )
            st.session_state.edited_profile['past_incidents'] = [x.strip() for x in past_incidents.split("\n") if x.strip()]

        # Save and Reset buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Save Changes", type="primary", use_container_width=True):
                save_profile(st.session_state.edited_profile, profile_options[selected_profile])
                st.success("Profile saved successfully!")
                st.rerun()
        
        with col2:
            if st.button("Reset Changes", type="secondary", use_container_width=True):
                st.session_state.edited_profile = copy.deepcopy(company_profile)
                st.info("Changes reset to original profile.")
                st.rerun()

    # Show current profile info
    else:
        st.markdown('<div class="sidebar-info">Current Profile Statistics:</div>', unsafe_allow_html=True)
        
        # Display key metrics
        st.markdown('<div class="sidebar-stat">'
                    '<span class="sidebar-stat-label">Business Model</span>'
                    f'<span class="sidebar-stat-value">{company_profile["business_model"]}</span>'
                    '</div>', unsafe_allow_html=True)
        
        st.markdown('<div class="sidebar-stat">'
                    '<span class="sidebar-stat-label">Security Maturity</span>'
                    f'<span class="sidebar-stat-value">{company_profile["security_maturity"].capitalize()}</span>'
                    '</div>', unsafe_allow_html=True)
        
        st.markdown('<div class="sidebar-stat">'
                    '<span class="sidebar-stat-label">Risk Tolerance</span>'
                    f'<span class="sidebar-stat-value">{company_profile["risk_tolerance"].capitalize()}</span>'
                    '</div>', unsafe_allow_html=True)
        
        st.markdown('<div class="sidebar-stat">'
                    '<span class="sidebar-stat-label">Internal SOC</span>'
                    f'<span class="sidebar-stat-value">{"Yes" if company_profile["has_internal_soc"] else "No"}</span>'
                    '</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Additional Settings Section (if needed)
    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("#### Pipeline Settings")
    st.checkbox("Enable detailed analysis", value=True)
    st.checkbox("Include historical data", value=True)
    st.markdown('</div>', unsafe_allow_html=True)

# Technology Stack Section
with st.expander(f"💻 Technology Stack ({len(company_profile['tech_stack'])})", expanded=True):
    st.markdown(
        "".join([f'<span class="tag">{tech}</span>' for tech in company_profile['tech_stack']]),
        unsafe_allow_html=True
    )

# Critical Assets Section
with st.expander(f"🛡️ Critical Assets ({len(company_profile['critical_assets'])})", expanded=False):
    st.markdown(
        "".join([f'<span class="tag">{asset}</span>' for asset in company_profile['critical_assets']]),
        unsafe_allow_html=True
    )

# Compliance Section
with st.expander(f"📋 Compliance Requirements ({len(company_profile['compliance'])})", expanded=False):
    st.markdown(
        "".join([f'<span class="tag">{compliance}</span>' for compliance in company_profile['compliance']]),
        unsafe_allow_html=True
    )

# Threats and Incidents Section
# Mock data for the new threat card design
mock_threats = [
    {"title": "APT29 Campaign", "status": "Active Investigation", "severity": "high"},
    {"title": "Phishing Campaign #127", "status": "Monitoring", "severity": "medium"},
    {"title": "Malware Detection", "status": "Containment", "severity": "high"},
    {"title": "Suspicious Login Activity", "status": "Resolved", "severity": "low"},
    {"title": "DDoS Attack Vector", "status": "Mitigated", "severity": "medium"},
    {"title": "Data Exfiltration Attempt", "status": "Under Review", "severity": "high"},
    {"title": "Insider Threat Alert", "status": "Investigating", "severity": "medium"},
    {"title": "Ransomware Indicators", "status": "Blocked", "severity": "high"},
]

total_threats = len(mock_threats)
with st.expander(f"⚠️ Security Threats & Incidents ({total_threats})", expanded=True):
    st.markdown('<div class="threat-list-grid">', unsafe_allow_html=True)
    for threat in mock_threats:
        st.markdown(f"""
            <div class="threat-item-card">
                <div class="threat-header">
                    <div class="status-dot status-{threat['severity']}"></div>
                    <div class="threat-title">{threat['title']}</div>
                </div>
                <div class="threat-subtitle">{threat['status']}</div>
            </div>
        """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# Pipeline Button
st.markdown("<br>", unsafe_allow_html=True)
col1, col2, col3 = st.columns([1,2,1])
with col2:
    if st.button("🚀 Run Threat Intelligence Pipeline", type="primary", use_container_width=True):
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
                    
            # Two-column layout for threats
            col_left, col_right = st.columns([1, 3])
            with col_left:
                st.markdown("**Select a threat to view details and chat:**")
                threat_names = [t.get("name", f"Threat {i+1}") for i, t in enumerate(filtered_threats)]
                selected_idx = st.radio("Threats", options=list(range(len(threat_names))), 
                                     format_func=lambda i: threat_names[i], key="threat_radio")
                
            with col_right:
                threat = filtered_threats[selected_idx]
                st.markdown(f"### Enrichment & Recommendations for: {threat.get('name', 'Unknown')}")
                
                if isinstance(enriched_summaries, list) and len(enriched_summaries) > selected_idx:
                    st.write(enriched_summaries[selected_idx])
                elif isinstance(enriched_summaries, dict) and threat.get('name') in enriched_summaries:
                    st.write(enriched_summaries[threat.get('name')])
                else:
                    st.write(enriched_summaries)
                    
                st.markdown("---")
                st.markdown("**Chat with the AI about this threat:**")
                
                # Initialize chat history
                chat_key = f"chat_history_{threat.get('name', str(selected_idx))}"
                if chat_key not in st.session_state:
                    st.session_state[chat_key] = []
                
                # Display chat history
                for msg in st.session_state[chat_key]:
                    with st.chat_message(msg["role"]):
                        st.write(msg["content"])
                
                # Chat input
                user_input = st.chat_input(f"Ask about {threat.get('name', 'this threat')}...", 
                                         key=f"input_{selected_idx}")
                if user_input:
                    st.session_state[chat_key].append({"role": "user", "content": user_input})
                    with st.chat_message("user"):
                        st.write(user_input)
                        
                    with st.spinner("AI is thinking..."):
                        from agents.threat_chat_agent import ThreatChatAgent
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
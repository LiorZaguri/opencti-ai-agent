import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
import json
import copy
import re
import difflib
from agents.data_retrieval_agent import DataRetrievalAgent
from agents.threat_filtering_agent import ThreatFilteringAgent
from agents.threat_enrichment_agent import ThreatEnrichmentAgent

st.set_page_config(page_title="Threat Intelligence Pipeline", layout="wide")

# Profile selection
profile_files = [
    "data/company_profile.json",
    "data/company_profile_clear.json",
    "data/company_profile_no_threats.json",
    "data/company_profile_minimal.json",
    "data/company_profile_empty.json"
]

profile_options = {}
for file_path in profile_files:
    try:
        with open(file_path, "r") as f:
            profile = json.load(f)
            name = profile.get("company_name", file_path)
            profile_options[name] = file_path
    except Exception:
        profile_options[file_path] = file_path  # fallback

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
company_name = company_profile.get("company_name", st.session_state.selected_profile)

def parse_llm_json(s):
    try:
        return json.loads(s)
    except Exception:
        return None

def split_enrichment_by_markdown_heading(enrichment_str, threat_names):
    import re
    
    # Try multiple patterns to match different markdown formats
    patterns = [
        r'^###\s*\*\*(\d+)\.\s*(.+?)\*\*',  # ### **1. Threat Name**
        r'^#+\s*\*\*(\d+)\.\s*(.+?)\*\*',   # **1. Threat Name**
        r'^#+\s*(\d+)\.\s*(.+?)$',          # # 1. Threat Name
        r'^#+\s*(.+?)$',                     # # Threat Name
        r'^##\s*(.+?)$',                     # ## Threat Name
        r'^\*\*(\d+)\.\s*(.+?)\*\*',        # **1. Threat Name** (no #)
    ]
    
    chunks = {}
    
    for pattern in patterns:
        regex_pattern = re.compile(pattern, re.MULTILINE)
        matches = list(regex_pattern.finditer(enrichment_str))
        
        if matches:
            for idx, match in enumerate(matches):
                start = match.start()
                end = matches[idx + 1].start() if idx + 1 < len(matches) else len(enrichment_str)
                
                # Extract heading text based on pattern
                if pattern == r'^###\s*\*\*(\d+)\.\s*(.+?)\*\*':  # ### **1. Threat Name**
                    heading = match.group(2).strip()
                elif pattern == r'^#+\s*\*\*(\d+)\.\s*(.+?)\*\*':  # **1. Threat Name**
                    heading = match.group(2).strip()
                elif pattern == r'^#+\s*(\d+)\.\s*(.+?)$':  # # 1. Threat Name
                    heading = match.group(2).strip()
                elif pattern == r'^#+\s*(.+?)$':  # # Threat Name
                    heading = match.group(1).strip()
                elif pattern == r'^##\s*(.+?)$':  # ## Threat Name
                    heading = match.group(1).strip()
                elif pattern == r'^\*\*(\d+)\.\s*(.+?)\*\*':  # **1. Threat Name** (no #)
                    heading = match.group(2).strip()
                else:
                    # Fallback: use the entire match
                    heading = match.group(0).strip()
                
                chunk = enrichment_str[start:end].strip()
                
                # Try to match the heading to threat names (exact match first)
                matched = False
                for name in threat_names:
                    if name.lower() == heading.lower():
                        chunks[name] = chunk
                        matched = True
                        break
                
                # If no exact match, try partial matching
                if not matched:
                    for name in threat_names:
                        # Check if the threat name is contained in the heading or vice versa
                        if (name.lower() in heading.lower() or 
                            heading.lower() in name.lower()):
                            chunks[name] = chunk
                            matched = True
                            break
                
                # If still no match, try word-based matching
                if not matched:
                    for name in threat_names:
                        # Split both names into words and check for overlap
                        name_words = set(name.lower().split())
                        heading_words = set(heading.lower().split())
                        # Remove common words
                        name_words = {w for w in name_words if len(w) > 3}
                        heading_words = {w for w in heading_words if len(w) > 3}
                        if name_words & heading_words:  # intersection
                            chunks[name] = chunk
                            matched = True
                            break
            
            # If we found matches with this pattern, break
            if chunks:
                break
    
    # If still no matches, try to split by any markdown heading and assign by index
    if not chunks and threat_names:
        # Split by any markdown heading
        heading_pattern = re.compile(r'^#+\s*(.+?)$', re.MULTILINE)
        matches = list(heading_pattern.finditer(enrichment_str))
        
        for idx, match in enumerate(matches):
            if idx < len(threat_names):
                start = match.start()
                end = matches[idx + 1].start() if idx + 1 < len(matches) else len(enrichment_str)
                chunk = enrichment_str[start:end].strip()
                chunks[threat_names[idx]] = chunk
    
    # If still no matches, try to split by numbered sections
    if not chunks and threat_names:
        # Look for numbered sections like "1. Threat Name" or "**1. Threat Name**"
        numbered_pattern = re.compile(r'^(?:\*\*)?(\d+)\.\s*(.+?)(?:\*\*)?', re.MULTILINE)
        matches = list(numbered_pattern.finditer(enrichment_str))
        
        for idx, match in enumerate(matches):
            if idx < len(threat_names):
                start = match.start()
                end = matches[idx + 1].start() if idx + 1 < len(matches) else len(enrichment_str)
                chunk = enrichment_str[start:end].strip()
                chunks[threat_names[idx]] = chunk
    
    return chunks

def remove_cross_references(text, threat_names, current_threat):
    # Normalize threat names for matching
    def normalize(s):
        return re.sub(r'[^a-z0-9]', '', s.lower())
    current_norm = normalize(current_threat)
    other_norms = [normalize(n) for n in threat_names if normalize(n) != current_norm]

    lines = text.splitlines()
    filtered = []
    skip_section = False
    for line in lines:
        line_norm = normalize(line)
        # Remove lines that mention any other threat by fuzzy match
        if any(difflib.SequenceMatcher(None, line_norm, n).ratio() > 0.7 for n in other_norms):
            continue
        # Remove generic cross-reference lines
        if re.search(r'(other threats|other malware|other campaigns|other attack patterns|other items)', line, re.IGNORECASE):
            continue
        # Optionally, skip 'General Recommendations' sections
        if re.match(r'^(general )?recommendations', line.strip(), re.IGNORECASE):
            skip_section = True
            continue
        if skip_section:
            # End skipping if we hit a new section or empty line
            if line.strip() == '' or re.match(r'^[A-Z][a-z]+:', line):
                skip_section = False
            else:
                continue
        filtered.append(line)
    return '\n'.join(filtered).strip()

data_agent = DataRetrievalAgent(profile_options[st.session_state.selected_profile])
filter_agent = ThreatFilteringAgent()
enrich_agent = ThreatEnrichmentAgent()

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
    
    /* Chat Interface Styling */
    .chat-container {
        height: 500px;
        overflow-y: auto;
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 1rem;
        background: rgba(25, 20, 35, 0.97);
        margin-bottom: 1rem;
    }
    
    /* Ensure chat input stays at bottom */
    .stChatInput {
        position: sticky;
        bottom: 0;
        background: rgba(30, 25, 40, 0.97);
        border-top: 1px solid var(--ai-border);
        padding: 1rem 0;
        z-index: 100;
    }
    
    /* Chat message styling */
    .stChatMessage {
        margin-bottom: 1rem;
    }
    
    /* Two-column layout for threats and chat */
    .threat-chat-layout {
        display: grid;
        grid-template-columns: 1fr 3fr;
        gap: 1rem;
        height: 600px;
    }
    
    .threat-selection {
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        padding: 1rem;
        background: rgba(25, 20, 35, 0.97);
        overflow-y: auto;
    }
    
    .chat-area {
        border: 1px solid var(--ai-border);
        border-radius: 8px;
        background: rgba(25, 20, 35, 0.97);
        display: flex;
        flex-direction: column;
        height: 100%;
    }
    
    .chat-messages {
        flex: 1;
        overflow-y: auto;
        padding: 1rem;
    }
    
    .chat-input-area {
        border-top: 1px solid var(--ai-border);
        padding: 1rem;
        background: rgba(30, 25, 40, 0.97);
    }
    </style>
""", unsafe_allow_html=True)

# Main content
st.markdown(f"# 🧠 Threat Intelligence Automation Pipeline for {company_name}")

# Initialize session state for sidebar visibility
if 'show_recent_activity' not in st.session_state:
    st.session_state.show_recent_activity = False

# Main layout with native sidebar and custom right sidebar
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

    # If the user changed the selection, update session state and rerun
    if selected_profile != st.session_state.selected_profile:
        st.session_state.selected_profile = selected_profile
        st.session_state.edited_profile = None  # reset edit state
        st.rerun()
    
    # Initialize edited_profile if it doesn't exist or if profile changed
    if 'edited_profile' not in st.session_state or st.session_state.edited_profile is None:
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

# Create two-column layout for main content and right sidebar
main_col, right_sidebar = st.columns([4, 1])

# Main Content Area
with main_col:
    # Technology Stack Section
    if company_profile.get('tech_stack'):
        with st.expander(f"💻 Technology Stack ({len(company_profile['tech_stack'])})", expanded=False):
            st.markdown(
                "".join([f'<span class="tag">{tech}</span>' for tech in company_profile['tech_stack']]),
                unsafe_allow_html=True
            )

    # Critical Assets Section
    if company_profile.get('critical_assets'):
        with st.expander(f"🛡️ Critical Assets ({len(company_profile['critical_assets'])})", expanded=False):
            st.markdown(
                "".join([f'<span class="tag">{asset}</span>' for asset in company_profile['critical_assets']]),
                unsafe_allow_html=True
            )

    # Compliance Section
    if company_profile.get('compliance'):
        with st.expander(f"📋 Compliance Requirements ({len(company_profile['compliance'])})", expanded=False):
            st.markdown(
                "".join([f'<span class="tag">{compliance}</span>' for compliance in company_profile['compliance']]),
                unsafe_allow_html=True
            )

    # Threats and Incidents Section
    if company_profile.get('past_incidents'):
        with st.expander(f"⚠️ Security Threats & Incidents ({len(company_profile['past_incidents'])})", expanded=False):
            st.markdown('<div class="threat-list-grid">', unsafe_allow_html=True)
            for incident in company_profile['past_incidents']:
                st.markdown(f"<div class='threat-item-card'><div class='threat-header'><div class='threat-title'>{incident}</div></div></div>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        with st.expander("⚠️ Security Threats & Incidents (0)", expanded=False):
            st.info("No threats or incidents recorded for this company profile.")

    # Pipeline Button
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        if st.button("🚀 Run Threat Intelligence Pipeline", type="primary", use_container_width=True):
            # Add log function
            def add_log(agent, message, level='info'):
                import datetime
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                st.session_state.agent_logs.append({
                    'timestamp': timestamp,
                    'agent': agent,
                    'message': message,
                    'level': level
                })
            
            # Clear previous logs
            st.session_state.agent_logs = []
            
            # Create placeholder for real-time log updates
            log_placeholder = st.empty()
            
            def update_logs_display():
                if st.session_state.agent_logs:
                    log_html = ""
                    for log in st.session_state.agent_logs[-5:]:  # Show last 5 logs
                        timestamp = log.get('timestamp', '')
                        agent = log.get('agent', '')
                        message = log.get('message', '')
                        level = log.get('level', 'info')
                        
                        color_map = {
                            'info': '#A78BFA',
                            'success': '#10b981',
                            'warning': '#f59e0b',
                            'error': '#ef4444'
                        }
                        color = color_map.get(level, '#A78BFA')
                        
                        log_html += f"""
                        <div style="margin-bottom: 0.5rem; padding: 0.3rem; border-left: 3px solid {color}; background: rgba(139, 92, 246, 0.05);">
                            <div style="font-size: 0.7rem; color: {color}; font-weight: 600;">{agent}</div>
                            <div style="font-size: 0.8rem; color: #E0E0E0;">{message}</div>
                            <div style="font-size: 0.6rem; color: #9E9E9E;">{timestamp}</div>
                        </div>
                        """
                    log_placeholder.markdown(log_html, unsafe_allow_html=True)
            
            add_log("Pipeline", "Starting threat intelligence pipeline...", "info")
            update_logs_display()
            
            with st.spinner("Retrieving threats from OpenCTI..."):
                add_log("DataRetrievalAgent", "Querying OpenCTI for threat data...", "info")
                update_logs_display()
                raw_threats_str = data_agent.run()
                raw_threats = parse_llm_json(raw_threats_str)
                
                # Create a comprehensive log message showing all entity types
                malware_count = len(raw_threats.get('malware', []))
                attack_patterns_count = len(raw_threats.get('attack_patterns', []))
                intrusion_sets_count = len(raw_threats.get('intrusion_sets', []))
                vulnerabilities_count = len(raw_threats.get('vulnerabilities', []))
                threat_reports_count = len(raw_threats.get('threat_reports', []))
                
                log_message = f"Retrieved {malware_count} malware, {attack_patterns_count} attack patterns, {intrusion_sets_count} intrusion sets, {vulnerabilities_count} vulnerabilities, {threat_reports_count} threat reports"
                
                add_log("DataRetrievalAgent", log_message, "success")
                update_logs_display()
            
            with st.spinner("Filtering and ranking threats..."):
                add_log("ThreatFilteringAgent", "Pre-filtering threats for AI analysis...", "info")
                update_logs_display()
                
                # Calculate total threats received
                total_threats = 0
                for entity_type, entities in raw_threats.items():
                    if isinstance(entities, list):
                        total_threats += len(entities)
                
                add_log("ThreatFilteringAgent", f"Processing {total_threats} total threats from OpenCTI...", "info")
                update_logs_display()
                
                filtered_threats_str = filter_agent.run(
                    threat_data=raw_threats if isinstance(raw_threats, dict) else {},
                    company_profile=company_profile
                )
                filtered_threats_data = parse_llm_json(filtered_threats_str)
                
                # Handle new reasoning structure
                if isinstance(filtered_threats_data, dict):
                    filtered_threats = filtered_threats_data.get("threats", [])
                    threat_objects = filtered_threats_data.get("threat_objects", [])
                    reasoning = filtered_threats_data.get("reasoning", {})
                else:
                    filtered_threats = filtered_threats_data if filtered_threats_data else []
                    threat_objects = []
                    reasoning = {}

                # Debug: Log the names in filtered_threats and threat_objects
                add_log("DEBUG", f"AI summary threats: {[t.get('name') for t in filtered_threats]}", "info")
                add_log("DEBUG", f"Threat objects: {[t.get('name') for t in threat_objects]}", "info")

                add_log("ThreatFilteringAgent", f"AI analysis completed. Found {len(filtered_threats)} relevant threats", "success")
                update_logs_display()

            # If no threats found, do not call enrichment agent
            if not filtered_threats or len(filtered_threats) == 0:
                add_log("Pipeline", "No relevant threats detected for this company profile", "warning")
                update_logs_display()
                st.session_state["threat_names"] = []
                st.session_state["threats_loaded"] = False
                st.session_state["selected_threat"] = None
                st.session_state["filtered_threats"] = []
                st.session_state["raw_threats"] = raw_threats
                st.session_state["enriched_summaries"] = None
                st.session_state["reasoning"] = {}
                st.info(
                    '''**No Relevant Threats Detected for This Company**

Based on the information you provided about your company (such as its industry, technology stack, and past incidents), our AI did not find any current cyber threats that are specifically relevant to your organization.

**What does this mean?**
- Your company's profile does not match any known threat patterns in our database at this time.
- This could be because your company uses uncommon technologies, operates in a low-risk industry, or simply hasn't been targeted by the types of threats we track.

**What should you do next?**
- Continue to follow general cybersecurity best practices (like using strong passwords, keeping software updated, and training employees to spot phishing).
- If your company's details change, or you want to check again in the future, you can update your profile and re-run the analysis.

If you have questions about cybersecurity or want to learn more about how threats are detected, feel free to ask!'''
                )
                st.stop()

            with st.spinner("Enriching all threats and generating recommendations..."):
                add_log("ThreatEnrichmentAgent", f"Enriching {len(threat_objects) if threat_objects else len(filtered_threats)} threats with detailed intelligence...", "info")
                update_logs_display()
                # Use the actual threat objects for enrichment
                threats_to_enrich = threat_objects if threat_objects else filtered_threats
                add_log("DEBUG", f"Threats to enrich: {[t.get('name') for t in threats_to_enrich]}", "info")
                enriched_summaries_str = enrich_agent.run(top_threats=threats_to_enrich)
                # Store the raw enrichment output
                enriched_summaries = enriched_summaries_str
                add_log("ThreatEnrichmentAgent", "Enrichment completed successfully", "success")
                update_logs_display()
            
            add_log("Pipeline", "Pipeline completed successfully", "success")
            update_logs_display()
            
            # Initialize chat histories for each threat
            if filtered_threats:
                threat_names_list = [t.get("name", f"Threat {i+1}") for i, t in enumerate(filtered_threats)]
                
                # Process enrichment output
                enrichment_chunks = split_enrichment_by_markdown_heading(enriched_summaries_str, threat_names_list)
                
                # Debug: Log enrichment parsing results
                add_log("DEBUG", f"Threat names for chat: {threat_names_list}", "info")
                add_log("DEBUG", f"Enrichment chunks found: {list(enrichment_chunks.keys())}", "info")
                
                for i, threat in enumerate(filtered_threats):
                    threat_name = threat.get("name", f"Threat {i+1}")
                    chat_key = f"chat_history_{threat_name}"
                    if chat_key not in st.session_state:
                        st.session_state[chat_key] = []
                    # Only add if not already present
                    if not st.session_state[chat_key]:
                        # Try to get the enriched content for this threat
                        if threat_name in enrichment_chunks:
                            initial_msg = enrichment_chunks[threat_name]
                            # Remove cross-references to other threats
                            initial_msg = remove_cross_references(initial_msg, threat_names_list, threat_name)
                        else:
                            # Fallback: create a basic threat summary
                            threat_desc = threat.get("description", "No description available")
                            threat_labels = ", ".join(threat.get("labels", []))
                            initial_msg = f"""## {threat_name}

**Type:** {threat.get('entity_type', 'Unknown')}
**Description:** {threat_desc}
**Labels:** {threat_labels}
**Confidence:** {threat.get('confidence', threat.get('score', 'Unknown'))}

*Note: Detailed enrichment information is not available for this threat. Please ask specific questions about this threat for more information.*"""
                        
                        # Add reasoning to the initial message - use the correct reasoning for this specific threat
                        if threat_name in reasoning:
                            reason_info = reasoning[threat_name]
                            # Ensure the reasoning text mentions the correct threat name
                            reason_text = reason_info.get('reason', f'This threat ({threat_name}) was detected based on your company profile.')
                            # Replace any mention of other threats with the correct threat name
                            if 'Akira' in reason_text or 'ransomware' in reason_text.lower():
                                reason_text = f"{threat_name} was detected based on your company profile characteristics and potential vulnerabilities."
                            
                            reasoning_text = f"""
**Why was this threat detected for your company?**
{reason_text}

**Matched Keywords:** {', '.join(reason_info.get('matched_keywords', []))}
**Relevance Score:** {reason_info.get('relevance_score', 0)} matches found
"""
                            initial_msg = reasoning_text + "\n\n" + initial_msg
                        else:
                            # If no specific reasoning found, create a generic one
                            reasoning_text = f"""
**Why was this threat detected for your company?**
This threat ({threat_name}) was detected based on your company profile characteristics and potential vulnerabilities.

**Relevance Score:** Based on AI analysis
"""
                            initial_msg = reasoning_text + "\n\n" + initial_msg
                        
                        st.session_state[chat_key].append({"role": "assistant", "content": initial_msg})
                # Store threat names for sidebar
                st.session_state["threat_names"] = threat_names_list
                st.session_state["threats_loaded"] = True
                st.session_state["selected_threat"] = st.session_state["threat_names"][0] if st.session_state["threat_names"] else None
            else:
                st.session_state["threat_names"] = []
                st.session_state["threats_loaded"] = False
                st.session_state["selected_threat"] = None
            st.session_state["filtered_threats"] = filtered_threats
            st.session_state["raw_threats"] = raw_threats
            st.session_state["enriched_summaries"] = enriched_summaries
            st.session_state["reasoning"] = reasoning
            st.session_state["threats_to_enrich"] = threats_to_enrich  # Store the correct threat objects
            st.rerun()

# Chat Interface with Threat Selection
if st.session_state.get("threats_loaded") and st.session_state.get("selected_threat"):
    # Create two-column layout for threat selection and chat
    threat_col, chat_col = st.columns([1, 3])
    
    # Threat Selection (Left Column)
    with threat_col:
        st.markdown("### Threats")
        selected_threat = st.radio(
            "Select a threat to chat about:",
            options=st.session_state["threat_names"],
            key="selected_threat_radio"
        )
        st.session_state["selected_threat"] = selected_threat
    
    # Chat Interface (Right Column)
    with chat_col:
        threats_to_enrich = st.session_state.get("threats_to_enrich", [])
        threat_name = st.session_state["selected_threat"]
        chat_key = f"chat_history_{threat_name}"
        st.markdown(f"### 💬 Chat about: {threat_name}")
        
        # Initialize chat history if it doesn't exist
        if chat_key not in st.session_state:
            st.session_state[chat_key] = []
        
        # Display chat history using Streamlit's native chat interface
        for message in st.session_state[chat_key]:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Chat input - this will always be at the bottom
        if prompt := st.chat_input(f"Ask about {threat_name}..."):
            # Add user message to chat history
            st.session_state[chat_key].append({"role": "user", "content": prompt})
            
            # Display user message
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Get AI response
            with st.chat_message("assistant"):
                with st.spinner("AI is thinking..."):
                    from agents.threat_chat_agent import ThreatChatAgent
                    # Find the threat object from threats_to_enrich
                    threat_obj = None
                    for i, t in enumerate(st.session_state.get("threat_names", [])):
                        if t == threat_name:
                            if i < len(threats_to_enrich):
                                threat_obj = threats_to_enrich[i]
                            break
                    if threat_obj is None:
                        threat_obj = {"name": threat_name}
                    chat_agent = ThreatChatAgent(threat_obj, company_profile)
                    ai_reply = chat_agent.run(prompt)
                
                # Display AI response
                st.markdown(ai_reply)
                
                # Add AI response to chat history
                st.session_state[chat_key].append({"role": "assistant", "content": ai_reply})
else:
    st.info("Click the button above to run the full threat intelligence pipeline and start chatting.")

# Right Sidebar - Activity Logs
with right_sidebar:
    st.markdown('<div class="sidebar-header">🔍 Activity Logs</div>', unsafe_allow_html=True)
    
    # Initialize logs in session state if not exists
    if 'agent_logs' not in st.session_state:
        st.session_state.agent_logs = []
    
    # Display agent logs
    if st.session_state.agent_logs:
        st.markdown("#### Recent Activity")
        
        # Show last 10 logs
        for log in st.session_state.agent_logs[-10:]:
            timestamp = log.get('timestamp', '')
            agent = log.get('agent', '')
            message = log.get('message', '')
            level = log.get('level', 'info')
            
            # Color coding based on level
            color_map = {
                'info': '#A78BFA',
                'success': '#10b981',
                'warning': '#f59e0b',
                'error': '#ef4444'
            }
            color = color_map.get(level, '#A78BFA')
            
            st.markdown(f"""
            <div style="margin-bottom: 0.5rem; padding: 0.3rem; border-left: 3px solid {color}; background: rgba(139, 92, 246, 0.05);">
                <div style="font-size: 0.7rem; color: {color}; font-weight: 600;">{agent}</div>
                <div style="font-size: 0.8rem; color: #E0E0E0;">{message}</div>
                <div style="font-size: 0.6rem; color: #9E9E9E;">{timestamp}</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Clear logs button
        if st.button("Clear Logs", key="clear_logs", use_container_width=True):
            st.session_state.agent_logs = []
            # Don't rerun to avoid interrupting pipeline
    else:
        st.info("No agent activity yet. Run the pipeline to see logs.") 
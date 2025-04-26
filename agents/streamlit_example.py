# To launch this app, run:
#   streamlit run agents/streamlit_example.py

import streamlit as st
import inspect
import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.base import BaseAgent
# Removed unused imports like initiate_swarm_chat, ContextVariables
import agents.tools.opencti_tools as tools_pkg

# Sidebar: Tool selection
st.sidebar.title("Configure CTI Agent Tools")
available_tools = [
    name for name, fn in inspect.getmembers(tools_pkg, inspect.isfunction)
    if fn.__module__ == tools_pkg.__name__ and not name.startswith('_')
]
# Initialize selected_tools in session
if 'selected_tools' not in st.session_state:
    st.session_state.selected_tools = []
# Render tool checkboxes
tool_checks = {}
for tool in available_tools:
    tool_checks[tool] = st.sidebar.checkbox(
        tool,
        value=(tool in st.session_state.selected_tools)
    )
# Save Tools button
if st.sidebar.button("Save Tools"):
    st.session_state.selected_tools = [t for t, checked in tool_checks.items() if checked]
    st.sidebar.success(
        "Tools updated: " + ", ".join(st.session_state.selected_tools)
        if st.session_state.selected_tools else "No tools selected"
    )
    # Force agent re-initialization when tools change by removing it from state
    if 'cti_agent' in st.session_state:
        del st.session_state.cti_agent
    # Clear chat history when tools change
    st.session_state.chat_history = []

# Instantiate or update CTI agent if not in session state
if 'cti_agent' not in st.session_state:
    enabled = st.session_state.selected_tools
    if enabled:
        tools_context = "Available tools: " + ", ".join(enabled)
    else:
        tools_context = "No tools enabled"
    system_message = (
        f"You are an OpenCTI Cyber Threat Intelligence Agent. {tools_context}. "
        "Leverage OpenCTI and these tools to provide accurate, context-rich intelligence to the user."
    )
    # Initialize BaseAgent - it will use default_llm_config from model_configs
    st.session_state.cti_agent = BaseAgent(
        name="CTI_Agent",
        system_message=system_message,
        tools=enabled
    )
    st.rerun() # Rerun to update UI after agent initialization

# Interactive chat
st.title("💬 CTI Agent Chat")

# Display currently enabled tools below the title as bubbles
enabled_tools = st.session_state.cti_agent.get_registered_tools()
if enabled_tools:
    bubble_html = "".join(
        f"<span style='display:inline-block; padding:6px 12px; margin:2px; border:1px solid #888; border-radius:12px; font-size:0.9em;'>{tool}</span>"
        for tool in enabled_tools
    )
    st.markdown(
        f"**Enabled tools:** {bubble_html}", unsafe_allow_html=True
    )
else:
    st.info("No tools enabled. Configure tools in the sidebar and click 'Save Tools'.")

# Initialize chat history in session state if it doesn't exist
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# Display chat history
for message in st.session_state.chat_history:
    with st.chat_message(message["role"]):
        st.write(message["content"])

# User input
user_input = st.chat_input("Enter your message")
if user_input:
    # Add user message to chat history and display it
    st.session_state.chat_history.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.write(user_input)

    # Show spinner while agent is processing
    with st.spinner("CTI Agent is thinking..."):
        # Call the run method from BaseAgent
        assistant_reply = st.session_state.cti_agent.run(user_input)

    # Add assistant reply to chat history and display it
    st.session_state.chat_history.append({"role": "assistant", "content": assistant_reply})
    with st.chat_message("assistant"):
        st.write(assistant_reply)

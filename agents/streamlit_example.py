# To launch this app, run:
#   streamlit run agents/streamlit_example.py

import streamlit as st
import inspect
import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.base import BaseAgent
from autogen import initiate_swarm_chat
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

# Instantiate or update CTI agent
if 'cti_agent' not in st.session_state or st.session_state.get('selected_tools') is not None:
    # Create a dynamic system message that lists enabled tools
    enabled = st.session_state.selected_tools
    if enabled:
        tools_context = "Available tools: " + ", ".join(enabled)
    else:
        tools_context = "No tools enabled"
    system_message = (
        f"You are an OpenCTI Cyber Threat Intelligence Agent. {tools_context}. "
        "Leverage OpenCTI and these tools to provide accurate, context-rich intelligence to the user."
    )
    st.session_state.cti_agent = BaseAgent(
        name="CTI_Agent",
        system_message=system_message,
        tools=enabled
    )

# Interactive chat without persistent history
st.title("💬 CTI Agent Chat")

# Display currently enabled tools below the title as bubbles
if st.session_state.selected_tools:
    # Render bubbles inline using HTML spans
    bubble_html = "".join(
    f"<span style='display:inline-block; padding:6px 12px; margin:2px; border:1px solid #888; border-radius:12px; font-size:0.9em;'>{tool}</span>"
    for tool in st.session_state.selected_tools
)
    st.markdown(
        f"**Enabled tools:** {bubble_html}", unsafe_allow_html=True
    )
else:
    st.info("No tools enabled. Please configure tools in the sidebar.")

# User input
user_input = st.chat_input("Enter your message")
if user_input:
    # Display user message immediately
    st.chat_message("user").write(user_input)

    # Show spinner under the user message
    with st.spinner("CTI Agent is thinking..."):
        cti_conv = st.session_state.cti_agent.conversable_agent
        result, tool_execs, _ = initiate_swarm_chat(
            initial_agent=cti_conv,
            agents=[cti_conv],
            user_agent=None,
            messages=user_input,
            max_rounds=50,
        )
        assistant_reply = result.chat_history[-1]["content"]

    # Display assistant reply
    st.chat_message("assistant").write(assistant_reply)

    # Execute and display tool outputs
    if tool_execs:
        for tool in st.session_state.selected_tools:
            func = getattr(tools_pkg, tool, None)
            if func:
                output = func()
                st.chat_message("system").write(f"Tool {tool} output: {output}")

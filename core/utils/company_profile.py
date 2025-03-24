import os
import json

def load_company_profile():
    """
    Load the static company profile used by AI agents and utilities
    for contextual analysis and prioritization.
    """
    path = os.path.join("data", "company_profile.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}
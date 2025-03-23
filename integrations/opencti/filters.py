"""
Filter utilities for OpenCTI queries.

This module provides helper functions for creating and manipulating filters
for OpenCTI API queries.
"""

from typing import List, Dict, Any, Optional


def prepare_filters(filters: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """
    Format filters according to OpenCTI's FilterGroup structure.
    
    As per the documentation at https://docs.opencti.io/latest/reference/filters/
    OpenCTI 5.12+ requires filters to be in FilterGroup format.
    
    Args:
        filters: List of filter dictionaries with key, values, and optional operator
        
    Returns:
        A properly formatted FilterGroup dict, or None if filters is None
    """
    if not filters:
        return None
        
    # Create a proper FilterGroup structure
    filter_group = {
        "mode": "and",
        "filters": [],
        "filterGroups": []
    }
    
    # Add each filter to the filters array with required fields
    for f in filters:
        filter_obj = {
            "key": f["key"],
            "values": f["values"],
            "mode": "or"  # Default mode for multi-value filters
        }
        
        # Add operator if specified
        if "operator" in f:
            filter_obj["operator"] = f["operator"]
        else:
            filter_obj["operator"] = "eq"  # Default operator
            
        filter_group["filters"].append(filter_obj)
    
    return filter_group 
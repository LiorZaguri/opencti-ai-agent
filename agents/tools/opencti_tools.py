"""
OpenCTI Tools for Agents.

This module provides tool functions that wrap OpenCTI ingestion pipeline for use with agents.
The tools leverage the existing ingestion pipeline with caching capabilities for better performance.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json
from core.utils.logger import setup_logger
from core.data_pipeline.ingestion.opencti import (
    ThreatActorIngestor,
    IndicatorIngestor,
    ObservableIngestor,
    VulnerabilityIngestor,
    ReportIngestor,
    RelationshipIngestor,
    clear_all_caches
)

logger = setup_logger(name="opencti_tools", component_type="agent_tools")

# Create a single instance of each ingestor with caching enabled
_ingestors = {
    'threat_actor': ThreatActorIngestor(use_cache=True),
    'indicator': IndicatorIngestor(use_cache=True),
    'observable': ObservableIngestor(use_cache=True),
    'vulnerability': VulnerabilityIngestor(use_cache=True),
    'report': ReportIngestor(use_cache=True),
    'relationship': RelationshipIngestor(use_cache=True)
}

def _parse_filters(filters):
    """Helper function to parse filters from various formats"""
    if not filters:
        return None

    if isinstance(filters, str):
        logger.warning(f"Received string for filters instead of list: {filters}")
        try:
            # Try to parse as JSON
            try:
                return json.loads(filters)
            except json.JSONDecodeError:
                # If not valid JSON, try to convert simple string formats
                if "=" in filters:
                    # Handle simple key=value format
                    parts = filters.split("=")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        return [{"key": key, "values": [value]}]
        except Exception as e:
            logger.error(f"Error parsing filters string: {str(e)}")

    return filters  # Return as is if already in correct format

# ===== Threat Actor Tools =====

def get_threat_actors(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve threat actors from OpenCTI."""
    logger.info(f"Tool: Retrieving up to {limit} threat actors from OpenCTI")
    try:
        result = _ingestors['threat_actor'].ingest_threat_actors(limit=limit, include_raw=True)
        logger.info(f"Retrieved {len(result)} threat actors")
        return result
    except Exception as e:
        logger.error(f"Error retrieving threat actors: {str(e)}")
        return []

# ===== Indicator Tools =====

def get_indicators(filters: Optional[List[Dict[str, Any]]] = None, days_back: int = 30, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve indicators from OpenCTI."""
    filters = _parse_filters(filters)
    logger.info(f"Tool: Retrieving indicators from OpenCTI with filters: {filters}, limit: {limit}")
    try:
        result = _ingestors['indicator'].ingest_indicators(limit=limit, days_back=days_back, include_raw=True)
        logger.info(f"Retrieved {len(result)} indicators")
        return result
    except Exception as e:
        logger.error(f"Error retrieving indicators: {str(e)}")
        return []

# ===== Observable Tools =====

def get_observables(filters: Optional[List[Dict[str, Any]]] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve observables from OpenCTI."""
    filters = _parse_filters(filters)

    # Extract types from filters if they exist
    types = None
    if filters:
        for filter_item in filters:
            if filter_item.get('key') == 'entity_type':
                types = filter_item.get('values')
                break

    logger.info(f"Tool: Retrieving observables from OpenCTI with types: {types}")
    try:
        result = _ingestors['observable'].ingest_observables(types=types, limit=limit, include_raw=True)
        logger.info(f"Retrieved {len(result)} observables")
        return result
    except Exception as e:
        logger.error(f"Error retrieving observables: {str(e)}")
        return []

# ===== Vulnerability Tools =====

def get_vulnerabilities(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve vulnerabilities from OpenCTI."""
    logger.info(f"Tool: Retrieving up to {limit} vulnerabilities from OpenCTI")
    try:
        result = _ingestors['vulnerability'].ingest_vulnerabilities(limit=limit, include_raw=True)
        logger.info(f"Retrieved {len(result)} vulnerabilities")
        return result
    except Exception as e:
        logger.error(f"Error retrieving vulnerabilities: {str(e)}")
        return []

# ===== Report Tools =====

def get_reports(limit: int = 20, days_back: int = 90) -> List[Dict[str, Any]]:
    """Retrieve reports from OpenCTI."""
    logger.info(f"Tool: Retrieving up to {limit} reports from OpenCTI (last {days_back} days)")
    try:
        result = _ingestors['report'].ingest_reports(limit=limit, days_back=days_back, include_raw=True)
        logger.info(f"Retrieved {len(result)} reports")
        return result
    except Exception as e:
        logger.error(f"Error retrieving reports: {str(e)}")
        return []

# ===== Relationship Tools =====

def get_relationships(entity_id: Optional[str] = None,
                     relationship_type: Optional[str] = None,
                     filters: Optional[List[Dict[str, Any]]] = None,
                     limit: int = 100,
                     days_back: int = 90) -> List[Dict[str, Any]]:
    """Retrieve relationships from OpenCTI."""
    filters = _parse_filters(filters)
    logger.info(f"Tool: Retrieving relationships from OpenCTI for entity: {entity_id}, type: {relationship_type}")
    try:
        if entity_id:
            # If we have an entity ID, use the specific method for entity relationships
            result = _ingestors['relationship'].ingest_relationships_for_entity(
                entity_id=entity_id,
                relationship_type=relationship_type,
                include_raw=True
            )
        else:
            # Otherwise use the general method
            relationship_types = [relationship_type] if relationship_type else None
            result = _ingestors['relationship'].ingest_relationships(
                limit=limit,
                days_back=days_back,
                relationship_types=relationship_types,
                include_raw=True
            )

        # Limit results if needed
        if limit and len(result) > limit:
            result = result[:limit]

        logger.info(f"Retrieved {len(result)} relationships")
        return result
    except Exception as e:
        logger.error(f"Error retrieving relationships: {str(e)}")
        return []

# ===== Entity Tools =====

def get_entities(entity_type: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve entities of a specific type from OpenCTI."""
    logger.info(f"Tool: Retrieving up to {limit} entities of type {entity_type} from OpenCTI")
    try:
        # Use the OpenCTI connector from the indicator ingestor
        filters = [{"key": "entity_type", "values": [entity_type]}]
        result = _ingestors['indicator'].opencti.get_entities(filters=filters, first=limit)
        logger.info(f"Retrieved {len(result)} {entity_type} entities")
        return result
    except Exception as e:
        logger.error(f"Error retrieving {entity_type} entities: {str(e)}")
        return []

# ===== Create Tools =====

def create_report(
    name: str,
    description: str,
    published: str,
    report_class: str = "threat-report"
) -> Optional[Dict[str, Any]]:
    """Create a new report in OpenCTI.

    Required:
      - name
      - description
      - published (ISO timestamp)
    Optional:
      - report_class (defaults to 'threat-report')
    """
    report_data = {
        "name": name,
        "description": description,
        "published": published,
        "report_class": report_class,
    }
    logger.info(f"Tool: Creating new report: {name}")
    try:
        result = _ingestors['report'].opencti.create_report(report_data)
        if result:
            _ingestors['report'].invalidate_cache()
        return result
    except Exception as e:
        logger.error(f"Error creating report: {e}")
        return None

def create_indicator(
    name: str,
    pattern: str,
    pattern_type: str,
    valid_from: str,
    x_opencti_main_observable_type: str
) -> Optional[Dict[str, Any]]:
    """Create a new indicator in OpenCTI.

    Required:
      - name
      - pattern
      - pattern_type
      - valid_from (ISO-8601)
      - x_opencti_main_observable_type (e.g., 'IPv4-Addr', 'File', 'URL')
    """
    indicator_data = {
        "name": name,
        "pattern": pattern,
        "pattern_type": pattern_type,
        "valid_from": valid_from,
        "x_opencti_main_observable_type": x_opencti_main_observable_type,
    }
    logger.info(f"Tool: Creating new indicator: {name}")
    try:
        result = _ingestors['indicator'].opencti.create_indicator(indicator_data)
        if result:
            _ingestors['indicator'].invalidate_cache()
        return result
    except Exception as e:
        logger.error(f"Error creating indicator: {e}")
        return None

def entity_counts(days_back: Optional[int] = None) -> Dict[str, int]:
    """
    Get counts of different entity types in OpenCTI.
    
    Args:
        days_back: Optional number of days to look back. If None, returns all-time counts.
        
    Returns:
        Dictionary containing counts for each entity type.
    """
    logger.info(f"Tool: Getting entity counts{f' for past {days_back} days' if days_back else ''}")
    try:
        result = _ingestors['indicator'].opencti.entity_counts(days_back=days_back)
        logger.info(f"Entity counts: {result}")
        return result
    except Exception as e:
        logger.error(f"Error getting entity counts: {str(e)}")
        return {}

def clear_opencti_caches() -> None:
    """Clear all OpenCTI data caches."""
    logger.info("Tool: Clearing all OpenCTI data caches")
    try:
        clear_all_caches()
        logger.info("Successfully cleared all OpenCTI data caches")
    except Exception as e:
        logger.error(f"Error clearing OpenCTI caches: {str(e)}")
    return None



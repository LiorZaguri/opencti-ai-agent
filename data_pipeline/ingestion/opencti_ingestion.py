from core.utils.logger import setup_logger
from integrations.opencti import OpenCTIConnector
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import time
import re
from core.utils.company_profile import load_company_profile

logger = setup_logger(name="threat_ingestor", component_type="utils")

# Simple in-memory cache for ingestor results
_data_cache = {}
_cache_expiry = {}
DEFAULT_CACHE_TTL = 1800  # 30 minutes in seconds


def _assign_priority(score: float) -> str:
    if score >= 0.7:
        return "high"
    elif score >= 0.4:
        return "medium"
    else:
        return "low"


class BaseIngestor:
    """Base class for all ingestors with common functionality"""
    
    def __init__(self, use_cache: bool = True, cache_ttl: int = DEFAULT_CACHE_TTL):
        self.opencti = OpenCTIConnector()
        self.use_cache = use_cache
        self.cache_ttl = cache_ttl
    
    def _get_from_cache(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Get data from cache if available and not expired"""
        if not self.use_cache:
            return None
            
        current_time = time.time()
        if cache_key in _data_cache and current_time < _cache_expiry.get(cache_key, 0):
            logger.debug(f"Cache hit for {cache_key}")
            return _data_cache[cache_key]
        return None
    
    def _store_in_cache(self, cache_key: str, data: List[Dict[str, Any]]) -> None:
        """Store data in cache with expiry time"""
        if not self.use_cache:
            return
            
        _data_cache[cache_key] = data
        _cache_expiry[cache_key] = time.time() + self.cache_ttl
        logger.debug(f"Cached data for {cache_key}, expires in {self.cache_ttl}s")
    
    def invalidate_cache(self) -> None:
        """Clear specific ingestor's cache entries"""
        prefix = self.__class__.__name__
        keys_to_delete = [k for k in list(_data_cache.keys()) if k.startswith(prefix)]
        for key in keys_to_delete:
            if key in _data_cache:
                del _data_cache[key]
            if key in _cache_expiry:
                del _cache_expiry[key]
        logger.info(f"Invalidated cache for {prefix}, {len(keys_to_delete)} entries removed")
    

class ThreatActorIngestor(BaseIngestor):
    def ingest_threat_actors(self, limit: int = 50, include_raw: bool = False) -> List[Dict[str, Any]]:
        cache_key = f"{self.__class__.__name__}:actors:{limit}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
            
        logger.info("Fetching threat actors from OpenCTI...")
        actors = self.opencti.get_threat_actors(limit=limit)

        if not actors:
            logger.info("No threat actors found.")
            return []

        logger.info(f"Retrieved {len(actors)} threat actors")
        structured_actors = []

        for actor in actors:
            structured = self._process_actor(actor, include_raw)
            if structured:
                structured_actors.append(structured)

        logger.info(f"Structured {len(structured_actors)} threat actors")
        self._store_in_cache(cache_key, structured_actors)
        return structured_actors

    def _process_actor(self, actor: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        # Use imported function rather than lazy import
        profile = load_company_profile()
        relevance_score = 0
        matched = []

        # Matching logic
        if profile.get("industry") and profile["industry"].lower() in actor.get("description", "").lower():
            relevance_score += 0.4
            matched.append("industry")

        if profile.get("region") and profile["region"].lower() in actor.get("description", "").lower():
            relevance_score += 0.3
            matched.append("region")

        for focus in profile.get("threat_priority", []):
            if focus.lower() in actor.get("description", "").lower():
                relevance_score += 0.3
                matched.append("threat_priority")
                break

        for asset in profile.get("critical_assets", []):
            if asset.lower() in actor.get("description", "").lower():
                relevance_score += 0.2
                matched.append("critical_assets")
                break

        for incident in profile.get("past_incidents", []):
            if incident.lower() in actor.get("description", "").lower():
                relevance_score += 0.1
                matched.append("past_incidents")
                break

        for tech in profile.get("tech_stack", []):
            if tech.lower() in actor.get("description", "").lower():
                relevance_score += 0.15
                matched.append("tech_stack")
                break

        # Create basic structured data
        structured = {
            "type": "threat_actor",
            "id": actor.get("id"),
            "name": actor.get("name"),
            "description": actor.get("description", ""),
            "source": "OpenCTI",
            "created_at": actor.get("created"),
            "modified_at": actor.get("modified", actor.get("created")),
            "confidence": actor.get("confidence", 50),
            "labels": actor.get("labels", []),
            "relevance_score": round(relevance_score, 2),
            "priority": _assign_priority(relevance_score),
            "outside_profile_scope": relevance_score < 0.4,
            "matched_profile_fields": matched,
        }
        
        # Include raw data only if requested
        if include_raw:
            structured["raw_data"] = actor

        logger.debug(f"Processed actor: {actor.get('name')}")
        return structured


class IndicatorIngestor(BaseIngestor):
    def ingest_indicators(self, limit: int = 100, include_raw: bool = False, 
                           days_back: int = 90) -> List[Dict[str, Any]]:
        cache_key = f"{self.__class__.__name__}:indicators:{limit}:{days_back}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
        
        # Date filter for recent indicators
        date_filter = None
        if days_back > 0:
            start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            date_filter = [
                {
                    "key": "created_at",
                    "values": [start_date],
                    "operator": "gt"
                }
            ]
            
        logger.info(f"Fetching indicators from OpenCTI (last {days_back} days)...")
        
        try:
            indicators = self.opencti.get_indicators(filters=date_filter)
            
            if not indicators:
                logger.info("No indicators found.")
                return []
                
            # Limit results if needed
            if limit and len(indicators) > limit:
                indicators = indicators[:limit]
                
            logger.info(f"Retrieved {len(indicators)} indicators")
            structured_indicators = []
            
            for indicator in indicators:
                try:
                    structured = self._process_indicator(indicator, include_raw)
                    if structured:
                        structured_indicators.append(structured)
                except Exception as e:
                    logger.error(f"Error processing indicator {indicator.get('id', 'unknown')}: {str(e)}")
                    
            logger.info(f"Structured {len(structured_indicators)} indicators")
            self._store_in_cache(cache_key, structured_indicators)
            return structured_indicators
        except Exception as e:
            logger.error(f"Error retrieving indicators: {str(e)}")
            return []
        
    def _process_indicator(self, indicator: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        # Extract pattern and pattern type
        pattern = indicator.get("pattern", "")
        pattern_type = indicator.get("pattern_type", "unknown")
        
        # Determine indicator category based on pattern
        category = "unknown"
        value = ""
        
        if pattern_type == "stix":
            # Parse STIX pattern to extract value
            if "[file:hashes" in pattern:
                category = "file_hash"
                # Extract hash value with regex processing
                match = re.search(r"'([a-fA-F0-9]+)'", pattern)
                if match:
                    value = match.group(1)
            elif "[url:value" in pattern:
                category = "url"
                match = re.search(r"'(https?://[^']+)'", pattern)
                if match:
                    value = match.group(1)
            elif "[domain-name:value" in pattern:
                category = "domain"
                match = re.search(r"'([^']+)'", pattern)
                if match:
                    value = match.group(1)
            elif "[ipv4-addr:value" in pattern or "[ipv6-addr:value" in pattern:
                category = "ip"
                match = re.search(r"'([^']+)'", pattern)
                if match:
                    value = match.group(1)
            elif "[email-addr:value" in pattern:
                category = "email"
                match = re.search(r"'([^']+)'", pattern)
                if match:
                    value = match.group(1)
        
        # Create structured response
        structured = {
            "type": "indicator",
            "id": indicator.get("id"),
            "name": indicator.get("name", "Unnamed Indicator"),
            "description": indicator.get("description", ""),
            "pattern": pattern,
            "pattern_type": pattern_type,
            "category": category,
            "value": value,
            "valid_from": indicator.get("valid_from"),
            "valid_until": indicator.get("valid_until"),
            "created_at": indicator.get("created"),
            "modified_at": indicator.get("modified", indicator.get("created")),
            "revoked": indicator.get("revoked", False),
            "confidence": indicator.get("confidence", 50),
            "labels": indicator.get("labels", []),
            "score": indicator.get("x_opencti_score", 50),
        }
        
        # Set severity based on score
        if structured["score"] >= 75:
            structured["severity"] = "high"
        elif structured["score"] >= 50:
            structured["severity"] = "medium"
        else:
            structured["severity"] = "low"
            
        # Include raw data if requested
        if include_raw:
            structured["raw_data"] = indicator
            
        logger.debug(f"Processed indicator: {indicator.get('name')}")
        return structured


class ObservableIngestor(BaseIngestor):
    def ingest_observables(self, types: List[str] = None, limit: int = 100, 
                           include_raw: bool = False) -> List[Dict[str, Any]]:
        """
        Retrieve observables from OpenCTI
        
        Args:
            types: List of observable types to fetch (ip, domain, url, file, etc.)
            limit: Maximum number of observables to return
            include_raw: Whether to include raw data in the response
            
        Returns:
            List of structured observable dictionaries
        """
        # Build cache key based on parameters
        type_key = "_".join(types) if types else "all"
        cache_key = f"{self.__class__.__name__}:observables:{type_key}:{limit}"
        
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
            
        # Prepare filters for observable types
        filters = None
        if types:
            filters = [{
                "key": "entity_type", 
                "values": types
            }]
            
        logger.info(f"Fetching observables from OpenCTI...")
        
        try:
            observables = self.opencti.get_observables(filters=filters)
            
            if not observables:
                logger.info("No observables found.")
                return []
                
            # Limit results if needed
            if limit and len(observables) > limit:
                observables = observables[:limit]
                
            logger.info(f"Retrieved {len(observables)} observables")
            structured_observables = []
            
            for observable in observables:
                try:
                    structured = self._process_observable(observable, include_raw)
                    if structured:
                        structured_observables.append(structured)
                except Exception as e:
                    logger.error(f"Error processing observable {observable.get('id', 'unknown')}: {str(e)}")
                    
            logger.info(f"Structured {len(structured_observables)} observables")
            self._store_in_cache(cache_key, structured_observables)
            return structured_observables
        except Exception as e:
            logger.error(f"Error retrieving observables: {str(e)}")
            return []
            
    def _process_observable(self, observable: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        """Process a raw observable into a structured format"""
        # Extract observable type and value
        entity_type = observable.get("entity_type", "Unknown")
        value = ""
        
        # Determine value based on entity type
        if entity_type == "StixFile":
            hashes = observable.get("hashes", [])
            # Handle both list and dictionary formats for hashes
            if isinstance(hashes, dict):
                hashes = [hashes]
                
            for hash_obj in hashes:
                if hash_obj.get("algorithm") == "SHA-256":
                    value = hash_obj.get("hash", "")
                    break
                elif hash_obj.get("algorithm") == "MD5":
                    value = hash_obj.get("hash", "")
            
            if not value and observable.get("name"):
                value = observable.get("name")
        elif entity_type in ["IPv4-Addr", "IPv6-Addr"]:
            value = observable.get("value", "")
        elif entity_type == "Domain-Name":
            value = observable.get("value", "")
        elif entity_type == "URL":
            value = observable.get("value", "")
        elif entity_type == "Email-Addr":
            value = observable.get("value", "")
        else:
            value = observable.get("value", observable.get("name", "Unknown"))
            
        # Create structured response
        structured = {
            "type": "observable",
            "id": observable.get("id", f"unknown-{hash(str(observable))}"),
            "entity_type": entity_type,
            "value": value,
            "created_at": observable.get("created_at"),
            "updated_at": observable.get("updated_at", observable.get("created_at")),
            "labels": [],  # Initialize with empty list
            "x_opencti_score": observable.get("x_opencti_score", 0),
            "description": observable.get("description", ""),
        }
        
        # Safely extract labels if they exist
        object_label = observable.get("objectLabel", {})
        if isinstance(object_label, dict) and "edges" in object_label:
            structured["labels"] = [edge.get("node", {}) for edge in object_label.get("edges", [])]
        
        # Include raw data if requested
        if include_raw:
            structured["raw_data"] = observable
            
        logger.debug(f"Processed observable: {value}")
        return structured


class VulnerabilityIngestor(BaseIngestor):
    def ingest_vulnerabilities(self, limit: int = 50, include_raw: bool = False) -> List[Dict[str, Any]]:
        """Retrieve vulnerabilities from OpenCTI"""
        cache_key = f"{self.__class__.__name__}:vulnerabilities:{limit}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
            
        logger.info("Fetching vulnerabilities from OpenCTI...")
        
        # We need to use a special query since vulnerabilities aren't directly exposed
        # in the Python client in the same way as other entities
        custom_filters = [{
            "key": "entity_type",
            "values": ["Vulnerability"]
        }]
        
        try:
            vulnerabilities = self.opencti.get_entities(filters=custom_filters, first=limit)
            
            if not vulnerabilities:
                logger.info("No vulnerabilities found.")
                return []
                
            logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities")
            structured_vulnerabilities = []
            
            for vuln in vulnerabilities:
                try:
                    structured = self._process_vulnerability(vuln, include_raw)
                    if structured:
                        structured_vulnerabilities.append(structured)
                except Exception as e:
                    logger.error(f"Error processing vulnerability {vuln.get('id', 'unknown')}: {str(e)}")
                    
            logger.info(f"Structured {len(structured_vulnerabilities)} vulnerabilities")
            self._store_in_cache(cache_key, structured_vulnerabilities)
            return structured_vulnerabilities
        except Exception as e:
            logger.error(f"Error retrieving vulnerabilities: {str(e)}")
            return []
        
    def _process_vulnerability(self, vuln: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        # Default CVSS value
        cvss = 0.0
        
        # Try to extract CVSS score from different possible locations
        if "x_opencti_base_score" in vuln:
            cvss = float(vuln.get("x_opencti_base_score", 0.0))
        elif "cvss" in vuln:
            cvss = float(vuln.get("cvss", 0.0))
        
        # Determine severity based on CVSS
        if cvss >= 9.0:
            severity = "critical"
        elif cvss >= 7.0:
            severity = "high"
        elif cvss >= 4.0:
            severity = "medium"
        elif cvss > 0:
            severity = "low"
        else:
            severity = "unknown"
            
        # Extract CVE ID from name or external references
        cve_id = ""
        if "CVE-" in vuln.get("name", ""):
            cve_id = vuln.get("name", "")
        elif "external_references" in vuln and vuln["external_references"]:
            for ref in vuln["external_references"]:
                if ref.get("source_name") == "cve" or "CVE-" in ref.get("external_id", ""):
                    cve_id = ref.get("external_id", "")
                    break
        
        # Extract object references if available
        object_refs = []
        if "objectRefs" in vuln:
            object_refs = vuln["objectRefs"]
        else:
            # Get relationships for this vulnerability
            try:
                related_objects = self.opencti.relationship.list(entity_id=vuln.get("id"))
                object_refs = related_objects
            except Exception as e:
                logger.error(f"Error getting related objects for vulnerability {vuln.get('id')}: {e}")
        
        # Create structured response
        structured = {
            "type": "vulnerability",
            "id": vuln.get("id"),
            "name": vuln.get("name", "Unnamed Vulnerability"),
            "cve_id": cve_id,
            "description": vuln.get("description", ""),
            "created_at": vuln.get("created_at"),
            "modified_at": vuln.get("modified_at", vuln.get("created_at")),
            "cvss": cvss,
            "severity": severity,
            "published": vuln.get("published", vuln.get("created_at")),
            "labels": vuln.get("objectLabel", {}).get("edges", []),
            "object_refs": object_refs,
            "object_refs_count": len(object_refs)
        }
        
        # Include raw data if requested
        if include_raw:
            structured["raw_data"] = vuln
            
        logger.debug(f"Processed vulnerability: {vuln.get('name')}")
        return structured


class ReportIngestor(BaseIngestor):
    def ingest_reports(self, limit: int = 20, include_raw: bool = False, 
                       days_back: int = 90) -> List[Dict[str, Any]]:
        """Retrieve reports from OpenCTI"""
        cache_key = f"{self.__class__.__name__}:reports:{limit}:{days_back}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
            
        # Date filter for recent reports
        date_filter = []
        if days_back > 0:
            start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            date_filter = [{
                "key": "published",
                "values": [start_date],
                "operator": "gt"
            }]
            
        logger.info(f"Fetching reports from OpenCTI (last {days_back} days)...")
        
        # Use entity filter for Reports
        entity_filter = [{
            "key": "entity_type",
            "values": ["Report"]
        }]
        
        filters = date_filter + entity_filter if date_filter else entity_filter
        
        try:
            reports = self.opencti.get_entities(filters=filters, first=limit)
            
            if not reports:
                logger.info("No reports found.")
                return []
                
            logger.info(f"Retrieved {len(reports)} reports")
            structured_reports = []
            
            for report in reports:
                try:
                    structured = self._process_report(report, include_raw)
                    if structured:
                        structured_reports.append(structured)
                except Exception as e:
                    logger.error(f"Error processing report {report.get('id', 'unknown')}: {str(e)}")
                    
            logger.info(f"Structured {len(structured_reports)} reports")
            self._store_in_cache(cache_key, structured_reports)
            return structured_reports
        except Exception as e:
            logger.error(f"Error retrieving reports: {str(e)}")
            return []
        
    def _process_report(self, report: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        # Extract object references if available
        object_refs = []
        if "objectRefs" in report:
            object_refs = report["objectRefs"]
        else:
            # Get relationships for this report
            try:
                related_objects = self.opencti._get_container_object_refs(report.get("id"))
                object_refs = related_objects
            except Exception as e:
                logger.error(f"Error getting related objects for report {report.get('id')}: {e}")
        
        # Create structured response
        structured = {
            "type": "report",
            "id": report.get("id"),
            "name": report.get("name", "Unnamed Report"),
            "description": report.get("description", ""),
            "published": report.get("published"),
            "created_at": report.get("created_at"),
            "modified_at": report.get("modified_at", report.get("created_at")),
            "report_types": report.get("report_types", []),
            "confidence": report.get("confidence", 50),
            "object_refs": object_refs,
            "object_refs_count": len(object_refs),
            "labels": report.get("objectLabel", {}).get("edges", []),
        }
        
        # Include raw data if requested
        if include_raw:
            structured["raw_data"] = report
            
        logger.debug(f"Processed report: {report.get('name')}")
        return structured


class RelationshipIngestor(BaseIngestor):
    def ingest_relationships(self, 
                            limit: int = 100, 
                            include_raw: bool = False, 
                            days_back: int = 90,
                            relationship_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Ingest relationships from OpenCTI
        
        Args:
            limit: The maximum number of relationships to retrieve
            include_raw: Whether to include the raw JSON data in the structured data
            days_back: Only fetch relationships created within this many days
            relationship_types: List of specific relationship types to retrieve
            
        Returns:
            List of structured relationship data
        """
        # Create cache key based on parameters
        cache_key = f"{self.__class__.__name__}:relationships:{limit}:{days_back}:{relationship_types}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
            
        # Build filters
        filters = []
        
        # Date filter
        if days_back > 0:
            start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            filters.append({
                "key": "created_at",
                "values": [start_date],
                "operator": "gt"
            })
            
        # Relationship type filter
        if relationship_types:
            filters.append({
                "key": "relationship_type",
                "values": relationship_types
            })
        
        logger.info(f"Fetching relationships from OpenCTI (last {days_back} days)...")
        
        try:
            relationships = self.opencti.get_relationships(filters=filters if filters else None)
            
            if not relationships:
                logger.info("No relationships found.")
                return []
                
            # Limit results if needed
            if limit and len(relationships) > limit:
                relationships = relationships[:limit]
                
            logger.info(f"Retrieved {len(relationships)} relationships")
            structured_relationships = []
            
            for rel in relationships:
                try:
                    structured = self._process_relationship(rel, include_raw)
                    if structured:
                        structured_relationships.append(structured)
                except Exception as e:
                    rel_id = rel.get('id', 'unknown')
                    logger.error(f"Error processing relationship {rel_id}: {str(e)}")
                    
            logger.info(f"Structured {len(structured_relationships)} relationships")
            self._store_in_cache(cache_key, structured_relationships)
            return structured_relationships
        except Exception as e:
            logger.error(f"Error retrieving relationships: {str(e)}")
            return []
        
    def _process_relationship(self, relationship: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        # Check if this is an actual relationship or just an ID reference
        if isinstance(relationship, str):
            # Just an ID reference from object_refs
            return {
                "type": "relationship_ref",
                "id": relationship,
            }
            
        # Extract the basic relationship data
        structured = {
            "type": "relationship",
            "id": relationship.get("id"),
            "relationship_type": relationship.get("relationship_type"),
            "from": {
                "id": relationship.get("fromId"),
                "type": relationship.get("fromType"),
            },
            "to": {
                "id": relationship.get("toId"),
                "type": relationship.get("toType"),
            },
            "created_at": relationship.get("created_at"),
            "modified_at": relationship.get("modified_at", relationship.get("created_at")),
            "confidence": relationship.get("confidence", 50),
            "description": relationship.get("description", ""),
        }
        
        # Include raw data if requested
        if include_raw:
            structured["raw_data"] = relationship
            
        logger.debug(f"Processed relationship: {relationship.get('id')}")
        return structured

    def ingest_relationships_for_entity(self, entity_id: str, relationship_type: str = None, 
                                       include_raw: bool = False) -> List[Dict[str, Any]]:
        """Retrieve relationships for a specific entity"""
        cache_key = f"{self.__class__.__name__}:relationships:{entity_id}:{relationship_type or 'all'}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
            
        logger.info(f"Fetching relationships for entity {entity_id}...")
        
        try:
            relationships = self.opencti.get_relationships(entity_id=entity_id, relationship_type=relationship_type)
            
            if not relationships:
                logger.info(f"No relationships found for entity {entity_id}.")
                return []
                
            logger.info(f"Retrieved {len(relationships)} relationships")
            structured_relationships = []
            
            for relationship in relationships:
                try:
                    structured = self._process_relationship(relationship, include_raw)
                    if structured:
                        structured_relationships.append(structured)
                except Exception as e:
                    rel_id = relationship.get('id', 'unknown')
                    logger.error(f"Error processing relationship {rel_id}: {str(e)}")
                    
            logger.info(f"Structured {len(structured_relationships)} relationships")
            self._store_in_cache(cache_key, structured_relationships)
            return structured_relationships
        except Exception as e:
            logger.error(f"Error retrieving relationships for entity {entity_id}: {str(e)}")
            return []


# Function to clean and invalidate all caches
def clear_all_caches():
    """Clear all in-memory caches for ingestors"""
    global _data_cache, _cache_expiry
    _data_cache = {}
    _cache_expiry = {}
    logger.info("Cleared all data ingestor caches")

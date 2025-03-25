from typing import Dict, Any, List
from core.utils.logger import setup_logger
from core.data_pipeline.ingestion.opencti.base import BaseIngestor

logger = setup_logger(name="opencti_observable", component_type="utils")

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
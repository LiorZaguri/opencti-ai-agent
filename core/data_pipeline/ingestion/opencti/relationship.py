from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from core.utils.logger import setup_logger
from core.data_pipeline.ingestion.opencti.base import BaseIngestor

logger = setup_logger(name="opencti_relationship", component_type="utils")

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
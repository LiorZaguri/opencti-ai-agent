from pycti import OpenCTIApiClient
from config.settings import OPENCTI_BASE_URL, OPENCTI_API_KEY
from utils.logger import setup_logger

logger = setup_logger(name="OpenCTIConnector", component_type="utils")

def _prepare_filters(filters):
    """
    Format filters according to OpenCTI's FilterGroup structure.
    
    As per the documentation at https://docs.opencti.io/latest/reference/filters/
    OpenCTI 5.12+ requires filters to be in FilterGroup format.
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


class OpenCTIConnector:
    def __init__(self):
        """Initialize the OpenCTI connector."""
        self.client = OpenCTIApiClient(
            url=OPENCTI_BASE_URL,
            token=OPENCTI_API_KEY
        )
        logger.debug("OpenCTI connector initialized successfully")

    def get_threat_actors(self, filters=None, limit: int = 50):
        """Retrieve threat actors from OpenCTI."""
        logger.debug(f"Retrieving threat actors with filters: {filters} and limit: {limit}")
        try:
            # Try a simple direct query with no filters first
            logger.debug("Attempting simple direct query for threat actors with no filters")
            result = self.client.threat_actor.list(first=10)
            if result:
                logger.debug(f"Direct query returned {len(result)} threat actors")
            else:
                logger.debug("Direct query returned no threat actors")
            
            # Now try with filters if provided
            if filters:
                prepared_filters = _prepare_filters(filters)
                logger.debug(f"Using prepared filters: {prepared_filters}")
                result = self.client.threat_actor.list(filters=prepared_filters, first=limit)
            else:
                result = self.client.threat_actor.list(first=limit)
            
            logger.debug(f"Successfully retrieved {len(result)} threat actors")
            return result
        except Exception as e:
            logger.error(f"Error retrieving threat actors: {str(e)}")
            return []

    def get_indicators(self, filters=None):
        """Retrieve indicators from OpenCTI."""
        logger.debug(f"Retrieving indicators with filters: {filters}")
        try:
            if filters:
                filters = _prepare_filters(filters)
                result = self.client.indicator.list(filters=filters)
            else:
                result = self.client.indicator.list()
            logger.debug(f"Successfully retrieved {len(result)} indicators")
            return result
        except Exception as e:
            logger.error(f"Error retrieving indicators: {str(e)}")
            return []

    def get_observables(self, filters=None):
        """Retrieve observables from OpenCTI."""
        logger.debug(f"Retrieving observables with filters: {filters}")
        try:
            if filters:
                filters = _prepare_filters(filters)
                result = self.client.stix_cyber_observable.list(filters=filters)
            else:
                result = self.client.stix_cyber_observable.list()
            logger.debug(f"Successfully retrieved {len(result)} observables")
            return result
        except Exception as e:
            logger.error(f"Error retrieving observables: {str(e)}")
            return []

    def get_entities(self, filters=None, first: int = 50, orderBy: str = "created_at", orderMode: str = "desc"):
        """
        Retrieve STIX domain objects from OpenCTI.
        
        This is a generic method for retrieving entities that don't have specific endpoints
        such as vulnerabilities, reports, etc.
        """
        logger.debug(f"Retrieving entities with filters: {filters}, limit: {first}")
        try:
            if filters:
                filters = _prepare_filters(filters)
                result = self.client.stix_domain_object.list(
                    filters=filters, 
                    first=first,
                    orderBy=orderBy,
                    orderMode=orderMode
                )
            else:
                result = self.client.stix_domain_object.list(
                    first=first,
                    orderBy=orderBy,
                    orderMode=orderMode
                )
            logger.debug(f"Successfully retrieved {len(result)} entities")
            return result
        except Exception as e:
            logger.error(f"Error retrieving entities: {str(e)}")
            return []

    def _get_container_object_refs(self, container_id):
        """Extract object references from container entities like reports."""
        logger.debug(f"Getting object references for container: {container_id}")
        try:
            if container_id.startswith("report--"):
                logger.debug(f"Reading report: {container_id}")
                container = self.client.report.read(id=container_id)
            elif container_id.startswith("grouping--"):
                logger.debug(f"Reading grouping: {container_id}")
                container = self.client.grouping.read(id=container_id)
            elif container_id.startswith("case--"):
                logger.debug(f"Reading case: {container_id}")
                try:
                    container = self.client.case.read(id=container_id)
                except AttributeError:
                    logger.warning("Case entity type not supported in this OpenCTI version")
                    return []
            else:
                logger.warning(f"Unsupported container type: {container_id}")
                return []
            object_refs = container.get("objectRefs", [])
            logger.debug(f"Found {len(object_refs)} object references in container {container_id}")
            return object_refs
        except Exception as e:
            logger.error(f"Error retrieving container object references for {container_id}: {str(e)}")
            return []

    def get_relationships(self, entity_id=None, relationship_type=None, filters=None):
        """
        Retrieve relationships from OpenCTI.
        
        Args:
            entity_id (str, optional): The STIX ID of an entity to get relationships for
            relationship_type (str, optional): Filter by relationship type
            filters (list, optional): Direct filters to use instead of entity_id/relationship_type
            
        Returns:
            list: List of relationships
        """
        # If entity_id is provided, check if it's a container
        if entity_id:
            if entity_id.startswith("report--") or entity_id.startswith("grouping--") or entity_id.startswith("case--"):
                logger.debug(f"Entity {entity_id} is a container, getting object references")
                return self._get_container_object_refs(entity_id)
            
            # Entity is not a container, build filters
            if not filters:
                filters = [{
                    'key': 'fromId',
                    'values': [entity_id]
                }]
            
                if relationship_type:
                    filters.append({
                        'key': 'relationship_type',
                        'values': [relationship_type]
                    })
        
        # Use the provided filters or the built ones
        if filters:
            try:
                logger.debug(f"Retrieving relationships with filters: {filters}")
                filters = _prepare_filters(filters)
                result = self.client.stix_core_relationship.list(filters=filters)
                logger.debug(f"Found {len(result)} relationships")
                return result
            except Exception as e:
                logger.error(f"Error retrieving relationships: {str(e)}")
                return []
        else:
            # No filters, just get all relationships
            try:
                logger.debug("Retrieving all relationships")
                result = self.client.stix_core_relationship.list()
                logger.debug(f"Found {len(result)} relationships")
                return result
            except Exception as e:
                logger.error(f"Error retrieving relationships: {str(e)}")
                return []

    def create_report(self, report_data):
        """Create a new report in OpenCTI."""
        logger.info(f"Creating new report: {report_data.get('name', 'unnamed')}")
        try:
            result = self.client.report.create(**report_data)
            logger.info(f"Successfully created report with ID: {result.get('id')}")
            return result
        except Exception as e:
            logger.error(f"Error creating report: {str(e)}")
            return None

    def create_indicator(self, indicator_data):
        """Create a new indicator in OpenCTI."""
        logger.info(f"Creating new indicator: {indicator_data.get('name', 'unnamed')}")
        try:
            result = self.client.indicator.create(**indicator_data)
            logger.info(f"Successfully created indicator with ID: {result.get('id')}")
            return result
        except Exception as e:
            logger.error(f"Error creating indicator: {str(e)}")
            return None

    def test_entity_counts(self, limit=10):
        """
        Debug method to count different entity types available through the API.
        """
        try:
            results = {
                "all_entities": len(self.client.stix_domain_object.list(first=100)),
                "threat_actors": len(self.client.threat_actor.list(first=limit)),
                "indicators": len(self.client.indicator.list(first=limit)),
                "observables": len(self.client.stix_cyber_observable.list(first=limit)),
                "vulnerabilities": len(self.client.vulnerability.list(first=limit)) if hasattr(self.client, 'vulnerability') else "N/A",
                "reports": len(self.client.report.list(first=limit)),
                "malwares": len(self.client.malware.list(first=limit)),
                "intrusion_sets": len(self.client.intrusion_set.list(first=limit)),
                "attack_patterns": len(self.client.attack_pattern.list(first=limit)),
                "relationships": len(self.client.stix_core_relationship.list(first=limit)),
            }
            logger.debug(f"Entity counts in OpenCTI: {results}")
            return results
        except Exception as e:
            logger.error(f"Error counting entities: {str(e)}")
            return {}
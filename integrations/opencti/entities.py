"""
Entity-specific methods for the OpenCTI client.

This module contains methods for working with specific STIX entity types in OpenCTI,
such as threat actors, indicators, observables, etc.
"""

from core.utils.logger import setup_logger
from integrations.opencti.filters import prepare_filters

logger = setup_logger(name="OpenCTI_Entities", component_type="utils")


class ThreatActorMethods:
    """Methods for working with threat actors in OpenCTI."""
    
    def __init__(self, client):
        """
        Initialize with an OpenCTI client instance.
        
        Args:
            client: The pycti.OpenCTIApiClient instance
        """
        self.client = client
        
    def list(self, filters=None, limit: int = 50):
        """
        Retrieve threat actors from OpenCTI.
        
        Args:
            filters: Optional filters to apply
            limit: Maximum number of results to return
            
        Returns:
            List of threat actor objects
        """
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
                prepared_filters = prepare_filters(filters)
                logger.debug(f"Using prepared filters: {prepared_filters}")
                result = self.client.threat_actor.list(filters=prepared_filters, first=limit)
            else:
                result = self.client.threat_actor.list(first=limit)
            
            logger.debug(f"Successfully retrieved {len(result)} threat actors")
            return result
        except Exception as e:
            logger.error(f"Error retrieving threat actors: {str(e)}")
            return []


class IndicatorMethods:
    """Methods for working with indicators in OpenCTI."""
    
    def __init__(self, client):
        """
        Initialize with an OpenCTI client instance.
        
        Args:
            client: The pycti.OpenCTIApiClient instance
        """
        self.client = client
        
    def list(self, filters=None):
        """
        Retrieve indicators from OpenCTI.
        
        Args:
            filters: Optional filters to apply
            
        Returns:
            List of indicator objects
        """
        logger.debug(f"Retrieving indicators with filters: {filters}")
        try:
            if filters:
                prepared_filters = prepare_filters(filters)
                result = self.client.indicator.list(filters=prepared_filters)
            else:
                result = self.client.indicator.list()
            logger.debug(f"Successfully retrieved {len(result)} indicators")
            return result
        except Exception as e:
            logger.error(f"Error retrieving indicators: {str(e)}")
            return []
            
    def create(self, indicator_data):
        """
        Create a new indicator in OpenCTI.
        
        Args:
            indicator_data: Dictionary of indicator properties
            
        Returns:
            The created indicator object or None on error
        """
        logger.info(f"Creating new indicator: {indicator_data.get('name', 'unnamed')}")
        try:
            result = self.client.indicator.create(**indicator_data)
            logger.info(f"Successfully created indicator with ID: {result.get('id')}")
            return result
        except Exception as e:
            logger.error(f"Error creating indicator: {str(e)}")
            return None


class ObservableMethods:
    """Methods for working with observables in OpenCTI."""
    
    def __init__(self, client):
        """
        Initialize with an OpenCTI client instance.
        
        Args:
            client: The pycti.OpenCTIApiClient instance
        """
        self.client = client
        
    def list(self, filters=None):
        """
        Retrieve observables from OpenCTI.
        
        Args:
            filters: Optional filters to apply
            
        Returns:
            List of observable objects
        """
        logger.debug(f"Retrieving observables with filters: {filters}")
        try:
            if filters:
                prepared_filters = prepare_filters(filters)
                result = self.client.stix_cyber_observable.list(filters=prepared_filters)
            else:
                result = self.client.stix_cyber_observable.list()
            logger.debug(f"Successfully retrieved {len(result)} observables")
            return result
        except Exception as e:
            logger.error(f"Error retrieving observables: {str(e)}")
            return []


class EntityMethods:
    """Methods for working with generic STIX entities in OpenCTI."""
    
    def __init__(self, client):
        """
        Initialize with an OpenCTI client instance.
        
        Args:
            client: The pycti.OpenCTIApiClient instance
        """
        self.client = client
        
    def list(self, filters=None, first: int = 50, orderBy: str = "created_at", orderMode: str = "desc"):
        """
        Retrieve STIX domain objects from OpenCTI.
        
        This is a generic method for retrieving entities that don't have specific endpoints
        such as vulnerabilities, reports, etc.
        
        Args:
            filters: Optional filters to apply
            first: Maximum number of results to return
            orderBy: Field to order results by
            orderMode: Order direction (asc/desc)
            
        Returns:
            List of STIX domain objects
        """
        logger.debug(f"Retrieving entities with filters: {filters}, limit: {first}")
        try:
            if filters:
                prepared_filters = prepare_filters(filters)
                result = self.client.stix_domain_object.list(
                    filters=prepared_filters, 
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


class ReportMethods:
    """Methods for working with reports in OpenCTI."""
    
    def __init__(self, client):
        """
        Initialize with an OpenCTI client instance.
        
        Args:
            client: The pycti.OpenCTIApiClient instance
        """
        self.client = client
        
    def create(self, report_data):
        """
        Create a new report in OpenCTI.
        
        Args:
            report_data: Dictionary of report properties
            
        Returns:
            The created report object or None on error
        """
        logger.info(f"Creating new report: {report_data.get('name', 'unnamed')}")
        try:
            result = self.client.report.create(**report_data)
            logger.info(f"Successfully created report with ID: {result.get('id')}")
            return result
        except Exception as e:
            logger.error(f"Error creating report: {str(e)}")
            return None
            
            
class RelationshipMethods:
    """Methods for working with relationships in OpenCTI."""
    
    def __init__(self, client):
        """
        Initialize with an OpenCTI client instance.
        
        Args:
            client: The pycti.OpenCTIApiClient instance
        """
        self.client = client
        
    def _get_container_object_refs(self, container_id):
        """
        Extract object references from container entities like reports.
        
        Args:
            container_id: The ID of the container object
            
        Returns:
            List of object references
        """
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
            elif container_id.startswith("vulnerability--"):
                logger.debug(f"Reading vulnerability: {container_id}")
                try:
                    if hasattr(self.client, 'vulnerability'):
                        container = self.client.vulnerability.read(id=container_id)
                    else:
                        # Fallback to stix_domain_object
                        container = self.client.stix_domain_object.read(id=container_id)
                except Exception as e:
                    logger.warning(f"Error reading vulnerability container: {e}")
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
        
    def list(self, entity_id=None, relationship_type=None, filters=None):
        """
        Retrieve relationships from OpenCTI.
        
        Args:
            entity_id: The STIX ID of an entity to get relationships for
            relationship_type: Filter by relationship type
            filters: Direct filters to use instead of entity_id/relationship_type
            
        Returns:
            List of relationships
        """
        # If entity_id is provided, check if it's a container
        if entity_id:
            if entity_id.startswith("report--") or entity_id.startswith("grouping--") or entity_id.startswith("case--") or entity_id.startswith("vulnerability--"):
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
                prepared_filters = prepare_filters(filters)
                result = self.client.stix_core_relationship.list(filters=prepared_filters)
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
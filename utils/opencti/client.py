"""
OpenCTI API Client.

This module provides the main OpenCTIConnector class for interacting with the OpenCTI platform.
"""

from pycti import OpenCTIApiClient
from config.settings import OPENCTI_BASE_URL, OPENCTI_API_KEY
from utils.logger import setup_logger
from utils.opencti.entities import (
    ThreatActorMethods,
    IndicatorMethods,
    ObservableMethods,
    EntityMethods,
    ReportMethods,
    RelationshipMethods
)

logger = setup_logger(name="OpenCTIConnector", component_type="utils")


class OpenCTIConnector:
    """Main client for interacting with the OpenCTI platform."""
    
    def __init__(self):
        """Initialize the OpenCTI connector."""
        self.client = OpenCTIApiClient(
            url=OPENCTI_BASE_URL,
            token=OPENCTI_API_KEY
        )
        logger.debug("OpenCTI connector initialized successfully")
        
        # Initialize entity handlers
        self._threat_actor = ThreatActorMethods(self.client)
        self._indicator = IndicatorMethods(self.client)
        self._observable = ObservableMethods(self.client)
        self._entity = EntityMethods(self.client)
        self._report = ReportMethods(self.client)
        self._relationship = RelationshipMethods(self.client)
    
    @property
    def threat_actor(self):
        """Access threat actor methods."""
        return self._threat_actor
        
    @property
    def indicator(self):
        """Access indicator methods."""
        return self._indicator
        
    @property
    def observable(self):
        """Access observable methods."""
        return self._observable
        
    @property
    def entity(self):
        """Access entity methods."""
        return self._entity
        
    @property
    def report(self):
        """Access report methods."""
        return self._report
        
    @property
    def relationship(self):
        """Access relationship methods."""
        return self._relationship
    
    def get_threat_actors(self, filters=None, limit: int = 50):
        """
        Retrieve threat actors from OpenCTI.
        
        Shorthand for threat_actor.list()
        """
        return self._threat_actor.list(filters=filters, limit=limit)

    def get_indicators(self, filters=None):
        """
        Retrieve indicators from OpenCTI.
        
        Shorthand for indicator.list()
        """
        return self._indicator.list(filters=filters)

    def get_observables(self, filters=None):
        """
        Retrieve observables from OpenCTI.
        
        Shorthand for observable.list()
        """
        return self._observable.list(filters=filters)

    def get_entities(self, filters=None, first: int = 50, orderBy: str = "created_at", orderMode: str = "desc"):
        """
        Retrieve STIX domain objects from OpenCTI.
        
        Shorthand for entity.list()
        """
        return self._entity.list(filters=filters, first=first, orderBy=orderBy, orderMode=orderMode)

    def get_relationships(self, entity_id=None, relationship_type=None, filters=None):
        """
        Retrieve relationships from OpenCTI.
        
        Shorthand for relationship.list()
        """
        return self._relationship.list(entity_id=entity_id, relationship_type=relationship_type, filters=filters)

    def _get_container_object_refs(self, container_id):
        """
        Extract object references from container entities.
        
        Delegates to relationship._get_container_object_refs()
        """
        return self._relationship._get_container_object_refs(container_id)

    def create_report(self, report_data):
        """
        Create a new report in OpenCTI.
        
        Shorthand for report.create()
        """
        return self._report.create(report_data)

    def create_indicator(self, indicator_data):
        """
        Create a new indicator in OpenCTI.
        
        Shorthand for indicator.create()
        """
        return self._indicator.create(indicator_data)

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
                "malware": len(self.client.malware.list(first=limit)),
                "attack_patterns": len(self.client.attack_pattern.list(first=limit)),
                "intrusion_sets": len(self.client.intrusion_set.list(first=limit)) if hasattr(self.client, 'intrusion_set') else "N/A"
            }
            logger.debug(f"Entity counts: {results}")
            return results
        except Exception as e:
            logger.error(f"Error testing entity counts: {str(e)}")
            return {} 
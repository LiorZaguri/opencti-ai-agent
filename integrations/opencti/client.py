"""
OpenCTI API Client.

This module provides the main OpenCTIConnector class for interacting with the OpenCTI platform.
"""

from pycti import OpenCTIApiClient
from config.settings import OPENCTI_BASE_URL, OPENCTI_API_KEY
from core.utils.logger import setup_logger
from integrations.opencti.entities import (
    ThreatActorMethods,
    IndicatorMethods,
    ObservableMethods,
    EntityMethods,
    ReportMethods,
    RelationshipMethods
)
from datetime import datetime, timedelta, timezone

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

    def entity_counts(self, days_back: int = None):
        """
        Get counts of different entity types in OpenCTI via a single GraphQL call.

        Args:
            days_back: Optional number of days to look back. If None, returns all-time counts.

        Returns:
            Dictionary containing counts for each entity type.
        """
        try:
            # Build the filters block for “last N days”
            if days_back is not None:
                now = datetime.now(timezone.utc)
                start = now - timedelta(days=days_back)
                start_str = start.strftime("%Y-%m-%dT%H:%M:%SZ")
                end_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                filter_arg = f'''
                    filters: {{
                    mode: and,
                    filters: [
                        {{ key: "created_at", values: ["{start_str}"], operator: gt }},
                        {{ key: "created_at", values: ["{end_str}"], operator: lt }}
                    ],
                    filterGroups: []
                    }}
                '''
            else:
                # no filters = all-time
                filter_arg = ""

            # Assemble the GraphQL query
            gql = f"""
            query EntityCounts {{
            indicators(first: 0 {',' if filter_arg else ''} {filter_arg}) {{
                pageInfo {{ globalCount }}
            }}
            reports(first: 0 {',' if filter_arg else ''} {filter_arg}) {{
                pageInfo {{ globalCount }}
            }}
            threatActors(first: 0 {',' if filter_arg else ''} {filter_arg}) {{
                pageInfo {{ globalCount }}
            }}
            stixCyberObservables(first: 0 {',' if filter_arg else ''} {filter_arg}) {{
                pageInfo {{ globalCount }}
            }}
            vulnerabilities(first: 0 {',' if filter_arg else ''} {filter_arg}) {{
                pageInfo {{ globalCount }}
            }}
            malwares(first: 0 {',' if filter_arg else ''} {filter_arg}) {{
                pageInfo {{ globalCount }}
            }}
            }}
            """

            # Execute a single GraphQL request instead of multiple REST calls
            resp = self.client.query(gql)  # submit a query to the OpenCTI GraphQL API :contentReference[oaicite:0]{index=0}
            data = resp.get("data", {})

            # Extract the six counts
            return {
                "indicators":              data["indicators"]["pageInfo"]["globalCount"],
                "reports":                 data["reports"]["pageInfo"]["globalCount"],
                "threat_actors":           data["threatActors"]["pageInfo"]["globalCount"],
                "observables":             data["stixCyberObservables"]["pageInfo"]["globalCount"],
                "vulnerabilities":         data["vulnerabilities"]["pageInfo"]["globalCount"],
                "malware":                 data["malwares"]["pageInfo"]["globalCount"],
            }

        except Exception as e:
            logger.error(f"Error getting entity counts via GraphQL: {e}")
            return {}

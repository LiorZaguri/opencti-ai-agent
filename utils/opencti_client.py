from pycti import OpenCTIApiClient
from config.settings import OPENCTI_BASE_URL, OPENCTI_API_KEY
from utils.logger import setup_logger

logger = setup_logger(name="OpenCTIConnector", component_type="utils")

def _prepare_filters(filters):
    """
    Ensure each filter dictionary includes default 'operator' and 'filterMode' fields.
    Defaults: operator -> "eq", filterMode -> "in".
    """
    prepared = []
    for f in filters:
        if 'operator' not in f:
            f['operator'] = 'eq'
        if 'filterMode' not in f:
            f['filterMode'] = 'in'
        prepared.append(f)
    return prepared


class OpenCTIConnector:
    def __init__(self):
        """Initialize the OpenCTI connector."""
        self.client = OpenCTIApiClient(
            url=OPENCTI_BASE_URL,
            token=OPENCTI_API_KEY
        )
        logger.info("OpenCTI connector initialized successfully")

    def get_threat_actors(self, filters=None):
        """Retrieve threat actors from OpenCTI."""
        try:
            if filters:
                filters = _prepare_filters(filters)
                return self.client.threat_actor.list(filters=filters)
            else:
                return self.client.threat_actor.list()
        except Exception as e:
            logger.error(f"Error retrieving threat actors: {str(e)}")
            return []

    def get_indicators(self, filters=None):
        """Retrieve indicators from OpenCTI."""
        try:
            if filters:
                filters = _prepare_filters(filters)
                return self.client.indicator.list(filters=filters)
            else:
                return self.client.indicator.list()
        except Exception as e:
            logger.error(f"Error retrieving indicators: {str(e)}")
            return []

    def get_observables(self, filters=None):
        """Retrieve observables from OpenCTI."""
        try:
            if filters:
                filters = _prepare_filters(filters)
                return self.client.stix_cyber_observable.list(filters=filters)
            else:
                return self.client.stix_cyber_observable.list()
        except Exception as e:
            logger.error(f"Error retrieving observables: {str(e)}")
            return []

    def get_relationships(self, entity_id, relationship_type=None):
        """
        Retrieve relationships for an entity.
        If the entity is a container (e.g. Report, Grouping, or Case), return its objectRefs.
        Otherwise, use the standard relationship query.
        """
        if entity_id.startswith("report--") or entity_id.startswith("grouping--") or entity_id.startswith("case--"):
            try:
                # For containers, retrieve the objectRefs field.
                if entity_id.startswith("report--"):
                    container = self.client.report.read(id=entity_id)
                # Extend here for other container types as needed.
                return container.get("objectRefs", [])
            except Exception as e:
                logger.error(f"Error retrieving container object references: {str(e)}")
                return []
        else:
            try:
                filters = [{
                    'key': 'fromId',
                    'values': [entity_id],
                    'operator': 'eq',
                    'filterMode': 'in'
                }]
                if relationship_type:
                    filters.append({
                        'key': 'relationship_type',
                        'values': [relationship_type],
                        'operator': 'eq',
                        'filterMode': 'in'
                    })
                return self.client.stix_core_relationship.list(filters=filters)
            except Exception as e:
                logger.error(f"Error retrieving relationships: {str(e)}")
                return []

    def create_report(self, report_data):
        """Create a new report in OpenCTI."""
        try:
            return self.client.report.create(**report_data)
        except Exception as e:
            logger.error(f"Error creating report: {str(e)}")
            return None

    def create_indicator(self, indicator_data):
        """Create a new indicator in OpenCTI."""
        try:
            return self.client.indicator.create(**indicator_data)
        except Exception as e:
            logger.error(f"Error creating indicator: {str(e)}")
            return None
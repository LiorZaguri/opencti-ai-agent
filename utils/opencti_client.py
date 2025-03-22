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
        logger.debug("OpenCTI connector initialized successfully")

    def get_threat_actors(self, filters=None):
        """Retrieve threat actors from OpenCTI."""
        logger.debug(f"Retrieving threat actors with filters: {filters}")
        try:
            if filters:
                filters = _prepare_filters(filters)
                result = self.client.threat_actor.list(filters=filters)
            else:
                result = self.client.threat_actor.list()
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

    def get_relationships(self, entity_id, relationship_type=None):
        """
        Retrieve relationships for an entity.
        If the entity is a container (e.g. Report, Grouping, or Case), return its objectRefs.
        Otherwise, use the standard relationship query.

        Args:
            entity_id (str): The STIX ID of the entity
            relationship_type (str, optional): Filter by relationship type

        Returns:
            list: List of relationships or object references
        """
        logger.debug(f"Getting relationships for entity: {entity_id}, type: {relationship_type}")

        if entity_id.startswith("report--") or entity_id.startswith("grouping--") or entity_id.startswith("case--"):
            logger.debug(f"Entity {entity_id} is a container, getting object references")
            return self._get_container_object_refs(entity_id)
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
                logger.debug(f"Retrieving relationships with filters: {filters}")
                result = self.client.stix_core_relationship.list(filters=filters)
                logger.debug(f"Found {len(result)} relationships for entity {entity_id}")
                return result
            except Exception as e:
                logger.error(f"Error retrieving relationships for {entity_id}: {str(e)}")
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
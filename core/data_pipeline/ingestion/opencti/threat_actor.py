from typing import Dict, Any, List
from core.utils.logger import setup_logger
from core.data_pipeline.ingestion.opencti.base import BaseIngestor
from core.data_pipeline.ingestion.opencti.utils import assign_priority
from core.utils.company_profile import load_company_profile

logger = setup_logger(name="opencti_threat_actor", component_type="utils")

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
            "priority": assign_priority(relevance_score),
            "outside_profile_scope": relevance_score < 0.4,
            "matched_profile_fields": matched,
        }
        
        # Include raw data only if requested
        if include_raw:
            structured["raw_data"] = actor

        logger.debug(f"Processed actor: {actor.get('name')}")
        return structured 
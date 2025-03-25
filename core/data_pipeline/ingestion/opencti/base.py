from typing import Dict, Any, List, Optional
from core.utils.logger import setup_logger
from integrations.opencti import OpenCTIConnector
from core.data_pipeline.ingestion.opencti.cache import get_from_cache, store_in_cache, invalidate_cache_prefix, DEFAULT_CACHE_TTL

logger = setup_logger(name="opencti_base", component_type="utils")

class BaseIngestor:
    """Base class for all ingestors with common functionality"""
    
    def __init__(self, use_cache: bool = True, cache_ttl: int = DEFAULT_CACHE_TTL):
        self.opencti = OpenCTIConnector()
        self.use_cache = use_cache
        self.cache_ttl = cache_ttl
    
    def _get_from_cache(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Get data from cache if available and not expired"""
        return get_from_cache(cache_key, self.use_cache)
    
    def _store_in_cache(self, cache_key: str, data: List[Dict[str, Any]]) -> None:
        """Store data in cache with expiry time"""
        store_in_cache(cache_key, data, self.use_cache, self.cache_ttl)
    
    def invalidate_cache(self) -> None:
        """Clear specific ingestor's cache entries"""
        prefix = self.__class__.__name__
        invalidate_cache_prefix(prefix) 
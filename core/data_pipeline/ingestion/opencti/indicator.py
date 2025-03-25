import re
from typing import Dict, Any, List
from datetime import datetime, timedelta
from core.utils.logger import setup_logger
from core.data_pipeline.ingestion.opencti.base import BaseIngestor

logger = setup_logger(name="opencti_indicator", component_type="utils")

class IndicatorIngestor(BaseIngestor):
    def ingest_indicators(self, limit: int = 100, include_raw: bool = False, 
                           days_back: int = 90) -> List[Dict[str, Any]]:
        cache_key = f"{self.__class__.__name__}:indicators:{limit}:{days_back}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
        
        # Date filter for recent indicators
        date_filter = None
        if days_back > 0:
            start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            date_filter = [
                {
                    "key": "created_at",
                    "values": [start_date],
                    "operator": "gt"
                }
            ]
            
        logger.info(f"Fetching indicators from OpenCTI (last {days_back} days)...")
        
        try:
            indicators = self.opencti.get_indicators(filters=date_filter)
            
            if not indicators:
                logger.info("No indicators found.")
                return []
                
            # Limit results if needed
            if limit and len(indicators) > limit:
                indicators = indicators[:limit]
                
            logger.info(f"Retrieved {len(indicators)} indicators")
            structured_indicators = []
            
            for indicator in indicators:
                try:
                    structured = self._process_indicator(indicator, include_raw)
                    if structured:
                        structured_indicators.append(structured)
                except Exception as e:
                    logger.error(f"Error processing indicator {indicator.get('id', 'unknown')}: {str(e)}")
                    
            logger.info(f"Structured {len(structured_indicators)} indicators")
            self._store_in_cache(cache_key, structured_indicators)
            return structured_indicators
        except Exception as e:
            logger.error(f"Error retrieving indicators: {str(e)}")
            return []
        
    def _process_indicator(self, indicator: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        # Extract pattern and pattern type
        pattern = indicator.get("pattern", "")
        pattern_type = indicator.get("pattern_type", "unknown")
        
        # Determine indicator category based on pattern
        category = "unknown"
        value = ""
        
        if pattern_type == "stix":
            # Parse STIX pattern to extract value
            if "[file:hashes" in pattern:
                category = "file_hash"
                # Extract hash value with regex processing
                match = re.search(r"'([a-fA-F0-9]+)'", pattern)
                if match:
                    value = match.group(1)
            elif "[url:value" in pattern:
                category = "url"
                match = re.search(r"'(https?://[^']+)'", pattern)
                if match:
                    value = match.group(1)
            elif "[domain-name:value" in pattern:
                category = "domain"
                match = re.search(r"'([^']+)'", pattern)
                if match:
                    value = match.group(1)
            elif "[ipv4-addr:value" in pattern or "[ipv6-addr:value" in pattern:
                category = "ip"
                match = re.search(r"'([^']+)'", pattern)
                if match:
                    value = match.group(1)
            elif "[email-addr:value" in pattern:
                category = "email"
                match = re.search(r"'([^']+)'", pattern)
                if match:
                    value = match.group(1)
        
        # Create structured response
        structured = {
            "type": "indicator",
            "id": indicator.get("id"),
            "name": indicator.get("name", "Unnamed Indicator"),
            "description": indicator.get("description", ""),
            "pattern": pattern,
            "pattern_type": pattern_type,
            "category": category,
            "value": value,
            "valid_from": indicator.get("valid_from"),
            "valid_until": indicator.get("valid_until"),
            "created_at": indicator.get("created"),
            "modified_at": indicator.get("modified", indicator.get("created")),
            "revoked": indicator.get("revoked", False),
            "confidence": indicator.get("confidence", 50),
            "labels": indicator.get("labels", []),
            "score": indicator.get("x_opencti_score", 50),
        }
        
        # Set severity based on score
        if structured["score"] >= 75:
            structured["severity"] = "high"
        elif structured["score"] >= 50:
            structured["severity"] = "medium"
        else:
            structured["severity"] = "low"
            
        # Include raw data if requested
        if include_raw:
            structured["raw_data"] = indicator
            
        logger.debug(f"Processed indicator: {indicator.get('name')}")
        return structured 
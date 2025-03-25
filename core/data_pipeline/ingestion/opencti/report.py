from typing import Dict, Any, List
from datetime import datetime, timedelta
from core.utils.logger import setup_logger
from core.data_pipeline.ingestion.opencti.base import BaseIngestor

logger = setup_logger(name="opencti_report", component_type="utils")

class ReportIngestor(BaseIngestor):
    def ingest_reports(self, limit: int = 20, include_raw: bool = False, 
                       days_back: int = 90) -> List[Dict[str, Any]]:
        """Retrieve reports from OpenCTI"""
        cache_key = f"{self.__class__.__name__}:reports:{limit}:{days_back}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
            
        # Date filter for recent reports
        date_filter = []
        if days_back > 0:
            start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            date_filter = [{
                "key": "published",
                "values": [start_date],
                "operator": "gt"
            }]
            
        logger.info(f"Fetching reports from OpenCTI (last {days_back} days)...")
        
        # Use entity filter for Reports
        entity_filter = [{
            "key": "entity_type",
            "values": ["Report"]
        }]
        
        filters = date_filter + entity_filter if date_filter else entity_filter
        
        try:
            reports = self.opencti.get_entities(filters=filters, first=limit)
            
            if not reports:
                logger.info("No reports found.")
                return []
                
            logger.info(f"Retrieved {len(reports)} reports")
            structured_reports = []
            
            for report in reports:
                try:
                    structured = self._process_report(report, include_raw)
                    if structured:
                        structured_reports.append(structured)
                except Exception as e:
                    logger.error(f"Error processing report {report.get('id', 'unknown')}: {str(e)}")
                    
            logger.info(f"Structured {len(structured_reports)} reports")
            self._store_in_cache(cache_key, structured_reports)
            return structured_reports
        except Exception as e:
            logger.error(f"Error retrieving reports: {str(e)}")
            return []
        
    def _process_report(self, report: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        # Extract object references if available
        object_refs = []
        if "objectRefs" in report:
            object_refs = report["objectRefs"]
        else:
            # Get relationships for this report
            try:
                related_objects = self.opencti._get_container_object_refs(report.get("id"))
                object_refs = related_objects
            except Exception as e:
                logger.error(f"Error getting related objects for report {report.get('id')}: {e}")
        
        # Create structured response
        structured = {
            "type": "report",
            "id": report.get("id"),
            "name": report.get("name", "Unnamed Report"),
            "description": report.get("description", ""),
            "published": report.get("published"),
            "created_at": report.get("created_at"),
            "modified_at": report.get("modified_at", report.get("created_at")),
            "report_types": report.get("report_types", []),
            "confidence": report.get("confidence", 50),
            "object_refs": object_refs,
            "object_refs_count": len(object_refs),
            "labels": report.get("objectLabel", {}).get("edges", []),
        }
        
        # Include raw data if requested
        if include_raw:
            structured["raw_data"] = report
            
        logger.debug(f"Processed report: {report.get('name')}")
        return structured 
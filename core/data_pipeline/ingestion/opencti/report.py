from typing import Dict, Any, List, Optional
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
                    if isinstance(report, dict):
                        structured = self._process_report(report, include_raw)
                        if structured:
                            structured_reports.append(structured)
                    else:
                         logger.warning(f"Skipping non-dictionary report item: {type(report)}")
                except Exception as e:
                    report_id = report.get('id', 'unknown') if isinstance(report, dict) else 'unknown'
                    logger.error(f"Error processing report {report_id}: {str(e)}", exc_info=True)
                    
            logger.info(f"Structured {len(structured_reports)} reports")
            self._store_in_cache(cache_key, structured_reports)
            return structured_reports
        except Exception as e:
            logger.error(f"Error retrieving reports: {str(e)}", exc_info=True)
            return []
        
    def _process_report(self, report: Dict[str, Any], include_raw: bool = False) -> Optional[Dict[str, Any]]:
        """Process a single report dictionary into a structured format."""
        
        if not isinstance(report, dict):
            logger.warning(f"_process_report received non-dict item: {type(report)}")
            return None
        
        report_id = report.get("id")

        # --- Process object references carefully --- 
        processed_refs = []
        raw_refs_source = [] # Source list
        
        # 1. Try getting objectRefs directly from the input report data first
        if "objectRefs" in report and isinstance(report["objectRefs"], list):
             raw_refs_source = report["objectRefs"]
             logger.debug(f"Using direct objectRefs from input data for report {report_id}")
        else:
            # 2. Fallback: If not in input, try fetching via _get_container_object_refs
            #    (This might still log warnings for non-standard IDs)
            try:
                logger.debug(f"Direct objectRefs not found, fetching relationships for report {report_id}")
                raw_refs_source = self.opencti._get_container_object_refs(report_id)
            except Exception as e:
                logger.error(f"Error getting related objects for report {report_id}: {e}")
                raw_refs_source = []

        # Ensure raw_refs_source is always a list before iterating
        if not isinstance(raw_refs_source, list):
             logger.warning(f"Expected list for raw_refs_source, got {type(raw_refs_source)} for report {report_id}")
             raw_refs_source = []

        # Process each item in the source list
        for ref in raw_refs_source:
            if isinstance(ref, dict):
                ref_id = ref.get("id")
                ref_type = ref.get("entity_type") 
                ref_name = ref.get("name")
                if ref_id and ref_type:
                    processed_refs.append({
                        "id": ref_id,
                        "type": ref_type,
                        "name": ref_name or "Unknown"
                    })
                else:
                    logger.debug(f"Skipping ref in report {report_id} due to missing id/type: {ref}")
            
            elif isinstance(ref, str):
                 logger.debug(f"Skipping string ref in report {report_id}: {ref}")
            
            else:
                logger.warning(f"Unexpected item type in objectRefs/relationships for report {report_id}: {type(ref)}")

        # --- Process labels safely ---
        processed_labels = []
        object_label_data = report.get("objectLabel")
        if isinstance(object_label_data, dict):
            edges = object_label_data.get("edges", [])
            if isinstance(edges, list):
                 for edge in edges:
                    if isinstance(edge, dict):
                        node = edge.get("node")
                        if isinstance(node, dict):
                            label_value = node.get("value")
                            if label_value:
                                processed_labels.append(label_value)
            # Removed warning for non-list edges, default to []
        # Silently handle the case where objectLabel is a list or None
        # Only log if it's some other unexpected type (though unlikely)
        elif object_label_data is not None and not isinstance(object_label_data, list):
             logger.warning(f"Unexpected type for objectLabel, expected dict or list, got {type(object_label_data)} for report {report.get('id')}")

        # Create structured response
        structured = {
            "type": "report",
            "id": report_id,
            "name": report.get("name", "Unnamed Report"),
            "description": report.get("description", ""),
            "published": report.get("published"),
            "created_at": report.get("created_at", report.get("created")),
            "modified_at": report.get("modified_at", report.get("modified", report.get("created_at", report.get("created")))),
            "report_types": report.get("report_types", []),
            "confidence": report.get("confidence", 50),
            "object_refs": processed_refs,
            "object_refs_count": len(processed_refs),
            "labels": processed_labels,
        }
        
        if include_raw:
            structured["raw_data"] = report
            
        return structured 
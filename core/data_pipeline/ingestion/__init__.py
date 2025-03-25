# Empty file to make the directory a proper Python package
# Redirection for removed opencti_ingestion.py
import sys

class OpenCTIIngestionRedirector:
    def __getattr__(self, name):
        raise ImportError(
            "The 'opencti_ingestion' module has been removed. "
            "Please update your imports to use 'core.data_pipeline.ingestion.opencti' instead. "
            "See core/data_pipeline/ingestion/MIGRATION_NOTICE.md for details."
        )

sys.modules['core.data_pipeline.ingestion.opencti_ingestion'] = OpenCTIIngestionRedirector()

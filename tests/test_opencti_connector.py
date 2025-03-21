import unittest
from utils.opencti_client import OpenCTIConnector


class TestOpenCTIConnector(unittest.TestCase):
    def setUp(self):
        self.connector = OpenCTIConnector()
        # Store created objects for cleanup and reference
        self.created_objects = []

    def tearDown(self):
        # You could implement cleanup here to delete test objects
        # if your OpenCTI instance allows it
        pass

    def test_get_threat_actors(self):
        threat_actors = self.connector.get_threat_actors()
        self.assertIsNotNone(threat_actors)
        print(f"Retrieved {len(threat_actors)} threat actors")

    def test_get_indicators(self):
        indicators = self.connector.get_indicators()
        self.assertIsNotNone(indicators)
        print(f"Retrieved {len(indicators)} indicators")

    def test_get_observables(self):
        observables = self.connector.get_observables()
        self.assertIsNotNone(observables)
        print(f"Retrieved {len(observables)} observables")

    def test_create_report(self):
        dummy_report_data = {
            "name": "Test Report",
            "description": "This is a test report created by OpenCTIConnector.",
            "published": "2025-03-21T21:48:00.000Z",
            "report_class": "Threat Report"
        }
        created_report = self.connector.create_report(dummy_report_data)
        self.assertIsNotNone(created_report)
        self.created_objects.append(created_report['id'])
        print(f"Created Report: {created_report}")
        return created_report

    def test_create_indicator(self):
        dummy_indicator_data = {
            "name": "Test Indicator",
            "pattern": "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "x_opencti_main_observable_type": "File",
            "valid_from": "2021-01-01T00:00:00.000Z"
        }
        created_indicator = self.connector.create_indicator(dummy_indicator_data)
        self.assertIsNotNone(created_indicator)
        self.created_objects.append(created_indicator['id'])
        print(f"Created Indicator: {created_indicator}")
        return created_indicator


if __name__ == '__main__':
    unittest.main()
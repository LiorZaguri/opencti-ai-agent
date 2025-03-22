import unittest
from utils.opencti import OpenCTIConnector


class TestOpenCTIConnector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a single connector instance shared by all test methods
        cls.connector = OpenCTIConnector()
        # Store created objects for cleanup and reference
        cls.created_objects = []

    @classmethod
    def tearDownClass(cls):
        # Clean up all created objects at the end of all tests
        pass

    def test_opencti_entity_availability(self):
        """Test the availability of entities in OpenCTI"""
        print("Checking OpenCTI entity availability...")
        counts = self.connector.test_entity_counts(limit=10)

        print("\nEntities available in your OpenCTI instance:")
        print("--------------------------------------------")

        for entity_type, count in counts.items():
            if count == 0:
                status = "NONE FOUND"
            elif count == "N/A":
                status = "UNAVAILABLE"
            else:
                status = f"{count} found"

            print(f"{entity_type.ljust(20)}: {status}")

        print("\nIf you're seeing '0' for entity types that should exist in your OpenCTI,")
        print("there may be an issue with your API access or permissions.\n")

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


if __name__ == '__main__':
    unittest.main()
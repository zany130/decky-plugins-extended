import unittest

import accepted_baseline as ab


class AcceptedBaselineNetworkCompatibilityTests(unittest.TestCase):
    def test_cached_report_falls_back_to_complete_legacy_domain_inventory(self):
        domains = [f"host-{index}.example.com" for index in range(35)]
        report = {
            # Cached reports from before structured network inventories were
            # serialized can contain an explicit empty list here while retaining
            # the complete historical inventory in extracted_domains.
            "network_destinations": [],
            "extracted_domains": domains,
            "reviewer_capabilities": [
                {
                    "id": "network_communication",
                    "evidence": [
                        {"kind": "network_destination", "destination": value}
                        for value in domains[:20]
                    ],
                }
            ],
        }

        projected = ab._project_network(report)

        self.assertEqual(len(projected), 35)
        self.assertEqual(
            {item["destination"] for item in projected},
            set(domains),
        )

    def test_nonempty_structured_inventory_wins_over_legacy_inventory(self):
        report = {
            "network_destinations": [
                {"destination": "structured.example.com", "source_path": "src/api.ts"},
            ],
            "extracted_domains": ["legacy.example.com"],
        }

        self.assertEqual(
            ab._project_network(report),
            [{"destination": "structured.example.com"}],
        )

    def test_empty_structured_and_missing_legacy_inventory_stays_empty(self):
        self.assertEqual(ab._project_network({"network_destinations": []}), [])


if __name__ == "__main__":
    unittest.main()

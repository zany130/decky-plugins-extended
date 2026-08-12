import unittest

import review_queue as rq
import review_queue_guard as guard


class ReviewQueueGuardTests(unittest.TestCase):
    def item(self, index, *, drift=False, critical=False, new_artifact=False):
        digest = f"{index + 1:064x}"
        baseline_digest = digest if drift else f"{index + 10001:064x}"
        changed = []
        reasons = ["new_artifact"]
        priority = "normal"
        classification = "MANUAL_REVIEW"
        same_artifact = False
        attention_count = 0
        error_count = 0
        scanner_failures = []

        if drift:
            reasons = ["security_delta", "same_artifact_analysis_drift"]
            priority = "high"
            same_artifact = True
            attention_count = 1
            changed = [
                {
                    "id": "network_communication",
                    "title": "Network communication",
                    "status_change": "unchanged",
                    "summary": "network destinations +0/-4",
                    "reviewer_attention": True,
                }
            ]
        elif new_artifact:
            reasons = ["new_artifact", "security_delta"]
            priority = "high"
            attention_count = 1
            changed = [
                {
                    "id": "source_release_integrity",
                    "title": "Published release versus source",
                    "status_change": "unchanged",
                    "summary": "source/release difference profile changed",
                    "reviewer_attention": True,
                }
            ]

        if critical:
            classification = "AUDIT_ERROR"
            priority = "critical"
            reasons = ["audit_error", "security_delta", "same_artifact_analysis_drift"]
            same_artifact = True
            baseline_digest = digest
            attention_count = 1
            error_count = 1
            changed = [
                {
                    "id": "network_communication",
                    "title": "Network communication",
                    "status_change": "coverage_became_unknown",
                    "summary": "observed -> unknown",
                    "reviewer_attention": True,
                }
            ]
            scanner_failures = [{"name": "clamav", "status": "failed"}]

        return {
            "repository": f"https://github.com/example/plugin-{index}",
            "plugin_name": f"Plugin {index}",
            "release": f"v{index}.0.0",
            "artifact_sha256": digest,
            "source_commit": f"{index + 1:040x}",
            "final_classification": classification,
            "risk_score": 10,
            "priority": priority,
            "reasons": reasons,
            "first_seen_at": "2026-08-12T12:00:00Z",
            "baseline_release": f"v{index - 1}.0.0",
            "baseline_artifact_sha256": baseline_digest,
            "comparison_status": "compared",
            "same_artifact": same_artifact,
            "reviewer_attention_count": attention_count,
            "changed_capabilities": changed,
            "error_count": error_count,
            "scanner_failures": scanner_failures,
        }

    def queue(self, items, *, generated_at="2026-08-12T12:00:00Z"):
        payload = {
            "schema_version": "1",
            "generated_at": generated_at if items else "",
            "source_run_url": "https://github.com/example/store/actions/runs/123",
            "item_count": len(items),
            "items": items,
        }
        rq.validate_queue(payload)
        return payload

    def test_single_real_release_growth_passes(self):
        current_items = [self.item(index) for index in range(11)]
        candidate_items = current_items + [self.item(100, new_artifact=True)]

        result = guard.require_safe_persistence(
            self.queue(current_items),
            self.queue(candidate_items, generated_at="2026-08-12T13:00:00Z"),
        )

        self.assertTrue(result["safe"])
        self.assertEqual(result["net_growth"], 1)
        self.assertEqual(result["same_artifact_drift_additions"], 0)

    def test_legacy_style_11_to_50_drift_flood_is_blocked(self):
        current_items = [self.item(index) for index in range(11)]
        candidate_items = current_items + [self.item(100 + index, drift=True) for index in range(39)]

        result = guard.analyze_persistence(
            self.queue(current_items),
            self.queue(candidate_items, generated_at="2026-08-12T13:00:00Z"),
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["current_count"], 11)
        self.assertEqual(result["candidate_count"], 50)
        self.assertEqual(result["same_artifact_drift_additions"], 39)
        with self.assertRaisesRegex(ValueError, "flood guard refused"):
            guard.require_safe_persistence(
                self.queue(current_items),
                self.queue(candidate_items, generated_at="2026-08-12T13:00:00Z"),
            )

    def test_large_batch_of_real_new_artifacts_passes(self):
        current_items = [self.item(index) for index in range(11)]
        candidate_items = current_items + [
            self.item(100 + index, new_artifact=True) for index in range(25)
        ]

        result = guard.require_safe_persistence(
            self.queue(current_items),
            self.queue(candidate_items, generated_at="2026-08-12T13:00:00Z"),
        )

        self.assertEqual(result["net_growth"], 25)
        self.assertEqual(result["same_artifact_drift_additions"], 0)

    def test_critical_same_artifact_failures_do_not_count_as_flood_drift(self):
        current_items = [self.item(index) for index in range(11)]
        candidate_items = current_items + [
            self.item(100 + index, critical=True) for index in range(15)
        ]

        result = guard.require_safe_persistence(
            self.queue(current_items),
            self.queue(candidate_items, generated_at="2026-08-12T13:00:00Z"),
        )

        self.assertEqual(result["net_growth"], 15)
        self.assertEqual(result["same_artifact_drift_additions"], 0)

    def test_small_same_artifact_drift_batch_passes(self):
        current_items = [self.item(index) for index in range(11)]
        candidate_items = current_items + [self.item(100 + index, drift=True) for index in range(9)]

        result = guard.require_safe_persistence(
            self.queue(current_items),
            self.queue(candidate_items, generated_at="2026-08-12T13:00:00Z"),
        )

        self.assertEqual(result["same_artifact_drift_additions"], 9)
        self.assertTrue(result["safe"])

    def test_drift_must_dominate_new_identities_to_trigger(self):
        current_items = [self.item(index) for index in range(11)]
        drift_items = [self.item(100 + index, drift=True) for index in range(10)]
        real_items = [self.item(200 + index, new_artifact=True) for index in range(11)]
        candidate_items = current_items + drift_items + real_items

        result = guard.require_safe_persistence(
            self.queue(current_items),
            self.queue(candidate_items, generated_at="2026-08-12T13:00:00Z"),
        )

        self.assertEqual(result["net_growth"], 21)
        self.assertEqual(result["same_artifact_drift_additions"], 10)
        self.assertFalse(result["drift_dominates_additions"])


if __name__ == "__main__":
    unittest.main()

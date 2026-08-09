import copy
import unittest

import accepted_baseline
import review_queue as rq


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
COMMIT = "d" * 40
REPO = "https://github.com/example/plugin"
REPO_KEY = "github.com/example/plugin"


class ReviewQueueTests(unittest.TestCase):
    def capability(self):
        return {
            "id": "network_communication",
            "title": "Network communication",
            "question": "What network communication is present?",
            "status": "observed",
            "rule_ids": [],
            "finding_count": 0,
            "evidence_count": 1,
            "distinct_evidence_count": 1,
            "evidence_collapsed": 0,
            "evidence_truncated": False,
        }

    def baseline_report(self, digest=SHA_A, release="v1.0.0"):
        return {
            "repository": REPO,
            "plugin_name": "Example",
            "release": release,
            "artifact_sha256": digest,
            "source_commit": COMMIT,
            "final_classification": "MANUAL_REVIEW",
            "risk_score": 10,
            "schema_version": "1",
            "policy_version": "1",
            "reviewer_capabilities_schema_version": "1",
            "reviewer_capabilities": [self.capability()],
            "network_destinations": [{"destination": "old.example"}],
            "native_binaries": [],
            "source_artifact_diff": {},
            "baseline_captured_at": "2026-08-08T18:00:00Z",
            "baseline_source": accepted_baseline.BASELINE_SOURCE,
            "baseline_live_version": release.removeprefix("v"),
            "baseline_live_hash": digest,
        }

    def baseline(self, report=None):
        reports = [] if report is None else [report]
        payload = {
            "schema_version": accepted_baseline.BASELINE_SCHEMA_VERSION,
            "baseline_semantics": accepted_baseline.BASELINE_SEMANTICS,
            "generated_at": "2026-08-08T18:00:00Z" if reports else "",
            "auditor_ref": "e" * 40,
            "live_catalog_url": "https://example.invalid/plugins.json",
            "entry_count": len(reports),
            "reports": reports,
        }
        accepted_baseline.validate_baseline(payload)
        return payload

    def comparison(
        self,
        *,
        same_artifact=False,
        changed=False,
        attention=False,
        status="compared",
    ):
        capabilities = []
        if changed:
            capabilities.append(
                {
                    "id": "network_communication",
                    "title": "Network communication",
                    "changed": True,
                    "status_change": "unchanged",
                    "summary": "network destinations +1/-1",
                    "reviewer_attention": attention,
                    "details": {
                        "added_destinations": ["new.example"],
                        "removed_destinations": ["old.example"],
                    },
                }
            )
        return {
            "status": status,
            "same_artifact": same_artifact,
            "changed_count": 1 if changed else 0,
            "attention_count": 1 if attention else 0,
            "capabilities": capabilities,
        }

    def audit_report(
        self,
        *,
        digest=SHA_B,
        release="v1.1.0",
        classification="MANUAL_REVIEW",
        comparison=None,
        errors=None,
    ):
        return {
            "repository": REPO,
            "plugin_name": "Example",
            "release": release,
            "artifact_sha256": digest,
            "source_commit": COMMIT,
            "final_classification": classification,
            "risk_score": 25,
            "errors": errors or [],
            "reviewer_capability_comparison": comparison
            if comparison is not None
            else self.comparison(),
        }

    def audit(self, report):
        return {
            "generated_at": "2026-08-09T01:00:00Z",
            "reports": [report],
        }

    def build(self, report, *, baseline=None, decisions=None, queue=None):
        return rq.build_queue(
            self.audit(report),
            baseline if baseline is not None else self.baseline(self.baseline_report()),
            decisions if decisions is not None else rq.empty_decisions(),
            queue if queue is not None else rq.empty_queue(),
            {REPO_KEY},
            source_run_url="https://github.com/example/store/actions/runs/123",
        )

    def test_new_artifact_with_reviewer_attention_is_high_priority(self):
        report = self.audit_report(
            comparison=self.comparison(changed=True, attention=True),
        )

        queue, stats = self.build(report)

        self.assertEqual(queue["item_count"], 1)
        item = queue["items"][0]
        self.assertEqual(item["priority"], "high")
        self.assertEqual(item["artifact_sha256"], SHA_B)
        self.assertEqual(item["baseline_artifact_sha256"], SHA_A)
        self.assertEqual(item["reasons"], ["new_artifact", "security_delta"])
        self.assertEqual(item["reviewer_attention_count"], 1)
        self.assertEqual(item["changed_capabilities"][0]["summary"], "network destinations +1/-1")
        self.assertNotIn("details", item["changed_capabilities"][0])
        self.assertEqual(stats["high"], 1)

    def test_new_artifact_without_attention_remains_visible_at_normal_priority(self):
        queue, _ = self.build(self.audit_report(comparison=self.comparison()))

        self.assertEqual(queue["items"][0]["priority"], "normal")
        self.assertEqual(queue["items"][0]["reasons"], ["new_artifact"])

    def test_unchanged_accepted_manual_review_artifact_is_not_requeued(self):
        report = self.audit_report(
            digest=SHA_A,
            release="v1.0.0",
            comparison=self.comparison(same_artifact=True),
        )

        queue, _ = self.build(report)

        self.assertEqual(queue, rq.empty_queue())

    def test_baseline_missing_is_high_priority(self):
        report = self.audit_report(
            comparison=self.comparison(status="baseline_not_found"),
        )

        queue, _ = self.build(report, baseline=self.baseline())

        item = queue["items"][0]
        self.assertEqual(item["priority"], "high")
        self.assertIn("baseline_unavailable", item["reasons"])
        self.assertEqual(item["baseline_artifact_sha256"], "")

    def test_block_and_audit_error_are_critical(self):
        blocked, _ = self.build(
            self.audit_report(classification="BLOCK", comparison=self.comparison())
        )
        self.assertEqual(blocked["items"][0]["priority"], "critical")
        self.assertIn("blocked_by_policy", blocked["items"][0]["reasons"])

        errored, _ = self.build(
            self.audit_report(
                digest="",
                classification="AUDIT_ERROR",
                comparison={"status": "comparison_unavailable"},
                errors=["scanner timed out"],
            )
        )
        item = errored["items"][0]
        self.assertEqual(item["priority"], "critical")
        self.assertEqual(item["artifact_sha256"], "")
        self.assertIn("artifact_identity_unavailable", item["reasons"])
        self.assertEqual(item["error_count"], 1)

    def test_same_artifact_analysis_drift_is_queued_without_claiming_release_change(self):
        report = self.audit_report(
            digest=SHA_A,
            release="v1.0.0",
            classification="AUDIT_ERROR",
            comparison=self.comparison(same_artifact=True, changed=True, attention=True),
            errors=["ClamAV timed out"],
        )

        queue, _ = self.build(report)

        item = queue["items"][0]
        self.assertTrue(item["same_artifact"])
        self.assertIn("same_artifact_analysis_drift", item["reasons"])
        self.assertNotIn("new_artifact", item["reasons"])

    def test_pending_item_preserves_original_context_after_baseline_advances(self):
        initial, _ = self.build(
            self.audit_report(comparison=self.comparison(changed=True, attention=True))
        )
        original_item = copy.deepcopy(initial["items"][0])

        advanced_baseline = self.baseline(self.baseline_report(SHA_B, "v1.1.0"))
        current = self.audit_report(
            digest=SHA_B,
            release="v1.1.0",
            comparison=self.comparison(same_artifact=True),
        )
        queue, _ = self.build(current, baseline=advanced_baseline, queue=initial)

        self.assertEqual(queue, initial)
        self.assertEqual(queue["items"][0], original_item)
        self.assertEqual(queue["items"][0]["baseline_artifact_sha256"], SHA_A)
        self.assertEqual(queue["items"][0]["reasons"], ["new_artifact", "security_delta"])
        self.assertEqual(
            queue["items"][0]["changed_capabilities"][0]["summary"],
            "network destinations +1/-1",
        )

    def test_pending_item_can_escalate_to_critical_without_losing_review_context(self):
        initial, _ = self.build(
            self.audit_report(comparison=self.comparison(changed=True, attention=True))
        )
        original = copy.deepcopy(initial["items"][0])

        errored = self.audit_report(
            digest=SHA_B,
            release="v1.1.0",
            classification="AUDIT_ERROR",
            comparison=self.comparison(same_artifact=True, changed=True, attention=True),
            errors=["scanner timed out"],
        )
        queue, _ = self.build(errored, queue=initial)

        item = queue["items"][0]
        self.assertEqual(item["priority"], "critical")
        self.assertEqual(item["final_classification"], "AUDIT_ERROR")
        self.assertIn("audit_error", item["reasons"])
        self.assertEqual(item["baseline_artifact_sha256"], original["baseline_artifact_sha256"])
        self.assertEqual(item["changed_capabilities"], original["changed_capabilities"])
        self.assertEqual(item["first_seen_at"], original["first_seen_at"])
        self.assertEqual(item["error_count"], 1)

    def test_exact_artifact_decision_resolves_item_but_old_decision_does_not_hide_new_artifact(self):
        queue, _ = self.build(self.audit_report())
        decision = {
            "repository": REPO,
            "release": "v1.1.0",
            "artifact_sha256": SHA_B,
            "decision": "approved",
            "decided_by": "reviewer-user",
            "decided_at": "2026-08-09T01:30:00Z",
            "reason": "Reviewed expected update.",
        }
        decisions = {"schema_version": "1", "decisions": [decision]}

        resolved, stats = self.build(self.audit_report(), decisions=decisions, queue=queue)
        self.assertEqual(resolved["item_count"], 0)
        self.assertEqual(stats["resolved"], 1)

        newer = self.audit_report(digest=SHA_C, release="v1.2.0")
        newer_queue, _ = self.build(newer, decisions=decisions, queue=resolved)
        self.assertEqual(newer_queue["item_count"], 1)
        self.assertEqual(newer_queue["items"][0]["artifact_sha256"], SHA_C)

    def test_older_pending_artifact_is_superseded_by_newer_current_artifact(self):
        old, _ = self.build(self.audit_report(digest=SHA_B, release="v1.1.0"))
        newer = self.audit_report(digest=SHA_C, release="v1.2.0")

        queue, stats = self.build(newer, queue=old)

        self.assertEqual(queue["item_count"], 1)
        self.assertEqual(queue["items"][0]["artifact_sha256"], SHA_C)
        self.assertEqual(stats["superseded"], 1)

    def test_identical_queue_state_does_not_churn_generation_metadata(self):
        queue, _ = self.build(self.audit_report())
        second_audit = self.audit(self.audit_report())
        second_audit["generated_at"] = "2026-08-09T02:00:00Z"

        second, _ = rq.build_queue(
            second_audit,
            self.baseline(self.baseline_report()),
            rq.empty_decisions(),
            queue,
            {REPO_KEY},
            source_run_url="https://github.com/example/store/actions/runs/456",
        )

        self.assertEqual(second, queue)
        self.assertEqual(second["source_run_url"], "https://github.com/example/store/actions/runs/123")

    def test_record_decision_updates_history_and_queue_together(self):
        queue, _ = self.build(self.audit_report())

        decisions, updated_queue = rq.record_decision(
            rq.empty_decisions(),
            queue,
            repository=REPO,
            artifact_sha256=SHA_B,
            decision="rejected",
            reviewer="zany130",
            reason="Unexpected behavior needs upstream changes.",
            decided_at="2026-08-09T02:00:00Z",
        )

        self.assertEqual(len(decisions["decisions"]), 1)
        self.assertEqual(decisions["decisions"][0]["decision"], "rejected")
        self.assertEqual(updated_queue["item_count"], 0)
        rq.validate_state(decisions, updated_queue)

    def test_record_decision_refuses_unqueued_or_mutable_identity(self):
        queue, _ = self.build(self.audit_report())
        with self.assertRaisesRegex(ValueError, "exact 64-character"):
            rq.record_decision(
                rq.empty_decisions(),
                queue,
                repository=REPO,
                artifact_sha256="v1.1.0",
                decision="approved",
                reviewer="zany130",
                reason="No.",
            )
        with self.assertRaisesRegex(ValueError, "not currently pending"):
            rq.record_decision(
                rq.empty_decisions(),
                queue,
                repository=REPO,
                artifact_sha256=SHA_C,
                decision="approved",
                reviewer="zany130",
                reason="No.",
            )

    def test_state_validation_rejects_decided_artifact_still_in_queue(self):
        queue, _ = self.build(self.audit_report())
        decisions = {
            "schema_version": "1",
            "decisions": [
                {
                    "repository": REPO,
                    "release": "v1.1.0",
                    "artifact_sha256": SHA_B,
                    "decision": "approved",
                    "decided_by": "zany130",
                    "decided_at": "2026-08-09T02:00:00Z",
                    "reason": "Reviewed.",
                }
            ],
        }

        with self.assertRaisesRegex(ValueError, "already has a decision"):
            rq.validate_state(decisions, queue)

    def test_decision_validation_rejects_secret_shaped_reason_and_bad_sha(self):
        payload = rq.empty_decisions()
        payload["decisions"].append(
            {
                "repository": REPO,
                "release": "v1.1.0",
                "artifact_sha256": SHA_B,
                "decision": "approved",
                "decided_by": "zany130",
                "decided_at": "2026-08-09T02:00:00Z",
                "reason": "ghp_" + "A" * 36,
            }
        )
        with self.assertRaisesRegex(ValueError, "secret-shaped"):
            rq.validate_decisions(payload)

        payload = copy.deepcopy(payload)
        payload["decisions"][0]["reason"] = "Fine."
        payload["decisions"][0]["artifact_sha256"] = "short"
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            rq.validate_decisions(payload)

    def test_markdown_is_compact_and_does_not_include_comparison_details(self):
        queue, _ = self.build(
            self.audit_report(comparison=self.comparison(changed=True, attention=True))
        )

        markdown = rq.render_markdown(queue)

        self.assertIn("network destinations +1/-1", markdown)
        self.assertNotIn("new.example", markdown)
        self.assertNotIn("old.example", markdown)


if __name__ == "__main__":
    unittest.main()

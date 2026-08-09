import copy
import unittest

import review_queue as rq
import review_state_transition as transition


REPO = "https://github.com/example/plugin"
SHA_A = "a" * 64
SHA_B = "b" * 64


class ReviewStateTransitionTests(unittest.TestCase):
    def item(self, digest=SHA_A, release="v1.0.0"):
        return {
            "repository": REPO,
            "plugin_name": "Example",
            "release": release,
            "artifact_sha256": digest,
            "source_commit": "c" * 40,
            "final_classification": "MANUAL_REVIEW",
            "risk_score": 10,
            "priority": "high",
            "reasons": ["new_artifact", "security_delta"],
            "first_seen_at": "2026-08-09T01:00:00Z",
            "baseline_release": "v0.9.0",
            "baseline_artifact_sha256": "d" * 64,
            "comparison_status": "compared",
            "same_artifact": False,
            "reviewer_attention_count": 1,
            "changed_capabilities": [
                {
                    "id": "network_communication",
                    "title": "Network communication",
                    "status_change": "unchanged",
                    "summary": "network destinations +1/-1",
                    "reviewer_attention": True,
                }
            ],
            "error_count": 0,
        }

    def queue(self, *items):
        payload = {
            "schema_version": "1",
            "generated_at": "2026-08-09T01:00:00Z",
            "source_run_url": "https://github.com/example/store/actions/runs/123",
            "item_count": len(items),
            "items": list(items),
        }
        rq.validate_queue(payload)
        return payload

    def decision(self, digest=SHA_A, *, decided_at="2026-08-09T02:00:00Z"):
        return {
            "repository": REPO,
            "release": "v1.0.0" if digest == SHA_A else "v1.1.0",
            "artifact_sha256": digest,
            "decision": "approved",
            "decided_by": "zany130",
            "decided_at": decided_at,
            "reason": "Reviewed expected behavior.",
        }

    def current_after_decision(self, previous_queue, decision):
        current_queue = copy.deepcopy(previous_queue)
        target = (
            rq._repo_key(decision["repository"]),
            decision["artifact_sha256"],
        )
        current_queue["items"] = [
            item
            for item in current_queue["items"]
            if (rq._repo_key(item["repository"]), item["artifact_sha256"]) != target
        ]
        current_queue["item_count"] = len(current_queue["items"])
        current_queue["generated_at"] = decision["decided_at"]
        return current_queue

    def test_valid_decision_is_exact_append_and_queue_removal(self):
        previous_decisions = rq.empty_decisions()
        previous_queue = self.queue(self.item())
        decision = self.decision()
        current_decisions = {"schema_version": "1", "decisions": [decision]}
        current_queue = self.current_after_decision(previous_queue, decision)

        transition.validate_transition(
            previous_decisions,
            previous_queue,
            current_decisions,
            current_queue,
        )

    def test_old_decision_history_cannot_be_rewritten_or_deleted(self):
        old = self.decision()
        previous_decisions = {"schema_version": "1", "decisions": [old]}
        previous_queue = self.queue()
        rewritten = copy.deepcopy(old)
        rewritten["reason"] = "Changed history."
        current_decisions = {"schema_version": "1", "decisions": [rewritten]}

        with self.assertRaisesRegex(ValueError, "not append-only"):
            transition.validate_transition(
                previous_decisions,
                previous_queue,
                current_decisions,
                previous_queue,
            )

    def test_new_decision_must_target_exact_base_queue_artifact(self):
        previous_queue = self.queue(self.item())
        decision = self.decision(SHA_B)
        current_decisions = {"schema_version": "1", "decisions": [decision]}
        current_queue = copy.deepcopy(previous_queue)

        with self.assertRaisesRegex(ValueError, "pending in the base queue"):
            transition.validate_transition(
                rq.empty_decisions(),
                previous_queue,
                current_decisions,
                current_queue,
            )

    def test_queue_cannot_change_without_new_decision(self):
        previous_queue = self.queue(self.item())
        current_queue = self.queue()

        with self.assertRaisesRegex(ValueError, "changed without"):
            transition.validate_transition(
                rq.empty_decisions(),
                previous_queue,
                rq.empty_decisions(),
                current_queue,
            )

    def test_decision_transition_cannot_modify_unrelated_queue_item(self):
        first = self.item(SHA_A, "v1.0.0")
        second = self.item(SHA_B, "v1.1.0")
        previous_queue = self.queue(first, second)
        decision = self.decision(SHA_A)
        current_decisions = {"schema_version": "1", "decisions": [decision]}
        current_queue = self.current_after_decision(previous_queue, decision)
        current_queue["items"][0]["priority"] = "normal"

        with self.assertRaisesRegex(ValueError, "deterministic result"):
            transition.validate_transition(
                rq.empty_decisions(),
                previous_queue,
                current_decisions,
                current_queue,
            )

    def test_two_new_decisions_can_resolve_two_distinct_pending_artifacts(self):
        first = self.item(SHA_A, "v1.0.0")
        second = self.item(SHA_B, "v1.1.0")
        previous_queue = self.queue(first, second)
        decision_a = self.decision(SHA_A, decided_at="2026-08-09T02:00:00Z")
        decision_b = self.decision(SHA_B, decided_at="2026-08-09T02:05:00Z")
        current_decisions = {
            "schema_version": "1",
            "decisions": [decision_a, decision_b],
        }
        current_queue = self.queue()
        current_queue["generated_at"] = decision_b["decided_at"]
        current_queue["source_run_url"] = previous_queue["source_run_url"]

        transition.validate_transition(
            rq.empty_decisions(),
            previous_queue,
            current_decisions,
            current_queue,
        )


if __name__ == "__main__":
    unittest.main()

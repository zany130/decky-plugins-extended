import copy
import json
import os
import tempfile
import unittest

import accepted_baseline as ab


class AcceptedBaselineTests(unittest.TestCase):
    REPO = "https://github.com/example/plugin"
    SHA_OLD = "1" * 40
    SHA_NEW = "2" * 40

    def capability(self, capability_id, status="not_observed", rules=None):
        return {
            "id": capability_id,
            "title": capability_id.replace("_", " ").title(),
            "question": f"Does it use {capability_id}?",
            "status": status,
            "rule_ids": list(rules or []),
            "finding_count": 1 if status == "observed" else 0,
            "evidence_count": 1 if status == "observed" else 0,
            "distinct_evidence_count": 1 if status == "observed" else 0,
            "evidence_collapsed": 0,
            "evidence_truncated": False,
            "evidence": [
                {
                    "kind": "finding",
                    "message": "raw reviewer evidence must not be persisted",
                }
            ],
        }

    def report(self, *, release="v1.0.0", digest=None, commit=None, errors=None):
        digest = digest or ("a" * 64)
        commit = commit or self.SHA_OLD
        capabilities = [
            self.capability("command_execution", "observed", ["decky.exec"]),
            self.capability("network_communication", "observed", ["decky.network"]),
            self.capability("native_code", "observed", ["decky.native"]),
            self.capability("source_release_integrity", "observed", ["decky.source-diff"]),
        ]
        return {
            "repository": self.REPO,
            "plugin_name": "Example Plugin",
            "release": release,
            "artifact_sha256": digest,
            "artifact_url": "https://github.com/example/plugin/releases/download/v1/plugin.zip",
            "source_commit": commit,
            "final_classification": "MANUAL_REVIEW",
            "risk_score": 42,
            "schema_version": "1",
            "policy_version": "1",
            "reviewer_capabilities_schema_version": "1",
            "reviewer_capabilities": capabilities,
            "network_destinations": [
                {"destination": "api.example.com", "source_path": "src/api.ts"},
                {"destination": "cdn.example.com", "source_path": "src/cdn.ts"},
            ],
            "native_binaries": [
                {"path": "bin/helper", "sha256": "b" * 64, "size": 1234},
            ],
            "source_artifact_diff": {
                "same_path_modified": [
                    {"artifact_path": "dist/index.js", "source_path": "src/index.ts"},
                    {"artifact_path": "dist/vendor.js", "source_path": "src/vendor.ts"},
                ],
                "zip_only_executables": [{"artifact_path": "bin/helper"}],
            },
            "findings": [{"message": "raw scanner finding must not be persisted"}],
            "scanner_statuses": {"semgrep": "ok"},
            "errors": list(errors or []),
        }

    def audit_payload(self, report):
        return {
            "generated_at": "2026-08-08T12:00:00Z",
            "reports": [report],
        }

    def live_catalog(self, *, version="1.0.0", digest=None):
        return [
            {
                "name": "Example Plugin",
                "versions": [
                    {
                        "name": version,
                        "hash": digest or ("a" * 64),
                        "artifact": "https://example.invalid/plugin.zip",
                    }
                ],
            }
        ]

    def configured(self):
        return {ab.normalize_repository(self.REPO)}

    def build(self, report=None, live=None, existing=None):
        report = report or self.report()
        live = live or self.live_catalog()
        return ab.build_baseline(
            self.audit_payload(report),
            live,
            self.configured(),
            existing or ab.empty_baseline("https://store.example/plugins.json"),
            auditor_ref="d" * 40,
            live_catalog_url="https://store.example/plugins.json",
        )

    def test_matching_live_artifact_is_projected_without_raw_findings(self):
        payload, stats = self.build()

        self.assertEqual(stats["advanced"], 1)
        self.assertEqual(payload["entry_count"], 1)
        baseline = payload["reports"][0]
        self.assertEqual(baseline["artifact_sha256"], "a" * 64)
        self.assertEqual(baseline["baseline_live_version"], "1.0.0")
        self.assertNotIn("findings", baseline)
        self.assertNotIn("scanner_statuses", baseline)
        self.assertNotIn("artifact_url", baseline)
        self.assertNotIn("evidence", baseline["reviewer_capabilities"][0])
        self.assertEqual(
            baseline["network_destinations"],
            [
                {"destination": "api.example.com"},
                {"destination": "cdn.example.com"},
            ],
        )
        self.assertEqual(
            baseline["native_binaries"],
            [{"path": "bin/helper", "sha256": "b" * 64}],
        )
        self.assertEqual(len(baseline["source_artifact_diff"]["same_path_modified"]), 2)
        self.assertEqual(len(baseline["source_artifact_diff"]["zip_only_executables"]), 1)
        ab.validate_baseline(payload)

    def test_same_artifact_is_frozen_across_rescans(self):
        first, _ = self.build()
        changed_report = self.report()
        changed_report["risk_score"] = 999
        changed_report["reviewer_capabilities"][0]["rule_ids"] = ["new.rule"]
        changed_report["network_destinations"].append({"destination": "new.example.com"})

        second, stats = self.build(report=changed_report, existing=first)

        self.assertEqual(stats["advanced"], 0)
        self.assertEqual(stats["preserved"], 1)
        self.assertEqual(second, first)

    def test_new_live_artifact_advances_even_when_release_name_is_reused(self):
        first, _ = self.build()
        replacement = self.report(digest="c" * 64, commit=self.SHA_NEW)
        second, stats = self.build(
            report=replacement,
            live=self.live_catalog(digest="c" * 64),
            existing=first,
        )

        self.assertEqual(stats["advanced"], 1)
        self.assertEqual(second["reports"][0]["artifact_sha256"], "c" * 64)
        self.assertEqual(second["reports"][0]["source_commit"], self.SHA_NEW)

    def test_candidate_ahead_of_live_catalog_does_not_advance(self):
        first, _ = self.build()
        candidate = self.report(release="v2.0.0", digest="c" * 64, commit=self.SHA_NEW)

        second, stats = self.build(
            report=candidate,
            live=self.live_catalog(version="1.0.0", digest="a" * 64),
            existing=first,
        )

        self.assertEqual(stats["advanced"], 0)
        self.assertEqual(stats["preserved"], 1)
        self.assertEqual(second, first)

    def test_audit_errors_do_not_replace_last_good_baseline(self):
        first, _ = self.build()
        failed = self.report(release="v2.0.0", digest="c" * 64, errors=["scanner failed"])

        second, stats = self.build(
            report=failed,
            live=self.live_catalog(version="2.0.0", digest="c" * 64),
            existing=first,
        )

        self.assertEqual(stats["advanced"], 0)
        self.assertEqual(stats["preserved"], 1)
        self.assertEqual(second, first)

    def test_missing_initial_match_stays_explicitly_unavailable(self):
        payload, stats = self.build(
            report=self.report(release="v2.0.0", digest="c" * 64),
            live=self.live_catalog(version="1.0.0", digest="a" * 64),
        )

        self.assertEqual(payload["reports"], [])
        self.assertEqual(stats["unavailable"], 1)

    def test_removed_configured_repository_is_pruned(self):
        first, _ = self.build()
        payload, stats = ab.build_baseline(
            {"generated_at": "2026-08-08T13:00:00Z", "reports": []},
            [],
            set(),
            first,
            auditor_ref="d" * 40,
        )

        self.assertEqual(payload["entry_count"], 0)
        self.assertEqual(payload["reports"], [])
        self.assertEqual(stats["pruned"], 1)

    def test_secret_shaped_values_are_redacted_before_persistence(self):
        secret = "ghp_" + ("A" * 36)
        report = self.report()
        report["network_destinations"] = [{"destination": f"{secret}.example.com"}]
        report["native_binaries"] = [{"path": f"bin/{secret}", "sha256": "b" * 64}]

        payload, _ = self.build(report=report)
        serialized = json.dumps(payload)

        self.assertNotIn(secret, serialized)
        self.assertIn("[REDACTED]", serialized)
        ab.validate_baseline(payload)

    def test_validation_rejects_raw_report_fields_and_secret_text(self):
        payload, _ = self.build()
        bad = copy.deepcopy(payload)
        bad["reports"][0]["findings"] = []
        with self.assertRaises(ValueError):
            ab.validate_baseline(bad)

        secret = copy.deepcopy(payload)
        secret["reports"][0]["plugin_name"] = "github_pat_" + ("A" * 30)
        with self.assertRaises(ValueError):
            ab.validate_baseline(secret)

    def test_cli_build_and_validate_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            audit = os.path.join(temp_dir, "audit.json")
            live = os.path.join(temp_dir, "live.json")
            plugins = os.path.join(temp_dir, "plugins.txt")
            output = os.path.join(temp_dir, "accepted.json")
            with open(audit, "w", encoding="utf-8") as handle:
                json.dump(self.audit_payload(self.report()), handle)
            with open(live, "w", encoding="utf-8") as handle:
                json.dump(self.live_catalog(), handle)
            with open(plugins, "w", encoding="utf-8") as handle:
                handle.write(self.REPO + "\n")

            self.assertEqual(
                ab.main(
                    [
                        "--audit-report",
                        audit,
                        "--live-catalog",
                        live,
                        "--plugins-file",
                        plugins,
                        "--output",
                        output,
                        "--auditor-ref",
                        "d" * 40,
                    ]
                ),
                0,
            )
            self.assertEqual(ab.main(["--validate-only", output]), 0)


if __name__ == "__main__":
    unittest.main()

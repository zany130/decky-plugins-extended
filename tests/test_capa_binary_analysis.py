"""Regression tests for reviewer-focused capa binary capability enrichment."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import capa_binary_analysis as capa_analysis


@dataclass
class Finding:
    rule_id: str
    severity: str
    classification: str
    path: str
    line: int
    message: str
    evidence: str
    scanner: str
    allowlisted: bool = False


@dataclass
class ScannerStatus:
    name: str
    status: str
    version: str | None = None
    db_version: str | None = None
    detail: str | None = None


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    scanner_statuses: list[ScannerStatus] = field(default_factory=list)
    native_binaries: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    final_classification: str = "MANUAL_REVIEW"
    risk_score: int = 5


class CapaBinaryAnalysisTests(unittest.TestCase):
    @staticmethod
    def _core() -> ModuleType:
        core = ModuleType("fake_capa_core")
        core.Finding = Finding
        core.ScannerStatus = ScannerStatus
        core.EVIDENCE_MAX_LEN = 256
        core.POLICY_VERSION = "1"
        core.CACHE_DIR = ".audit-cache"
        core._truncate = lambda value, limit: str(value)[:limit]
        core._scanner_enabled = lambda policy, name: bool(
            (policy.get("scanners", {}).get(name, {}) or {}).get("enabled", True)
        )
        core._run_scanner = lambda *_args, **_kwargs: (True, "9.4.0", "")
        core.identify_binary = lambda data, path: (
            {"path": path, "type": "elf_binary", "label": "ELF"}
            if data.startswith(b"\x7fELF")
            else None
        )
        core.classify_findings = lambda findings, **_kwargs: (
            "MANUAL_REVIEW",
            5,
        )
        core.run_semgrep = lambda _root, _policy: (
            ScannerStatus("semgrep", "passed"),
            [],
        )
        core._cache_key = lambda repository, release, sha, policy_version="1": (
            f"{repository}|{release}|{sha}|{policy_version}"
        )
        core.generate_markdown_report = lambda _report: (
            "## Included Native Binaries\n\n## Archive Statistics\n"
        )

        def audit_repository(
            _repo,
            policy,
            _exceptions,
            cache_dir=".audit-cache",
            skip_cache=False,
        ):
            del cache_dir, skip_cache
            core.run_semgrep("/tmp/artifact", policy)
            return Report(
                findings=[
                    Finding(
                        "NATIVE_BINARY",
                        "medium",
                        "MANUAL_REVIEW",
                        "bin/helper",
                        0,
                        "Native binary: ELF",
                        "ELF",
                        "binary-detector",
                    )
                ],
                native_binaries=[
                    {"path": "bin/helper", "type": "elf_binary", "label": "ELF"}
                ],
            )

        core.audit_repository = audit_repository
        return core

    def test_parser_groups_capabilities_and_filters_internal_rules(self):
        document = {
            "rules": {
                "spawn process": {
                    "meta": {
                        "name": "spawn process",
                        "namespace": "host-interaction/process",
                    }
                },
                "send http": {
                    "meta": {
                        "name": "send HTTP request",
                        "namespace": "communication/http",
                    }
                },
                "internal": {
                    "meta": {
                        "name": "(internal) file format",
                        "namespace": "internal/file",
                    }
                },
                "experimental": {
                    "meta": {
                        "name": "experimental capability",
                        "namespace": "nursery/test",
                    }
                },
            }
        }

        summary = capa_analysis._parse_capa_document(document)

        self.assertEqual(summary["capability_count"], 2)
        self.assertEqual(summary["suppressed_internal_or_experimental"], 2)
        self.assertEqual(
            [group["name"] for group in summary["groups"]],
            ["process and command execution", "network communication"],
        )

    def test_binary_cache_is_keyed_by_sha_and_capa_version(self):
        core = self._core()
        document = {
            "rules": {
                "read file": {
                    "meta": {
                        "name": "read file",
                        "namespace": "host-interaction/file-system",
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / "helper"
            binary.write_bytes(b"\x7fELF" + b"X" * 64)
            info = {"full_path": str(binary)}
            with patch.object(
                core,
                "_run_scanner",
                return_value=(True, json.dumps(document), ""),
            ) as run:
                first = capa_analysis._analyze_binary(
                    core, info, root, "9.4.0", 10
                )
                second = capa_analysis._analyze_binary(
                    core, info, root, "9.4.0", 10
                )

        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(run.call_count, 1)

    def test_dependency_binary_is_collapsed_by_default(self):
        core = self._core()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Plugin" / "node_modules" / "pkg" / "helper"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"\x7fELF" + b"X" * 64)
            with patch.object(capa_analysis.shutil, "which", return_value="/usr/bin/capa"), patch.object(
                capa_analysis,
                "_capa_version",
                return_value=("9.4.0", None),
            ), patch.object(core, "_run_scanner") as run:
                status, results = capa_analysis._run_capa(
                    core,
                    root,
                    {"scanners": {"capa": {"enabled": True}}},
                    root,
                )

        result = results["Plugin/node_modules/pkg/helper"]
        self.assertEqual(status.status, "passed")
        self.assertEqual(result["status"], "skipped")
        self.assertIn("dependency", result["reason"])
        run.assert_not_called()

    def test_merge_enriches_existing_native_binary_finding(self):
        core = self._core()
        report = Report(
            findings=[
                Finding(
                    "NATIVE_BINARY",
                    "medium",
                    "MANUAL_REVIEW",
                    "bin/helper",
                    0,
                    "Native binary: ELF",
                    "ELF",
                    "binary-detector",
                )
            ],
            native_binaries=[{"path": "bin/helper"}],
        )
        result = {
            "status": "analyzed",
            "sha256": "a" * 64,
            "size_bytes": 4,
            "provenance": "plugin_runtime",
            "confidence": "high",
            "capability_count": 1,
            "groups": [
                {
                    "name": "process and command execution",
                    "count": 1,
                    "examples": ["spawn process"],
                }
            ],
            "representative_capabilities": ["spawn process"],
        }

        capa_analysis._merge_results_into_report(
            core,
            report,
            ScannerStatus("capa", "passed"),
            {"bin/helper": result},
            {"scanners": {"capa": {"enabled": True}}},
        )

        self.assertIn("capa summary", report.findings[0].message)
        self.assertEqual(report.findings[0].evidence, "spawn process")
        self.assertEqual(report.native_binaries[0]["capa"]["capability_count"], 1)
        self.assertEqual(report.scanner_statuses[0].name, "capa")

    def test_markdown_is_bounded_and_explains_capa_limitations(self):
        report = Report(
            native_binaries=[
                {
                    "path": "bin/helper",
                    "capa": {
                        "status": "analyzed",
                        "sha256": "b" * 64,
                        "provenance": "plugin_runtime",
                        "capability_count": 2,
                        "groups": [
                            {
                                "name": "network communication",
                                "count": 2,
                                "examples": ["send HTTP request"],
                            }
                        ],
                        "representative_capabilities": [
                            "send HTTP request",
                            "connect TCP socket",
                        ],
                        "limitations": [
                            "packed or obfuscated input may produce incomplete static results"
                        ],
                    },
                },
                {
                    "path": "node_modules/pkg/helper",
                    "capa": {
                        "status": "skipped",
                        "reason": "dependency or vendored binary collapsed from primary review",
                    },
                },
            ]
        )

        markdown = capa_analysis._binary_capability_markdown(report)

        self.assertIn("Native Binary Capability Analysis", markdown)
        self.assertIn("network communication (2)", markdown)
        self.assertIn("not proof of maliciousness or safety", markdown)
        self.assertIn("Skipped binary inventory — 1", markdown)

    def test_install_versions_audit_cache_and_adds_separate_status(self):
        core = self._core()
        capa_analysis.install(core)
        result = {
            "status": "analyzed",
            "sha256": "c" * 64,
            "size_bytes": 4,
            "provenance": "plugin_runtime",
            "confidence": "high",
            "capability_count": 0,
            "groups": [],
            "representative_capabilities": [],
        }
        with patch.object(
            capa_analysis,
            "_run_capa",
            return_value=(
                ScannerStatus("capa", "passed", version="9.4.0"),
                {"bin/helper": result},
            ),
        ):
            report = core.audit_repository(
                "https://github.com/owner/repo",
                {"scanners": {"capa": {"enabled": True}}},
                [],
            )

        self.assertTrue(any(status.name == "capa" for status in report.scanner_statuses))
        self.assertIn("decky-capa-v1", core._cache_key("r", "v", "sha"))
        rendered = core.generate_markdown_report(report)
        self.assertIn("Native Binary Capability Analysis", rendered)


if __name__ == "__main__":
    unittest.main()

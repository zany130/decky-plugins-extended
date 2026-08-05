"""Regression tests for network-destination provenance reporting."""

from __future__ import annotations

import unittest
from dataclasses import asdict, dataclass, field
from types import ModuleType
from typing import Any

import network_destination_filters as ndf


class NetworkReferenceProvenanceTests(unittest.TestCase):
    def test_references_retain_source_lines_and_redact_report_urls(self):
        refs = ndf.extract_network_references(
            "first = 'https://user:secret@API.Example.COM:8443/v1?token=secret'\n"
            "server = '192.168.1.25'\n"
        )

        self.assertEqual(refs[0]["destination"], "api.example.com:8443")
        self.assertEqual(refs[0]["line"], 1)
        self.assertEqual(refs[0]["report_url"], "https://api.example.com:8443")
        # The compatibility extractor still returns the source spelling to callers,
        # but report aggregation consumes only report_url.
        self.assertIn("user:secret", refs[0]["url"])
        self.assertEqual(refs[1]["destination"], "192.168.1.25")
        self.assertEqual(refs[1]["line"], 2)

    def test_path_ownership_classification(self):
        cases = {
            "main.py": ("plugin_runtime", "high"),
            "src/index.tsx": ("plugin_runtime", "high"),
            "dist/index.js": ("generated_runtime_bundle", "medium"),
            "dist/index.js.map": ("source_map_or_build_metadata", "low"),
            "node_modules/pkg/index.js": ("dependency_or_vendored", "low"),
            # Dependency ownership wins over the README basename.
            "node_modules/pkg/README.md": ("dependency_or_vendored", "low"),
            "tests/fixture.py": ("documentation_or_test", "low"),
            "docs/README.md": ("documentation_or_test", "low"),
            ".github/workflows/release.yml": ("documentation_or_test", "low"),
            "./.github/workflows/release.yml": ("documentation_or_test", "low"),
            "package.json": ("source_map_or_build_metadata", "low"),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(ndf.classify_network_source(path), expected)

    def test_aggregation_prioritizes_runtime_and_corroborates_weak_sources(self):
        records = [
            {
                "destination": "runtime.example.com",
                "path": "main.py",
                "line": 4,
                "provenance": "plugin_runtime",
                "confidence": "high",
                "kind": "url",
                "report_url": "https://runtime.example.com",
            },
            {
                "destination": "bundle.example.com",
                "path": "dist/index.js",
                "line": 1,
                "provenance": "generated_runtime_bundle",
                "confidence": "medium",
                "kind": "url",
                "report_url": "https://bundle.example.com",
            },
            {
                "destination": "corroborated.example.com",
                "path": "docs/README.md",
                "line": 9,
                "provenance": "documentation_or_test",
                "confidence": "low",
                "kind": "url",
                "report_url": "https://corroborated.example.com",
            },
            {
                "destination": "corroborated.example.com",
                "path": "tests/example.py",
                "line": 12,
                "provenance": "documentation_or_test",
                "confidence": "low",
                "kind": "url",
                "report_url": "https://corroborated.example.com",
            },
            # Repetition in the same file is retained as evidence but does not
            # count as corroboration across distinct paths.
            {
                "destination": "single-file.example.com",
                "path": "README.md",
                "line": 2,
                "provenance": "documentation_or_test",
                "confidence": "low",
                "kind": "url",
                "report_url": "https://single-file.example.com",
            },
            {
                "destination": "single-file.example.com",
                "path": "README.md",
                "line": 8,
                "provenance": "documentation_or_test",
                "confidence": "low",
                "kind": "url",
                "report_url": "https://single-file.example.com",
            },
        ]

        by_destination = {
            item["destination"]: item
            for item in ndf._aggregate_references(records)
        }

        self.assertEqual(by_destination["runtime.example.com"]["confidence"], "high")
        self.assertEqual(by_destination["bundle.example.com"]["confidence"], "medium")
        self.assertEqual(
            by_destination["corroborated.example.com"]["confidence"], "medium"
        )
        self.assertEqual(
            by_destination["single-file.example.com"]["confidence"], "low"
        )
        self.assertEqual(
            by_destination["single-file.example.com"]["source_count"], 2
        )


class NetworkProvenanceInstallTests(unittest.TestCase):
    @staticmethod
    def _fake_core(*, cached: bool = False) -> ModuleType:
        core = ModuleType("fake_audit_core")
        core.POLICY_VERSION = "1"

        @dataclass
        class AuditReport:
            extracted_domains: list[str] = field(default_factory=list)

        core.AuditReport = AuditReport
        core.scan_text_content = lambda _content, _path, _ext: []

        def audit_repository(*_args: Any, **_kwargs: Any) -> Any:
            report = core.AuditReport()
            if cached:
                report.network_destinations = [
                    {
                        "destination": "cached.example.com",
                        "confidence": "high",
                        "sources": [],
                    }
                ]
                report.network_destination_summary = {"total_destinations": 1}
                report.extracted_domains = ["cached.example.com"]
                return report

            files = [
                ("main.py", ".py", "api = 'https://API.Example.com/v1'\n"),
                ("dist/index.js", ".js", "fetch('https://bundle.example.com/x')\n"),
                ("docs/README.md", ".md", "https://weak.example.com/a\n"),
                ("tests/example.py", ".py", "https://weak.example.com/b\n"),
                (
                    "settings.py",
                    ".py",
                    "url = 'https://user:password@private.example.com/path?token=x'\n",
                ),
            ]
            for path, ext, content in files:
                core.scan_text_content(content, path, ext)
                core.extract_urls_and_domains(content)
            return report

        core.audit_repository = audit_repository
        core.generate_markdown_report = lambda report: (
            "# Report\n\n## Network Destinations\n\n"
            + "".join(f"- `{item}`\n" for item in report.extracted_domains)
            + "\n## Scanner Status\n\n- passed\n"
        )
        core._cache_key = lambda repository, release, sha, policy_version="1": (
            f"{repository}|{release}|{sha}|{policy_version}"
        )
        return core

    def test_install_adds_structured_provenance_and_preserves_legacy_inventory(self):
        core = self._fake_core()
        ndf.install(core)

        report = core.audit_repository("https://github.com/example/plugin", {}, [])
        serialized = asdict(report)
        by_destination = {
            item["destination"]: item
            for item in report.network_destinations
        }

        self.assertEqual(
            report.extracted_domains,
            [
                "api.example.com",
                "private.example.com",
                "bundle.example.com",
                "weak.example.com",
            ],
        )
        self.assertEqual(by_destination["api.example.com"]["confidence"], "high")
        self.assertEqual(by_destination["bundle.example.com"]["confidence"], "medium")
        self.assertEqual(by_destination["weak.example.com"]["confidence"], "medium")
        self.assertEqual(by_destination["api.example.com"]["sources"][0]["line"], 1)
        self.assertEqual(
            by_destination["private.example.com"]["sources"][0]["url"],
            "https://private.example.com",
        )
        self.assertNotIn("password", repr(serialized))
        self.assertNotIn("token=x", repr(serialized))
        self.assertIn("network_destination_summary", serialized)

        markdown = core.generate_markdown_report(report)
        self.assertIn("High-confidence runtime destinations", markdown)
        self.assertIn("generated runtime bundle", markdown)
        self.assertIn("## Scanner Status", markdown)

        self.assertIn(
            "network-provenance-v1",
            core._cache_key("example/plugin", "v1", "abc"),
        )

    def test_cache_hit_keeps_existing_provenance(self):
        core = self._fake_core(cached=True)
        ndf.install(core)

        report = core.audit_repository("https://github.com/example/plugin", {}, [])

        self.assertEqual(report.extracted_domains, ["cached.example.com"])
        self.assertEqual(
            report.network_destinations[0]["destination"],
            "cached.example.com",
        )


if __name__ == "__main__":
    unittest.main()

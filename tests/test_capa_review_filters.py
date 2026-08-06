"""Corpus-derived capa prioritization and coverage regressions."""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from types import ModuleType

import capa_review_filters as filters


@dataclass
class ScannerStatus:
    name: str
    status: str
    version: str | None = None
    db_version: str | None = None
    detail: str | None = None


class CapaReviewFilterTests(unittest.TestCase):
    @staticmethod
    def _core() -> ModuleType:
        core = ModuleType("fake_capa_filter_core")
        core.ScannerStatus = ScannerStatus
        return core

    def test_supported_smaller_targets_precede_arm64_and_gstreamer_is_dependency(self):
        discovered = [
            {
                "path": "Plugin/bin/tool-arm64.so",
                "type": "elf_binary",
                "size_bytes": 10,
                "provenance": "plugin_runtime",
                "confidence": "high",
            },
            {
                "path": "Plugin/bin/tool-glibc-i386.so",
                "type": "elf_binary",
                "size_bytes": 20,
                "provenance": "plugin_runtime",
                "confidence": "high",
            },
            {
                "path": "Plugin/bin/tool-glibc-x86_64.so",
                "type": "elf_binary",
                "size_bytes": 30,
                "provenance": "plugin_runtime",
                "confidence": "high",
            },
            {
                "path": "Plugin/gst-plugins/libgstnice.so",
                "type": "elf_binary",
                "size_bytes": 5,
                "provenance": "plugin_runtime",
                "confidence": "high",
            },
            {
                "path": "Plugin/bin/neutral-large",
                "type": "elf_binary",
                "size_bytes": 500,
                "provenance": "plugin_runtime",
                "confidence": "high",
            },
            {
                "path": "Plugin/bin/neutral-small",
                "type": "elf_binary",
                "size_bytes": 50,
                "provenance": "plugin_runtime",
                "confidence": "high",
            },
        ]

        ordered = filters.prepare_discovered_binaries(discovered)

        paths = [item["path"] for item in ordered]
        self.assertEqual(paths[0], "Plugin/bin/tool-glibc-x86_64.so")
        self.assertEqual(paths[1], "Plugin/bin/tool-glibc-i386.so")
        self.assertLess(
            paths.index("Plugin/bin/neutral-small"),
            paths.index("Plugin/bin/neutral-large"),
        )
        arm64 = next(item for item in ordered if "arm64" in item["path"])
        self.assertEqual(arm64["type"], "elf_arm64_unsupported")
        gstreamer = next(item for item in ordered if "gst-plugins" in item["path"])
        self.assertEqual(gstreamer["provenance"], "dependency_or_vendored")
        self.assertEqual(gstreamer["confidence"], "high")

    def test_any_failed_selected_binary_marks_optional_capa_coverage_failed(self):
        core = self._core()
        raw_status = ScannerStatus(
            "capa",
            "passed",
            version="9.4.0",
            detail="1 binary analyzed; 1 incomplete",
        )
        raw_results = {
            "bin/small": {"status": "analyzed", "capability_count": 5},
            "bin/large": {"status": "failed", "detail": "timed out"},
        }

        status, results = filters.finalize_capa_results(
            core, raw_status, raw_results
        )

        self.assertIs(results, raw_results)
        self.assertEqual(status.status, "failed")
        self.assertEqual(status.version, "9.4.0")
        self.assertIn("coverage incomplete for 1", status.detail)

    def test_arm64_skip_reason_and_scanner_status_are_reviewer_explicit(self):
        core = self._core()
        raw_results = {
            "bin/helper-arm64.so": {
                "status": "skipped",
                "type": "elf_arm64_unsupported",
                "reason": "format not supported",
            }
        }

        status, results = filters.finalize_capa_results(
            core,
            ScannerStatus("capa", "passed", version="9.4.0", detail="0 analyzed"),
            raw_results,
        )

        self.assertEqual(status.status, "unsupported")
        self.assertEqual(status.version, "9.4.0")
        self.assertIn("unsupported for 1 ARM64", status.detail)
        self.assertIn(
            "direct ARM64 ELF analysis is unsupported",
            results["bin/helper-arm64.so"]["reason"],
        )
        self.assertIn(
            "manual binary review",
            results["bin/helper-arm64.so"]["reason"],
        )


if __name__ == "__main__":
    unittest.main()

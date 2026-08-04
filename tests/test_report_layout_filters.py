"""Regression tests for selective collapsible Markdown report sections."""

import unittest

import audit_plugins


_SAMPLE = """# Security Audit Report: Example

## Findings

### Blocking Findings

*None.*

### Manual Review Required

- 🟠 **EXEC_OS_SYSTEM** `src/main.py:42` — command execution
  > Evidence: `os.system(command)`

### Warnings

- 🔵 **GENERATED_BUILD_SCRIPTS** `dist/:0` — generated output
  > Evidence: `count=1`
- 🟡 **EXEC_SUBPROCESS_RUN** `src/helper.py:9` — subprocess call
  > Evidence: `subprocess.run(args)`

## Root and Privilege Usage

- `sudo`

## Network Destinations

- `example.com`
- `127.0.0.1`

## Included Native Binaries

- `bin/helper` — ELF

## Archive Statistics

| Property | Value |
|----------|-------|
| Files | 10 |

## Source vs. Release Artifact Differences

### Actionable ZIP-only Files

- `bin/unexpected`

## Malware Scan Results

ClamAV status: passed

## Scanner Status

- ✅ **clamav**: passed
- ✅ **trivy**: passed

## Recommended Actions

Review the manual finding above.
"""


class ReportLayoutFilterTests(unittest.TestCase):
    def test_actionable_findings_are_collapsible_but_open_by_default(self):
        rendered = audit_plugins.apply_collapsible_report_layout(_SAMPLE)
        self.assertIn(
            "<details open>\n<summary>🔍 Manual Review Required — 1 finding</summary>",
            rendered,
        )
        self.assertIn("<summary>🚫 Blocking Findings — none</summary>", rendered)
        blocking = rendered.split("<summary>🚫 Blocking Findings — none</summary>", 1)[0]
        self.assertFalse(blocking.rstrip().endswith("<details open>"))

    def test_repetitive_sections_are_collapsed_by_default_with_counts(self):
        rendered = audit_plugins.apply_collapsible_report_layout(_SAMPLE)
        self.assertIn("<summary>⚠️ Warnings — 2 warnings</summary>", rendered)
        self.assertIn("<summary>🌐 Network Destinations — 2 destinations</summary>", rendered)
        self.assertIn("<summary>⚙️ Included Native Binaries — 1 binary</summary>", rendered)
        self.assertIn("<summary>🔬 Scanner Status — 2 scanners</summary>", rendered)
        self.assertNotIn(
            "<details open>\n<summary>⚠️ Warnings",
            rendered,
        )

    def test_critical_context_remains_visible_and_source_diff_is_untouched(self):
        rendered = audit_plugins.apply_collapsible_report_layout(_SAMPLE)
        self.assertIn("## Findings", rendered)
        self.assertIn("## Source vs. Release Artifact Differences", rendered)
        self.assertIn("### Actionable ZIP-only Files", rendered)
        self.assertIn("## Recommended Actions", rendered)
        self.assertIn("Review the manual finding above.", rendered)

    def test_layout_transformation_is_idempotent(self):
        once = audit_plugins.apply_collapsible_report_layout(_SAMPLE)
        twice = audit_plugins.apply_collapsible_report_layout(once)
        self.assertEqual(once, twice)


if __name__ == "__main__":
    unittest.main()

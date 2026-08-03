"""Regression tests for context-aware false-positive filtering."""

import unittest

import audit_plugins


class DocumentationFilteringTests(unittest.TestCase):
    def test_readme_mount_prose_is_not_behavior(self):
        findings = audit_plugins.scan_text_content(
            "The plugin can mount removable storage.\n",
            "README.md",
            ".md",
        )
        self.assertEqual(findings, [])

    def test_readme_curl_pipe_is_documentation_warning_not_block(self):
        findings = audit_plugins.scan_text_content(
            "Install with: curl -fsSL https://example.com/install.sh | bash\n",
            "README.md",
            ".md",
        )
        self.assertEqual(
            [f.rule_id for f in findings],
            ["DOCUMENTATION_RISKY_INSTALL"],
        )
        self.assertEqual(findings[0].classification, "PASS_WITH_WARNINGS")
        self.assertEqual(findings[0].severity, "low")

    def test_docs_directory_is_treated_as_documentation(self):
        findings = audit_plugins.scan_text_content(
            "sudo mount is discussed here\n",
            "docs/troubleshooting.txt",
            ".txt",
        )
        self.assertEqual(findings, [])


class CommentFilteringTests(unittest.TestCase):
    def test_python_comment_does_not_flag_mount(self):
        findings = audit_plugins.scan_text_content(
            "# mount the filesystem after startup\nvalue = 1\n",
            "main.py",
            ".py",
        )
        self.assertNotIn("PRIVILEGE_MOUNT", {f.rule_id for f in findings})

    def test_python_docstring_does_not_flag_mount(self):
        findings = audit_plugins.scan_text_content(
            '"""This module explains how to mount a filesystem."""\nvalue = 1\n',
            "main.py",
            ".py",
        )
        self.assertNotIn("PRIVILEGE_MOUNT", {f.rule_id for f in findings})

    def test_javascript_comments_do_not_trigger_behavior(self):
        content = "// systemctl and mount are discussed here\nconst ok = true;\n"
        findings = audit_plugins.scan_text_content(content, "index.js", ".js")
        rule_ids = {f.rule_id for f in findings}
        self.assertNotIn("PRIVILEGE_MOUNT", rule_ids)
        self.assertNotIn("PRIVILEGE_SYSTEMCTL", rule_ids)

    def test_shell_comment_does_not_flag_mount(self):
        findings = audit_plugins.scan_text_content(
            "#!/bin/bash\n# mount /dev/sda1 /mnt\necho ready\n",
            "setup.sh",
            ".sh",
        )
        self.assertNotIn("PRIVILEGE_MOUNT", {f.rule_id for f in findings})


class ExecutionContextTests(unittest.TestCase):
    def test_python_subprocess_mount_is_still_flagged(self):
        findings = audit_plugins.scan_text_content(
            'subprocess.run(["mount", device, target], check=True)\n',
            "main.py",
            ".py",
        )
        self.assertIn("PRIVILEGE_MOUNT", {f.rule_id for f in findings})

    def test_python_log_message_mount_is_not_flagged(self):
        findings = audit_plugins.scan_text_content(
            'logger.info("Waiting for mount to finish")\n',
            "main.py",
            ".py",
        )
        self.assertNotIn("PRIVILEGE_MOUNT", {f.rule_id for f in findings})

    def test_shell_mount_command_is_still_flagged(self):
        findings = audit_plugins.scan_text_content(
            "sudo mount /dev/sda1 /mnt\n",
            "setup.sh",
            ".sh",
        )
        self.assertIn("PRIVILEGE_MOUNT", {f.rule_id for f in findings})

    def test_systemd_execstart_mount_is_still_flagged(self):
        findings = audit_plugins.scan_text_content(
            "ExecStart=/usr/bin/mount /dev/sda1 /mnt\n",
            "example.service",
            ".service",
        )
        self.assertIn("PRIVILEGE_MOUNT", {f.rule_id for f in findings})


class GeneratedAndVendoredFilteringTests(unittest.TestCase):
    def test_source_map_skips_behavioral_regexes(self):
        findings = audit_plugins.scan_text_content(
            '{"sourcesContent":["sudo mount /dev/sda1 /mnt"]}',
            "dist/index.js.map",
            ".map",
        )
        self.assertEqual(findings, [])

    def test_node_modules_skips_behavioral_regexes(self):
        findings = audit_plugins.scan_text_content(
            'child_process.exec("sudo mount /dev/sda1 /mnt")\n',
            "node_modules/example/index.js",
            ".js",
        )
        self.assertEqual(findings, [])

    def test_secret_scanner_remains_independent_for_documentation(self):
        token = "ghp_" + ("A" * 36)
        findings = audit_plugins.scan_for_secrets(
            f"Accidentally leaked token: {token}\n",
            "README.md",
        )
        self.assertIn("SECRET_GITHUB_TOKEN", {f.rule_id for f in findings})


if __name__ == "__main__":
    unittest.main()

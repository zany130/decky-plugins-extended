"""Contract tests for the independently implemented Decky Semgrep baseline."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class SemgrepRuleContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules_path = Path(__file__).resolve().parents[1] / "semgrep-rules.yml"
        cls.raw = cls.rules_path.read_text(encoding="utf-8")
        cls.rules = {
            rule["id"]: rule
            for rule in yaml.safe_load(cls.raw)["rules"]
        }

    def test_rules_are_marked_as_independent_with_attribution(self) -> None:
        self.assertEqual(len(self.rules), 5)
        for rule in self.rules.values():
            metadata = rule.get("metadata") or {}
            self.assertEqual(metadata.get("implementation"), "independent")
            self.assertEqual(metadata.get("confidence"), "HIGH")
            self.assertIn("beallio/decky-plugins-extended@", metadata.get("inspired_by", ""))

    def test_python_dynamic_rule_covers_compile_modes(self) -> None:
        rule_text = str(self.rules["decky.python.dynamic-execution"])
        self.assertIn('compile(..., "eval", ...)', rule_text)
        self.assertIn('compile(..., "exec", ...)', rule_text)
        self.assertIn('compile(..., "single", ...)', rule_text)

    def test_python_shell_rule_is_limited_to_shell_capable_subprocess_apis(self) -> None:
        rule_text = str(self.rules["decky.python.shell-command"])
        self.assertIn("shell=True", rule_text)
        for function in ("Popen", "call", "check_call", "check_output", "run"):
            self.assertIn(function, rule_text)

    def test_javascript_dynamic_rule_covers_scoped_eval_and_node_vm(self) -> None:
        rule_text = str(self.rules["decky.javascript.dynamic-execution"])
        self.assertIn("globalThis.eval", rule_text)
        self.assertIn("window.eval", rule_text)
        self.assertIn("runInNewContext", rule_text)
        self.assertIn("runInThisContext", rule_text)

    def test_child_process_rule_covers_commonjs_esm_and_exec_sync(self) -> None:
        rule_text = str(self.rules["decky.javascript.child-process-exec"])
        self.assertIn('require("node:child_process")', rule_text)
        self.assertIn('import * as $CP from "child_process"', rule_text)
        self.assertIn('import { $EXEC } from "node:child_process"', rule_text)
        self.assertIn("execSync", rule_text)

    def test_private_key_rule_covers_additional_key_headers(self) -> None:
        regex = self.rules["decky.generic.private-key"]["pattern-regex"]
        self.assertIn("ENCRYPTED", regex)
        self.assertIn("DSA", regex)
        self.assertIn("PGP PRIVATE KEY BLOCK", regex)


if __name__ == "__main__":
    unittest.main()

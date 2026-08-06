"""Policy-default regression for the optional capa scanner."""

from __future__ import annotations

import unittest

import audit_plugins


class CapaPolicyDefaultTests(unittest.TestCase):
    def test_omitted_capa_setting_remains_disabled(self):
        policy = audit_plugins._default_policy()

        self.assertEqual(
            policy["scanners"]["capa"],
            {"enabled": False, "required": False},
        )

    def test_repository_policy_explicitly_enables_capa(self):
        policy = audit_plugins.load_policy("security-policy.yml")

        self.assertTrue(policy["scanners"]["capa"]["enabled"])
        self.assertFalse(policy["scanners"]["capa"]["required"])


if __name__ == "__main__":
    unittest.main()

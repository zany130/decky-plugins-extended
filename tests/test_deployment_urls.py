"""Regression tests for deployment URL ownership.

These tests ensure that:
- The default live catalog URL points to the zany130 Cloudflare Pages deployment.
- The LIVE_CATALOG_URL environment variable overrides the default.
- No production code or active documentation uses the old Beallio deployment URL
  as an operational URL.
"""

import importlib
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure check_for_updates can be imported without GITHUB_TOKEN
os.environ.setdefault("GITHUB_TOKEN", "test-token")

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_STABLE = "https://zany130-decky-plugins-extended.pages.dev/plugins.json"
EXPECTED_TESTING = "https://zany130-decky-plugins-extended.pages.dev/testing_plugins.json"
EXPECTED_ROOT = "https://zany130-decky-plugins-extended.pages.dev"

OLD_DEPLOYMENT_DOMAIN = "decky-extended-plugins.beallio.com"

# Files where the old deployment domain must not appear as an operational URL.
# Upstream attribution uses "github.com/beallio/..." which is a legitimate
# repository reference and is not covered by this check.
OPERATIONAL_FILES = [
    "check_for_updates.py",
    "static/index.html",
    ".github/workflows/generate.yml",
]


class DefaultLiveCatalogUrlTests(unittest.TestCase):
    def _fresh_module(self, env_overrides=None):
        """Import check_for_updates with a clean environment."""
        env = {k: v for k, v in os.environ.items() if k != "LIVE_CATALOG_URL"}
        if env_overrides:
            env.update(env_overrides)
        with patch.dict(os.environ, env, clear=True):
            if "check_for_updates" in sys.modules:
                del sys.modules["check_for_updates"]
            import check_for_updates as cfu
            importlib.reload(cfu)
            return cfu

    def test_default_live_catalog_url_constant(self):
        cfu = self._fresh_module()
        self.assertEqual(cfu.DEFAULT_LIVE_CATALOG_URL, EXPECTED_STABLE)

    def test_live_url_uses_default_when_env_not_set(self):
        cfu = self._fresh_module()
        self.assertEqual(cfu.LIVE_URL, EXPECTED_STABLE)

    def test_live_url_env_override(self):
        override = "https://example.invalid/custom_plugins.json"
        cfu = self._fresh_module({"LIVE_CATALOG_URL": override})
        self.assertEqual(cfu.LIVE_URL, override)

    def test_default_url_does_not_contain_old_deployment(self):
        cfu = self._fresh_module()
        self.assertNotIn(OLD_DEPLOYMENT_DOMAIN, cfu.DEFAULT_LIVE_CATALOG_URL)

    def test_live_url_does_not_contain_old_deployment_by_default(self):
        cfu = self._fresh_module()
        self.assertNotIn(OLD_DEPLOYMENT_DOMAIN, cfu.LIVE_URL)


class OperationalUrlRegressionTests(unittest.TestCase):
    """Ensure the old Beallio deployment domain is not present in operational files."""

    def _check_file(self, rel_path):
        path = REPO_ROOT / rel_path
        content = path.read_text(encoding="utf-8")
        self.assertNotIn(
            OLD_DEPLOYMENT_DOMAIN,
            content,
            f"{rel_path} still contains an operational reference to "
            f"'{OLD_DEPLOYMENT_DOMAIN}'.  Update it to use the zany130 "
            "Cloudflare Pages URL.",
        )

    def test_check_for_updates_no_old_domain(self):
        self._check_file("check_for_updates.py")

    def test_index_html_no_old_domain(self):
        self._check_file("static/index.html")

    def test_generate_workflow_no_old_domain(self):
        self._check_file(".github/workflows/generate.yml")


class ReadmeDeploymentUrlTests(unittest.TestCase):
    """Verify the README documents the correct production URLs."""

    def setUp(self):
        self.readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    def test_readme_contains_stable_url(self):
        self.assertIn(EXPECTED_STABLE, self.readme)

    def test_readme_contains_testing_url(self):
        self.assertIn(EXPECTED_TESTING, self.readme)

    def test_readme_contains_root_url(self):
        self.assertIn(EXPECTED_ROOT, self.readme)


class IndexHtmlDeploymentUrlTests(unittest.TestCase):
    """Verify the landing page uses the correct production URLs."""

    def setUp(self):
        self.html = (REPO_ROOT / "static" / "index.html").read_text(encoding="utf-8")

    def test_index_html_copy_stable_url(self):
        self.assertIn(EXPECTED_STABLE, self.html)

    def test_index_html_copy_testing_url(self):
        self.assertIn(EXPECTED_TESTING, self.html)

    def test_index_html_github_link_is_fork(self):
        self.assertIn("github.com/zany130/decky-plugins-extended", self.html)


if __name__ == "__main__":
    unittest.main()

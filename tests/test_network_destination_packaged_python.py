"""Decky-specific provenance tests for packaged Python modules."""

import unittest

import network_destination_filters as ndf


class PackagedPythonProvenanceTests(unittest.TestCase):
    def test_plugin_package_matching_zip_wrapper_is_runtime(self):
        self.assertEqual(
            ndf.classify_network_source(
                "SDH-Ludusavi/py_modules/sdh_ludusavi/updater_client.py"
            ),
            ("plugin_runtime", "high"),
        )

    def test_unrelated_py_modules_package_is_dependency(self):
        self.assertEqual(
            ndf.classify_network_source(
                "SDH-Ludusavi/py_modules/requests/api.py"
            ),
            ("dependency_or_vendored", "low"),
        )

    def test_dist_info_inside_py_modules_is_dependency(self):
        self.assertEqual(
            ndf.classify_network_source(
                "SDH-Ludusavi/py_modules/pyludusavi-0.3.0.dist-info/METADATA"
            ),
            ("dependency_or_vendored", "low"),
        )


if __name__ == "__main__":
    unittest.main()

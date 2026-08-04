"""Regression tests for precise network-destination extraction."""

import unittest

import audit_plugins as ap


class NetworkDestinationFilterTests(unittest.TestCase):
    def test_http_url_host_is_normalized_and_port_is_preserved(self):
        content = "fetch('https://user:pass@API.Example.COM:8443/data')"
        urls, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(
            urls,
            ["https://user:pass@API.Example.COM:8443/data"],
        )
        self.assertEqual(destinations, ["api.example.com:8443"])

    def test_url_ip_is_kept_without_duplicate_bare_host(self):
        content = "endpoint = 'http://127.0.0.1:8384/rest/system/status'"
        _, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(destinations, ["127.0.0.1:8384"])

    def test_contextual_raw_ipv4_is_kept(self):
        content = "server = '192.168.1.100'\n"
        _, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(destinations, ["192.168.1.100"])

    def test_dns_list_keeps_public_resolvers(self):
        content = 'DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]\n'
        _, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(destinations, ["1.1.1.1", "8.8.8.8"])

    def test_version_literals_are_not_network_destinations(self):
        content = (
            'version = "1.2.3.4"\n'
            'server_version = "2.3.4.5"\n'
            'dependency_version = "3.4.5.6"\n'
        )
        _, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(destinations, [])

    def test_invalid_leading_zero_pseudo_addresses_are_rejected(self):
        content = (
            "server = '011.031.025.058'\n"
            "address = '1.05.52.52'\n"
            "endpoint = '3.063.72.174'\n"
        )
        _, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(destinations, [])

    def test_out_of_range_pseudo_address_is_rejected(self):
        _, destinations = ap.extract_urls_and_domains(
            "server = '999.1.2.3'\n"
        )
        self.assertEqual(destinations, [])

    def test_context_free_numeric_sequences_are_ignored(self):
        content = (
            "const values = ['1.1.2.3', '2.3.3.5', '12.2.2.4'];\n"
            "const tuple = [23, 52, 9, 3];\n"
        )
        _, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(destinations, [])

    def test_giant_generated_line_does_not_promote_numeric_noise(self):
        content = (
            "const bundle='" + ("x" * 2500) + "1.2.3.4 server';"
        )
        _, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(destinations, [])

    def test_duplicate_urls_and_destinations_are_deduplicated(self):
        content = (
            "https://api.example.com/data\n"
            "https://api.example.com/data\n"
            "https://API.EXAMPLE.COM/other\n"
        )
        urls, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(
            urls,
            [
                "https://api.example.com/data",
                "https://API.EXAMPLE.COM/other",
            ],
        )
        self.assertEqual(destinations, ["api.example.com"])

    def test_invalid_url_port_is_ignored_without_crashing(self):
        urls, destinations = ap.extract_urls_and_domains(
            "https://example.com:99999/path"
        )

        self.assertEqual(urls, [])
        self.assertEqual(destinations, [])

    def test_websocket_destination_is_detected(self):
        urls, destinations = ap.extract_urls_and_domains(
            "socket = new WebSocket('wss://events.example.com/feed')"
        )

        self.assertEqual(urls, ["wss://events.example.com/feed"])
        self.assertEqual(destinations, ["events.example.com"])

    def test_single_label_placeholder_urls_are_rejected(self):
        content = (
            "http://bar/path\n"
            "https://error/failure\n"
            "http://myrepo/archive\n"
            "https://proxy/config\n"
            "http://rev/value\n"
            "https://xyz/test\n"
        )
        urls, destinations = ap.extract_urls_and_domains(content)

        self.assertEqual(urls, [])
        self.assertEqual(destinations, [])

    def test_localhost_url_and_port_are_preserved(self):
        urls, destinations = ap.extract_urls_and_domains(
            "server = 'http://LOCALHOST:8765/status'"
        )

        self.assertEqual(urls, ["http://LOCALHOST:8765/status"])
        self.assertEqual(destinations, ["localhost:8765"])


if __name__ == "__main__":
    unittest.main()

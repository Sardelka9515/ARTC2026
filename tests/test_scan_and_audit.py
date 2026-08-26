import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from modules.config_audit import _is_hidden_ssid, audit_target
from modules.scan import _parse_iw_scan


class IwScanParserTests(unittest.TestCase):
    def test_parses_transition_auth_and_keeps_pmf_required(self):
        result = _parse_iw_scan(
            """
BSS AA:BB:CC:11:22:33(on wlan0)
        SSID: ARTC-TBOX-Test
        signal: -42.50 dBm
        DS Parameter set: channel 6
        RSN:
            * Authentication suites: SAE PSK
            * Capabilities: MFP-required
            * Capabilities: MFP-capable
        WPS:
"""
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["bssid"], "aa:bb:cc:11:22:33")
        self.assertEqual(result[0]["encryption"], "WPA3-Transition")
        self.assertEqual(result[0]["pmf"], "required")
        self.assertTrue(result[0]["wps"])

    def test_distinguishes_enterprise_and_hidden_ssid(self):
        result = _parse_iw_scan(
            """
BSS aa:bb:cc:44:55:66(on wlan0)
        SSID:
        RSN:
            * Authentication suites: 802.1X/SHA-256
            * Capabilities: MFP-capable
"""
        )

        self.assertEqual(result[0]["ssid"], "<hidden>")
        self.assertEqual(result[0]["encryption"], "WPA2-Enterprise")
        self.assertEqual(result[0]["pmf"], "capable")
        self.assertFalse(any(key.startswith("_") for key in result[0]))

    def test_does_not_misclassify_legacy_wpa_psk_as_wpa2(self):
        result = _parse_iw_scan(
            """
BSS aa:bb:cc:77:88:99(on wlan0)
        SSID: Legacy
        WPA:
            * Authentication suites: PSK
"""
        )

        self.assertEqual(result[0]["encryption"], "WPA")


class ConfigAuditTests(unittest.TestCase):
    def test_hidden_ssid_variants(self):
        for value in (None, "", "<hidden>", "\x00\x00", r"\x00\x00"):
            with self.subTest(value=value):
                self.assertTrue(_is_hidden_ssid(value))
        self.assertFalse(_is_hidden_ssid("ARTC-TBOX-Test"))

    @patch("modules.config_audit.scan_networks")
    def test_enterprise_and_required_pmf_pass(self, scan_networks):
        scan_networks.return_value = [{
            "bssid": "aa:bb:cc:11:22:33",
            "ssid": "<hidden>",
            "encryption": "WPA2-Enterprise",
            "wps": False,
            "pmf": "required",
        }]

        report = audit_target("wlan0", "AA:BB:CC:11:22:33")
        statuses = {check["name"]: check["status"] for check in report["checks"]}

        self.assertEqual(statuses["Strong auth (WPA3 / 802.1X)"], "PASS")
        self.assertEqual(statuses["PMF (802.11w)"], "PASS")
        self.assertEqual(statuses["SSID broadcast policy"], "PASS")


if __name__ == "__main__":
    unittest.main()

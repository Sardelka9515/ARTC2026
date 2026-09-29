import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from modules.config_audit import _is_hidden_ssid, audit_target
from modules.scan import _parse_iw_scan, scan_networks, list_interfaces, interface_choices


class RealDiscoveryTests(unittest.TestCase):
    def test_empty_or_failed_scan_never_returns_demo_aps(self):
        for result in (Mock(stdout='', returncode=0), OSError('no adapter')):
            with patch('modules.scan.shutil.which', return_value='/usr/sbin/iw'), \
                 patch('modules.scan.subprocess.run') as run, \
                 patch('modules.scan._scapy_scan', return_value=[]):
                if isinstance(result, Exception):
                    run.side_effect = result
                else:
                    run.return_value = result
                self.assertEqual(scan_networks('wlan1'), [])

    def test_missing_hardware_never_creates_interfaces(self):
        with patch('modules.scan.subprocess.run', side_effect=OSError('missing iw')):
            self.assertEqual(list_interfaces(), [])

    def test_roles_pin_to_bench_interface_names(self):
        # Fixed 3-radio bench: recon and WIDS reuse wlan0, deauth uses wlan1.
        ifaces = ['wlan0', 'wlan1']
        with patch.object(Path, 'read_text', side_effect=OSError):
            self.assertEqual(interface_choices(ifaces, 'scan')['preferred'], 'wlan0')
            self.assertEqual(interface_choices(ifaces, 'wids')['preferred'], 'wlan0')
            self.assertEqual(interface_choices(ifaces, 'deauth')['preferred'], 'wlan1')
            # Pinned name missing → fall back to the first available interface.
            self.assertEqual(interface_choices(['wlanX'], 'deauth')['preferred'], 'wlanX')
            # No interfaces at all → no preferred choice.
            self.assertIsNone(interface_choices([], 'scan')['preferred'])

    def test_vendor_brand_labels_are_kept_for_display(self):
        def read(path):
            return 'PRODUCT=e8d/7961/100\n' if 'wlan0' in str(path) else 'PRODUCT=2357/120/200\n'
        with patch.object(Path, 'read_text', read):
            labels = interface_choices(['wlan0', 'wlan1'], 'scan')['labels']
        self.assertEqual(labels['wlan0'], 'wlan0 · MediaTek')
        self.assertEqual(labels['wlan1'], 'wlan1 · TP-Link')


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

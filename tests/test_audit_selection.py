import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from modules.config_audit import AUDIT_CHECKS, audit_target


class AuditSelectionTests(unittest.TestCase):
    @patch("modules.config_audit.scan_networks")
    def test_only_selected_checks_affect_report(self, scan):
        scan.return_value = [{"bssid": "aa:bb:cc:11:22:33", "wps": True,
                              "encryption": "OPEN", "pmf": "required"}]
        report = audit_target("wlan0", "aa:bb:cc:11:22:33", ["PMF (802.11w)"])
        self.assertEqual([check["name"] for check in report["checks"]], ["PMF (802.11w)"])
        self.assertEqual(report["summary"], "0 FAIL / 0 WARN / 1 checks")

    @patch("modules.config_audit.scan_networks")
    def test_omitted_selection_preserves_full_audit(self, scan):
        scan.return_value = [{"bssid": "aa:bb:cc:11:22:33"}]
        report = audit_target("wlan0", "aa:bb:cc:11:22:33")
        self.assertEqual({check["name"] for check in report["checks"]}, AUDIT_CHECKS)

    @patch("modules.config_audit.scan_networks")
    def test_empty_selection_does_not_run_checks(self, scan):
        scan.return_value = [{"bssid": "aa:bb:cc:11:22:33"}]
        self.assertEqual(audit_target("wlan0", "aa:bb:cc:11:22:33", [])['checks'], [])

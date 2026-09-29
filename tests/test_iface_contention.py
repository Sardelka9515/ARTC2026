import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import app


class InterfaceContentionTests(unittest.TestCase):
    """wlan0 is shared by recon (managed) and WIDS (monitor); the two must never
    hold the same adapter at once."""

    def setUp(self):
        app.app.config["TESTING"] = True
        self.client = app.app.test_client()
        app._iface_owner.clear()

    def tearDown(self):
        app._iface_owner.clear()

    def test_scan_refused_while_wids_holds_interface(self):
        app._claim_iface("wlan0", "wids")
        r = self.client.post("/api/scan", json={"interface": "wlan0"})
        self.assertEqual(r.status_code, 409)
        self.assertFalse(r.get_json()["ok"])
        # The WIDS reservation must survive the refused scan.
        self.assertEqual(app._iface_owner.get("wlan0"), "wids")

    def test_scan_releases_interface_when_done(self):
        with patch("app.scan_networks", return_value=[]):
            r = self.client.post("/api/scan", json={"interface": "wlan0"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("wlan0", app._iface_owner)

    def test_scan_releases_interface_even_on_error(self):
        with patch("app.scan_networks", side_effect=RuntimeError("boom")):
            r = self.client.post("/api/scan", json={"interface": "wlan0"})
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("wlan0", app._iface_owner)

    def test_wids_start_refused_during_scan(self):
        app._claim_iface("wlan0", "scan")
        r = self.client.post("/api/wids/start", json={"interface": "wlan0"})
        self.assertEqual(r.status_code, 409)
        # The scan reservation is untouched by the refused WIDS start.
        self.assertEqual(app._iface_owner.get("wlan0"), "scan")

    def test_failed_wids_start_does_not_release_a_running_wids(self):
        # WIDS already running on wlan0; a second start must not free the adapter.
        app._claim_iface("wlan0", "wids")
        with patch.object(app.wids, "start",
                          return_value={"ok": False, "error": "WIDS is already running",
                                        "status": {}}):
            r = self.client.post("/api/wids/start", json={"interface": "wlan0"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(app._iface_owner.get("wlan0"), "wids")

    def test_different_interfaces_do_not_contend(self):
        # WIDS on wlan0 must not block a scan on wlan1 (the deauth radio, etc.).
        app._claim_iface("wlan0", "wids")
        with patch("app.scan_networks", return_value=[]):
            r = self.client.post("/api/scan", json={"interface": "wlan1"})
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()

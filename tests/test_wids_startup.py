import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from modules.wids import WIDSMonitor


class SocketStub:
    def __init__(self):
        self.events = []

    def emit(self, name, payload, namespace=None):
        self.events.append((name, payload, namespace))


class LoggerStub:
    def __init__(self):
        self.messages = []

    def info(self, category, message):
        self.messages.append(("info", category, message))

    def error(self, category, message):
        self.messages.append(("error", category, message))


class WidsStartupTests(unittest.TestCase):
    def setUp(self):
        self.monitor = WIDSMonitor(SocketStub(), LoggerStub())

    @patch.object(WIDSMonitor, "_prepare_interface", side_effect=RuntimeError("monitor mode denied"))
    def test_start_failure_is_reported_and_does_not_run(self, _prepare):
        result = self.monitor.start("wlan9", channel=6)

        self.assertFalse(result["ok"])
        self.assertFalse(self.monitor._running)
        self.assertEqual(result["status"]["state"], "error")
        self.assertIn("monitor mode denied", result["error"])
        self.assertIsNone(self.monitor._thread)

    @patch.object(WIDSMonitor, "_scapy_loop", side_effect=RuntimeError("capture lost"))
    def test_runtime_capture_failure_becomes_error_not_fake_events(self, _capture):
        self.monitor._running = True
        self.monitor._loop()

        status = self.monitor.status()
        self.assertFalse(self.monitor._running)
        self.assertEqual(status["state"], "error")
        self.assertIn("capture lost", status["error"])

    @patch.object(WIDSMonitor, "list_interfaces", return_value=["wlan0"])
    @patch("modules.wids.shutil.which", return_value="/usr/sbin/tool")
    def test_prepare_changes_selected_interface_to_monitor_and_locks_channel(self, _which, _list):
        responses = iter([
            "Interface wlan0\n\ttype managed\n\tchannel 1\n",
            "", "", "", "",
            "Interface wlan0\n\ttype monitor\n\tchannel 6 (2437 MHz)\n",
        ])
        commands = []

        def run(command):
            commands.append(command)
            return next(responses)

        with patch.object(WIDSMonitor, "_run_command", side_effect=run):
            channel = self.monitor._prepare_interface("wlan0", 6)

        self.assertEqual(channel, 6)
        self.assertIn(["iw", "dev", "wlan0", "set", "type", "monitor"], commands)
        self.assertIn(["iw", "dev", "wlan0", "set", "channel", "6"], commands)

    @patch("modules.wids.subprocess.run")
    @patch("modules.wids.shutil.which", return_value="/usr/sbin/iw")
    def test_interface_list_contains_only_iw_results(self, _which, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "phy#0\n\tInterface wlan0\nphy#1\n\tInterface wlan1mon\n"

        self.assertEqual(WIDSMonitor.list_interfaces(), ["wlan0", "wlan1mon"])


if __name__ == "__main__":
    unittest.main()

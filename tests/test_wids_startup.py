import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from modules.wids import FrameObservation, MacSpoofDetector, WIDSMonitor


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


class SequenceDetectorTests(unittest.TestCase):
    BSSID = "54:AF:97:62:DA:6A"

    @staticmethod
    def beacon(seq, retry=False, transmitter=None):
        return FrameObservation(
            fc_type=0, subtype=8, bssid=SequenceDetectorTests.BSSID,
            transmitter=transmitter or SequenceDetectorTests.BSSID,
            seq=seq, retry=retry,
        )

    def setUp(self):
        self.detector = MacSpoofDetector()

    def test_large_forward_gap_is_not_misread_as_negative_modular_jump(self):
        self.assertEqual(self.detector.feed(self.beacon(475), {}), [])
        self.assertEqual(self.detector.feed(self.beacon(3926), {}), [])

    def test_data_frames_are_not_used_for_ap_sequence_detection(self):
        first = FrameObservation(fc_type=2, bssid=self.BSSID, transmitter="AA:00:00:00:00:01", seq=2000)
        second = FrameObservation(fc_type=2, bssid=self.BSSID, transmitter="AA:00:00:00:00:02", seq=10)
        self.assertEqual(self.detector.feed(first, {}), [])
        self.assertEqual(self.detector.feed(second, {}), [])
        self.assertEqual(self.detector.last_seq, {})

    def test_normal_rollover_is_ignored(self):
        self.detector.feed(self.beacon(4000), {})
        self.assertEqual(self.detector.feed(self.beacon(20), {}), [])

    def test_single_backward_jump_is_not_an_alert(self):
        self.detector.feed(self.beacon(2000), {})
        self.assertEqual(self.detector.feed(self.beacon(1000), {}), [])

    def test_three_backward_jumps_emit_one_medium_alert(self):
        events = []
        for seq in (3000, 2000, 3100, 1900, 3200, 1800):
            events.extend(self.detector.feed(self.beacon(seq), {}))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "seq_anomaly")
        self.assertEqual(events[0]["severity"], "medium")
        self.assertEqual(events[0]["evidence"]["count"], 3)

    def test_retry_beacon_is_ignored(self):
        self.detector.feed(self.beacon(2000), {})
        self.assertEqual(self.detector.feed(self.beacon(1000, retry=True), {}), [])


if __name__ == "__main__":
    unittest.main()

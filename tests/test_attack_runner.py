import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from modules.attack_runner import AttackJob, AttackRunner


class AttackRunnerTests(unittest.TestCase):
    def setUp(self):
        self.socket = Mock()
        self.runner = AttackRunner(self.socket, Mock())
        self.job = AttackJob("test-job", "deauth",
                             "python3 scripts/deauth_test.py --interface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6 --count 1")

    @patch("modules.attack_runner.shutil.which", return_value="/usr/bin/aireplay-ng")
    @patch("modules.attack_runner.subprocess.Popen")
    def test_deauth_launches_streams_output_and_finishes(self, popen, _which):
        popen.return_value.stdout = iter(["test output\n"])
        popen.return_value.returncode = 0

        self.runner._run(self.job)

        self.assertEqual(popen.call_args.args[0], [
            "python3", "scripts/deauth_test.py", "--interface", "wlan0", "--bssid",
            "AA:BB:CC:DD:EE:FF", "--channel", "6", "--count", "1",
        ])
        popen.return_value.wait.assert_called_once()
        self.socket.emit.assert_any_call(
            "job_output", {"job_id": "test-job", "line": "test output"}, namespace="/")
        updates = [call.args[1] for call in self.socket.emit.call_args_list
                   if call.args[0] == "job_update"]
        self.assertEqual([u["status"] for u in updates], ["running", "finished"])
        self.assertEqual(self.job.return_code, 0)
        self.assertIsNotNone(self.job.ended_at)

    @patch("modules.attack_runner.shutil.which", return_value="/usr/bin/aireplay-ng")
    @patch("modules.attack_runner.subprocess.Popen", side_effect=PermissionError("denied"))
    def test_launch_failure_reports_error_instead_of_remaining_running(self, _popen, _which):
        self.runner._run(self.job)

        self.assertEqual(self.job.status, "error")
        self.assertIsNotNone(self.job.ended_at)
        self.socket.emit.assert_any_call(
            "job_output", {"job_id": "test-job", "line": "[runner-error] denied"}, namespace="/")
        self.socket.emit.assert_any_call("job_update", self.job.to_dict(), namespace="/")

    @patch.object(Path, "exists", return_value=True)
    def test_deauth_command_is_finite_and_rejects_injected_values(self, _exists):
        command = self.runner._local_command("deauth", {
            "interface": "wlan1", "bssid": "aa:bb:cc:dd:ee:ff",
            "channel": 6, "count": 50,
        })
        self.assertIn("scripts/deauth_test.py", command)
        for bad in ({"interface": "wlan1 --help"}, {"count": 10000}, {"channel": 0}):
            values = {"interface": "wlan1", "bssid": "aa:bb:cc:dd:ee:ff",
                      "channel": 6, "count": 50, **bad}
            with self.assertRaises(ValueError):
                self.runner._local_command("deauth", values)


if __name__ == "__main__":
    unittest.main()

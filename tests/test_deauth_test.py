import sys
import io
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deauth_test


class DeauthScriptTests(unittest.TestCase):
    @patch.object(deauth_test.subprocess, "Popen")
    @patch.object(deauth_test, "set_type")
    @patch.object(deauth_test, "run")
    @patch.object(deauth_test, "interface_type", return_value="managed")
    def test_sets_monitor_channel_and_restores_interface(self, _type, run, set_type, popen):
        proc = Mock()
        proc.stdout = iter(["sent\n"])
        proc.wait.return_value = 0
        proc.poll.return_value = 0
        popen.return_value = proc

        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(deauth_test.execute("wlan1", "aa:bb:cc:dd:ee:ff", 6, 50), 0)

        self.assertEqual(set_type.call_args_list, [call("wlan1", "monitor"), call("wlan1", "managed")])
        run.assert_called_with(["iw", "dev", "wlan1", "set", "channel", "6"])
        self.assertEqual(popen.call_args.args[0],
                         ["aireplay-ng", "--deauth", "50", "-a",
                          "aa:bb:cc:dd:ee:ff", "wlan1"])


if __name__ == "__main__":
    unittest.main()

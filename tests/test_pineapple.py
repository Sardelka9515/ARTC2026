import copy
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'backend'))
import pineapple as p
from modules.attack_runner import AttackRunner


def config():
    value = json.loads((ROOT / 'configs/pineapple.example.json').read_text())
    value['enabled'] = True
    value['target'].update(bssid='02:11:22:33:44:55', ssid='ARTC-LAB', client_mac='02:11:22:33:44:66')
    return value


class FakeClient:
    base = 'http://172.16.42.1:1471'

    def __init__(self):
        self.values = {key: False for key in p.FIELDS}
        self.values.update(ap_channel='1', beacon_interval='normal', beacon_response_interval='normal',
                           pineap_mac='02:11:22:33:44:77', target_mac='ff:ff:ff:ff:ff:ff')
        self.pool = ''
        self.calls = []

    def settings(self):
        return copy.deepcopy(self.values)

    def request(self, method, path, body=None):
        return self.pool

    def mutate(self, method, path, body):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == p.SETTINGS:
            self.values = copy.deepcopy(body)
        elif path == p.SSID:
            self.pool = body['ssid'] if method == 'PUT' else ''


class PineappleTests(unittest.TestCase):
    def test_ssid_pool_accepts_firmware_response_variants(self):
        for value in ('one\ntwo', ['one', 'two'], {'ssids': ['one', 'two']},
                      {'pool': 'one\ntwo'}):
            self.assertEqual(p.parse_ssid_pool(value), ['one', 'two'])
        self.assertEqual(p.parse_ssid_pool(None), [])
        with self.assertRaises(p.PineappleError):
            p.parse_ssid_pool({'unexpected': True})

    def test_wrapped_settings_round_trip_preserves_mode_and_extra_fields(self):
        values = FakeClient().values
        values['autostartPineAP'] = values.pop('AutoStart')
        values.update(armedPineAP=False, broadcast_ssid_pool_random=False)
        wire = {'mode': 'passive', 'settings': values}
        client = p.Client(config())
        client.request = Mock(return_value=wire)
        normalized = client.settings()
        self.assertEqual(normalized['_mode'], 'passive')
        self.assertIs(normalized['AutoStart'], False)
        client.request.return_value = {'success': True}
        client.mutate('PUT', p.SETTINGS, normalized)
        expected = copy.deepcopy(wire)
        expected['settings'].pop('evil_ap_handshakes', None)
        client.request.assert_called_with('PUT', p.SETTINGS, expected)
        self.assertIn('_mode', normalized)

    def test_wrapped_firmware_base64_encodes_ssid_mutations(self):
        client = p.Client(config())
        client.wrapped_settings = True
        client.request = Mock(return_value={'success': True})
        client.mutate('PUT', p.SSID, {'ssid': 'T-BOX'})
        client.request.assert_called_once_with('PUT', p.SSID, {'ssid': 'VC1CT1g='})

    def test_wrapped_firmware_uses_wpa_twin_and_restores(self):
        class WpaClient:
            base = 'http://172.16.42.1:1471'
            def __init__(self):
                self.open = {'ssid': 'Pineapple', 'country': 'US', 'channel': 8, 'hidden': False}
                self.wpa = {'ssid': 'old', 'bssid': '02:11:22:33:44:77', 'auth': 'psk2+ccmp',
                            'password': 'old-password', 'hidden': False, 'disabled': True,
                            'capture_handshakes': True}
            def request(self, method, path, body=None):
                return copy.deepcopy(self.open if path == p.OPEN_AP else self.wpa)
            def mutate(self, method, path, body):
                value = copy.deepcopy(body)
                value.pop('confirm_password', None)
                if path == p.OPEN_AP:
                    self.open = value
                else:
                    self.wpa = value
        client = WpaClient()
        original_open, original_wpa = copy.deepcopy(client.open), copy.deepcopy(client.wpa)
        def inspect(_):
            self.assertEqual(client.open['channel'], 6)
            self.assertEqual(client.wpa['ssid'], 'ARTC-LAB')
            self.assertEqual(client.wpa['bssid'], '02:11:22:33:44:55'.upper())
            self.assertFalse(client.wpa['capture_handshakes'])
        with tempfile.TemporaryDirectory() as folder, patch('sys.stdout', new=io.StringIO()):
            p.run_evil_twin_wpa(client, config(), Path(folder) / 'recovery.json', sleep=inspect)
        self.assertEqual(client.open, original_open)
        self.assertEqual(client.wpa, original_wpa)

    def test_settings_rejects_invalid_wrapped_values(self):
        values = FakeClient().values
        values['autostartPineAP'] = 'false'
        values.pop('AutoStart')
        for wire in ({'mode': 'advanced', 'settings': values},
                     {'settings': values}, {'mode': 'advanced', 'settings': []}):
            client = p.Client(config())
            client.request = Mock(return_value=wire)
            with self.assertRaises(p.PineappleError):
                client.settings()

    def test_wrapped_evil_twin_restores_original_mode(self):
        client = FakeClient()
        client.values.update(_mode='passive', armedPineAP=False)
        original = copy.deepcopy(client.values)
        def during_test(_):
            self.assertEqual(client.values['_mode'], 'advanced')
        with tempfile.TemporaryDirectory() as folder, patch('sys.stdout', new=io.StringIO()):
            p.run_evil_twin(client, config(), Path(folder) / 'recovery.json', sleep=during_test)
        self.assertEqual(client.values, original)

    def test_evil_twin_clones_target_mac_channel_and_ssid(self):
        client = FakeClient()
        during = {}
        def inspect(_):
            during.update(client.values)
            self.assertEqual(client.pool, config()['target']['ssid'])
        with tempfile.TemporaryDirectory() as folder, patch('sys.stdout', new=io.StringIO()):
            p.run_evil_twin(client, config(), Path(folder) / 'recovery.json', sleep=inspect)
        self.assertEqual(during['pineap_mac'], config()['target']['bssid'].upper())
        self.assertEqual(during['ap_channel'], str(config()['target']['channel']))

    def test_evil_twin_rejects_a_different_clone_mac(self):
        value = config()
        value['evil_twin']['bssid'] = '02:11:22:33:44:99'
        with self.assertRaises(p.PineappleError):
            p.validate(value, 'evil-twin')

    @patch.object(Path, 'exists', return_value=True)
    @patch.object(p.subprocess, 'run')
    def test_management_route_must_use_selected_interface(self, run, _exists):
        run.return_value = Mock(returncode=0, stdout='172.16.42.1 dev eth1 src 172.16.42.42\n')
        p.verify_management_route('http://172.16.42.1:1471', 'eth1')
        with self.assertRaises(p.PineappleError):
            p.verify_management_route('http://172.16.42.1:1471', 'enp0s3')

    def test_plan_never_connects_with_unconfigured_example(self):
        with patch.object(p, 'Client') as client, patch('sys.stdout', new=io.StringIO()):
            self.assertEqual(p.main(['plan', '--config', str(ROOT / 'configs/pineapple.example.json')]), 0)
            client.assert_not_called()

    def test_execute_requires_enabled_config(self):
        with patch.object(p, 'Client') as client:
            with self.assertRaises(p.PineappleError):
                p.main(['deauth', '--execute', '--config', str(ROOT / 'configs/pineapple.example.json')])
            client.assert_not_called()

    def test_target_and_channel_must_match(self):
        for kwargs in ({'bssid': '02:00:00:00:00:99'}, {'channel': 11}):
            with self.assertRaises(p.PineappleError):
                p.validate(config(), 'deauth', **kwargs)

    def test_broadcast_client_and_unbounded_bursts_rejected(self):
        c = config()
        c['target']['client_mac'] = 'ff:ff:ff:ff:ff:ff'
        with self.assertRaises(p.PineappleError):
            p.validate(c, 'deauth')
        c = config()
        c['deauth']['bursts'] = 10000
        with self.assertRaises(p.PineappleError):
            p.validate(c, 'deauth')

    def test_deauth_is_finite_and_client_scoped(self):
        client = FakeClient()
        with patch('sys.stdout', new=io.StringIO()):
            p.run_deauth(client, config(), sleep=lambda _: None)
        self.assertEqual(len(client.calls), 5)
        self.assertTrue(all(path.endswith('/deauth/client') for _, path, _ in client.calls))
        self.assertTrue(all(body['mac'] == config()['target']['client_mac'] for _, _, body in client.calls))

    def test_evil_twin_restores_even_when_interrupted(self):
        for interrupt in (False, True):
            client = FakeClient()
            original = client.settings()
            def sleep(_):
                self.assertTrue(client.values['broadcast_ssid_pool'])
                self.assertFalse(client.values['karma'])
                if interrupt:
                    raise KeyboardInterrupt
            with tempfile.TemporaryDirectory() as folder, patch('sys.stdout', new=io.StringIO()):
                snapshot = Path(folder) / 'recovery.json'
                if interrupt:
                    with self.assertRaises(KeyboardInterrupt):
                        p.run_evil_twin(client, config(), snapshot, sleep=sleep)
                else:
                    p.run_evil_twin(client, config(), snapshot, sleep=sleep)
                self.assertEqual(client.settings(), original)
                self.assertEqual(client.pool, '')
                self.assertFalse(snapshot.exists())

    def test_active_pineap_and_existing_pool_are_restored(self):
        client = FakeClient()
        client.values.update(enablePineAP=True, AutoStart=True)
        client.pool = 'unrelated-network'
        original = client.settings()
        with tempfile.TemporaryDirectory() as folder, patch('sys.stdout', new=io.StringIO()):
            p.run_evil_twin(client, config(), Path(folder) / 'recovery.json', sleep=lambda _: None)
        self.assertEqual(client.settings(), original)
        self.assertEqual(client.pool, 'unrelated-network')

    def test_restore_failure_keeps_recovery(self):
        client = FakeClient()
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / 'recovery.json'
            def fail(_):
                client.mutate = Mock(side_effect=p.PineappleError('disconnected'))
            with self.assertRaises(p.PineappleError):
                p.run_evil_twin(client, config(), snapshot, sleep=fail)
            self.assertTrue(snapshot.exists())
            self.assertFalse('password' in snapshot.read_text())

    def test_api_failure_and_invalid_json_are_errors(self):
        for raw in (b'{"success":false}', b'{"error":"invalid"}', b'<html>login</html>'):
            client = p.Client(config())
            response = Mock()
            response.read.return_value = raw
            context = Mock()
            context.__enter__ = Mock(return_value=response)
            context.__exit__ = Mock(return_value=False)
            client.opener = Mock()
            client.opener.open.return_value = context
            with self.assertRaises(p.PineappleError):
                client.mutate('PUT', p.SETTINGS, {})

    def test_login_rejection_explains_credentials_without_exposing_password(self):
        for status in (400, 401):
            client = p.Client(config())
            client.opener = Mock()
            client.opener.open.side_effect = p.HTTPError(
                client.base + '/api/login', status, 'rejected', {}, None)
            with patch.dict(os.environ, {'PINEAPPLE_PASSWORD': 'test-secret'}):
                with self.assertRaises(p.PineappleError) as error:
                    client.login()
            self.assertIn('裝置拒絕帳號或密碼', str(error.exception))
            self.assertNotIn('test-secret', str(error.exception))
            request = client.opener.open.call_args.args[0]
            self.assertEqual(json.loads(request.data),
                             {'username': 'root', 'password': 'test-secret'})

    def test_runner_uses_server_config_and_quoted_argv(self):
        with tempfile.TemporaryDirectory(prefix='pineapple test ') as folder:
            cfg = Path(folder) / 'device.json'
            cfg.write_text(json.dumps(config()))
            runner = AttackRunner(Mock(), Mock())
            with patch.dict(os.environ, {'PINEAPPLE_CONFIG': str(cfg)}), patch('modules.attack_runner.threading.Thread'):
                job = runner.start('test', 'rogue_ap', {'engine': 'pineapple', 'bssid': config()['target']['bssid'],
                                                       'channel': 6, 'config_path': '/untrusted/browser/path'})
            argv = shlex.split(job.cmd)
            self.assertIn(str(cfg), argv)
            self.assertIn('evil-twin', argv)
            self.assertNotIn('/untrusted/browser/path', argv)
            self.assertNotIn('hostapd', argv)

    def test_recovery_refuses_different_device(self):
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / 'recovery.json'
            p.save_snapshot(snapshot, {'base_url': 'http://other:1471'})
            client = FakeClient()
            with self.assertRaises(p.PineappleError):
                p.restore(client, snapshot)
            self.assertEqual(client.calls, [])

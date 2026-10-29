#!/usr/bin/env python3
"""WiFi Pineapple Mark VII lab controller. Default invocation never transmits.

Uses the documented MK7 REST API, no extra Python dependencies. Configuration
and pending recovery state are server-side, never supplied by browser clients.
"""
import argparse
import base64
import copy
import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs/pineapple.local.json"
SETTINGS = "/api/pineap/settings"
SSID = "/api/pineap/ssids/ssid"
OPEN_AP = "/api/settings/networking/ap/open"
WPA_AP = "/api/settings/networking/ap/wpa"
FIELDS = {"enablePineAP", "AutoStart", "ap_channel", "beacon_interval",
          "beacon_response_interval", "beacon_responses", "broadcast_ssid_pool",
          "capture_ssids", "connect_notifications", "disconnect_notifications",
          "karma", "logging", "pineap_mac", "target_mac"}
WRITABLE_FIELDS = FIELDS | {"armedPineAP", "broadcast_ssid_pool_random"}
# The MK7 Evil WPA hostapd restart varied from 5–25 seconds on the lab device.
EVIL_TWIN_WARMUP_SECONDS = 30


class PineappleError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PineappleError("裝置要求重新導向；請確認 base_url，未轉送登入資料。")


def mac(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        raise PineappleError("請填寫有效的 BSSID / client_mac。")
    if int(value[:2], 16) & 1 or value.lower() == "00:00:00:00:00:00":
        raise PineappleError("BSSID / client_mac 必須為單播位址。")
    return value.lower()


def bounded(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise PineappleError(f"{name} 必須介於 {low} 與 {high}。")
    return value


def validate(config, scenario, bssid=None, channel=None, ssid=None):
    target = config.get("target", {})
    target_mac = mac(bssid)
    bounded(channel, 1, 14, "channel（此設定限 2.4 GHz）")
    if type(channel) is not int:
        raise PineappleError("頻道必須為整數。")
    if scenario == "deauth":
        mac(target.get("client_mac"))
        cfg = config.get("deauth", {})
        for key, low, high in (("bursts", 1, 10), ("multiplier", 1, 5)):
            bounded(cfg.get(key), low, high, key)
            if type(cfg[key]) is not int:
                raise PineappleError(f"{key} 必須為整數。")
        bounded(cfg.get("interval_seconds"), 0.5, 3, "interval_seconds")
    elif scenario == "evil-twin":
        if not isinstance(ssid, str) or not 1 <= len(ssid.encode()) <= 32 or any(c in ssid for c in '\r\n\x00'):
            raise PineappleError("請填寫 1–32 bytes 的單一測試 SSID。")
        evil = config.get("evil_twin", {})
        bounded(evil.get("duration_seconds"), 1, 30, "duration_seconds")
    return target_mac, ssid, channel


def verify_management_route(base_url, interface):
    """Refuse to send credentials unless the Pineapple address routes via the selected link."""
    if not interface:
        raise PineappleError("請選擇 Pineapple 管理介面（例如 eth1）。")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface) or not (Path("/sys/class/net") / interface).exists():
        raise PineappleError(f"找不到 Pineapple 管理介面：{interface}")
    host = urlparse(base_url).hostname
    if not host:
        raise PineappleError("base_url 缺少有效的 Pineapple 主機位址。")
    try:
        result = subprocess.run(["ip", "route", "get", host], capture_output=True,
                                text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PineappleError("無法檢查 Pineapple 管理路由；需要 iproute2。") from exc
    if result.returncode != 0 or re.search(rf"\bdev\s+{re.escape(interface)}\b", result.stdout) is None:
        raise PineappleError(f"{host} 未經所選介面 {interface} 路由；未傳送登入資料。")


class Client:
    def __init__(self, config):
        self.base = config.get("base_url", "").rstrip("/")
        url = urlparse(self.base)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
            raise PineappleError("base_url 應為 http(s)://裝置位址:連接埠。")
        self.timeout = bounded(config.get("request_timeout", 5), 1, 10, "request_timeout")
        self.token = None
        self.wrapped_settings = False
        # Do not send local device credentials through environment HTTP proxies.
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.config = config

    def request(self, method, path, body=None):
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            with self.opener.open(Request(self.base + path, data=data, headers=headers, method=method), timeout=self.timeout) as response:
                raw = response.read().decode()
        except HTTPError as exc:
            if path == "/api/login" and exc.code in (400, 401):
                raise PineappleError(
                    f"登入失敗（HTTP {exc.code}）：裝置拒絕帳號或密碼。"
                    "請先確認可用相同帳密登入管理頁；若環境變數保存舊密碼，"
                    "請清除 password_env 指定的變數後重新執行 check，在終端輸入密碼。"
                ) from None
            raise PineappleError(f"{method} {path}: HTTP {exc.code}；請確認韌體與登入設定。") from None
        except (URLError, TimeoutError, OSError):
            raise PineappleError(f"{method} {path}: 連線失敗或逾時，請檢查 USB 網路。") from None
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            if path == "/api/pineap/ssids" and method == "GET":
                return raw
            raise PineappleError(f"{path}: 非預期 JSON 回應，請確認韌體 API。") from None
        if isinstance(result, dict) and (result.get("error") or result.get("success") is False):
            raise PineappleError(f"{path}: 裝置回報失敗，請查看 Pineapple 管理頁。")
        return result

    def mutate(self, method, path, body):
        if path == SETTINGS and method == "PUT" and "_mode" in body:
            self.wrapped_settings = True
            body = copy.deepcopy(body)
            mode = body.pop("_mode")
            body["autostartPineAP"] = body.pop("AutoStart")
            body = {key: value for key, value in body.items()
                    if key in (WRITABLE_FIELDS - {"AutoStart"}) | {"autostartPineAP"}}
            body = {"mode": mode, "settings": body}
        elif path == SSID and self.wrapped_settings:
            body = copy.deepcopy(body)
            body["ssid"] = base64.b64encode(body["ssid"].encode()).decode()
        result = self.request(method, path, body)
        if not isinstance(result, dict) or result.get("success") is not True:
            raise PineappleError(f"{path}: 缺少 success=true，無法確認操作成功。")

    def login(self):
        password = os.environ.get(self.config.get("password_env", "PINEAPPLE_PASSWORD"))
        if not password and sys.stdin.isatty():
            password = getpass.getpass("Pineapple 密碼：")
        if not password:
            raise PineappleError("請設定 password_env 指定的環境變數，或從互動終端輸入密碼。")
        result = self.request("POST", "/api/login", {"username": self.config.get("username", "root"), "password": password})
        if not isinstance(result, dict) or not isinstance(result.get("token"), str) or not result["token"]:
            raise PineappleError("登入回應未包含有效 token。")
        self.token = result["token"]

    def settings(self):
        settings = self.request("GET", SETTINGS)
        # Newer firmware wraps settings and renames AutoStart. Keep the mode
        # and all additional settings so a recovery can restore them exactly.
        if isinstance(settings, dict) and "settings" in settings:
            self.wrapped_settings = True
            mode, values = settings.get("mode"), settings["settings"]
            if not isinstance(mode, str) or not mode or not isinstance(values, dict):
                raise PineappleError("PineAP settings 包裝格式不符，未變更裝置。")
            if "AutoStart" in values or "_mode" in values or "autostartPineAP" not in values:
                raise PineappleError("PineAP settings 自動啟動欄位格式不符，未變更裝置。")
            settings = copy.deepcopy(values)
            settings["AutoStart"] = settings.pop("autostartPineAP")
            settings["_mode"] = mode
        if not isinstance(settings, dict) or not FIELDS.issubset(settings):
            raise PineappleError("PineAP settings 與官方 API 格式不符；保留現況，需核對實機韌體。")
        for key in ("enablePineAP", "AutoStart", "beacon_responses", "broadcast_ssid_pool", "capture_ssids", "karma", "logging"):
            if type(settings[key]) is not bool:
                raise PineappleError(f"PineAP {key} 格式不符，未變更裝置。")
        return copy.deepcopy(settings)


def save_snapshot(path, snapshot):
    # Create before any remote write; never overwrite an unfinished recovery.
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(snapshot, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def parse_ssid_pool(value):
    """Normalize documented text and newer firmware's JSON-wrapped pool."""
    if value is None:
        return []
    if isinstance(value, str):
        return value.splitlines()
    if isinstance(value, list) and all(isinstance(name, str) for name in value):
        return value
    if isinstance(value, dict):
        for key in ("ssids", "pool"):
            if key in value:
                return parse_ssid_pool(value[key])
    raise PineappleError(f"SSID pool 格式不符（{type(value).__name__}），未變更裝置。")


def restore(client, path, sleep=time.sleep):
    snapshot = json.loads(path.read_text())
    if snapshot.get("base_url") != client.base:
        raise PineappleError("復原檔的裝置位址不符。")
    if snapshot.get("strategy") == "wpa":
        original_wpa = copy.deepcopy(snapshot["wpa_ap"])
        if "password" in original_wpa:
            original_wpa["confirm_password"] = original_wpa["password"]
        client.mutate("PUT", OPEN_AP, snapshot["open_ap"])
        client.mutate("PUT", WPA_AP, original_wpa)
        current_open = client.request("GET", OPEN_AP)
        current_wpa = client.request("GET", WPA_AP)
        checked_wpa = ("ssid", "bssid", "auth", "hidden", "disabled", "enabled",
                       "capture_handshakes")
        if (not isinstance(current_open, dict) or not isinstance(current_wpa, dict)
                or int(current_open.get("channel", 0)) != int(snapshot["open_ap"].get("channel", 0))
                or any(key in snapshot["wpa_ap"] and current_wpa.get(key) != snapshot["wpa_ap"].get(key)
                       for key in checked_wpa)):
            raise PineappleError("裝置尚未還原 Evil WPA/Open AP 設定，保留復原檔。")
        path.unlink()
        print("[restore] Evil WPA/Open AP 設定已還原。", flush=True)
        return
    # Stop transmission while restoring the exact pre-test SSID pool.
    quiet = copy.deepcopy(snapshot["settings"])
    quiet.update(enablePineAP=False, AutoStart=False, armedPineAP=False,
                 broadcast_ssid_pool_random=False)
    client.mutate("PUT", SETTINGS, quiet)
    current = parse_ssid_pool(client.request("GET", "/api/pineap/ssids"))
    original = snapshot.get("ssids", [])  # Old recovery files assumed an empty pool.
    for name in current:
        if name not in original:
            client.mutate("DELETE", SSID, {"ssid": name})
    for name in original:
        if name not in current:
            client.mutate("PUT", SSID, {"ssid": name})
    client.mutate("PUT", SETTINGS, snapshot["settings"])
    # PineAP start/stop is asynchronous; verify writable settings, not
    # read-only firmware fields such as handshake paths and counters.
    compared = FIELDS | ({"_mode"} if "_mode" in snapshot["settings"] else set())
    for attempt in range(6):
        current = client.settings()
        pool = parse_ssid_pool(client.request("GET", "/api/pineap/ssids"))
        changed = sorted(key for key in compared
                         if current.get(key) != snapshot["settings"].get(key))
        if not changed and pool == original:
            break
        if attempt < 5:
            sleep(1)
    else:
        detail = f"settings={','.join(changed) or 'ok'}, ssid_pool={'changed' if pool != original else 'ok'}"
        raise PineappleError(f"裝置尚未還原原始設定（{detail}），保留復原檔。")
    path.unlink()
    print("[restore] PineAP 設定已還原，本次測試 SSID 已移除。", flush=True)


def run_deauth(client, config, sleep=time.sleep):
    target, cfg = config["target"], config["deauth"]
    for i in range(cfg["bursts"]):
        client.mutate("POST", "/api/pineap/deauth/client", {
            "bssid": target["bssid"], "mac": target["client_mac"],
            "channel": target["channel"], "multiplier": cfg["multiplier"],
        })
        print(f"[deauth] 定向測試請求 {i + 1}/{cfg['bursts']} 已接受；實際效果請以 WIDS 與受測端驗證。", flush=True)
        if i + 1 < cfg["bursts"]:
            sleep(cfg["interval_seconds"])


def run_evil_twin(client, config, snapshot_path, sleep=time.sleep, wait=time.sleep):
    original = client.settings()
    if getattr(client, "wrapped_settings", False):
        return run_evil_twin_wpa(client, config, snapshot_path, sleep)
    pool = parse_ssid_pool(client.request("GET", "/api/pineap/ssids"))
    target, evil = config["target"], config["evil_twin"]
    original_ssids = pool
    save_snapshot(snapshot_path, {"base_url": client.base, "settings": original,
                                  "ssids": original_ssids})
    settings = copy.deepcopy(original)
    if "_mode" in settings:
        settings["_mode"] = "advanced"
    settings.update(enablePineAP=True, AutoStart=False, armedPineAP=False,
                    broadcast_ssid_pool_random=False, ap_channel=str(target["channel"]),
                    broadcast_ssid_pool=True, capture_ssids=False, beacon_responses=False,
                    karma=False, logging=True, pineap_mac=target["bssid"].upper(),
                    target_mac="FF:FF:FF:FF:FF:FF")
    try:
        quiet = copy.deepcopy(original)
        quiet.update(enablePineAP=False, AutoStart=False, armedPineAP=False,
                     broadcast_ssid_pool_random=False)
        if "_mode" in quiet:
            quiet["_mode"] = "advanced"
        client.mutate("PUT", SETTINGS, quiet)
        quiet_keys = {"enablePineAP", "AutoStart"}
        for attempt in range(6):
            current = client.settings()
            if all(current.get(key) == quiet.get(key) for key in quiet_keys):
                break
            if attempt < 5:
                wait(1)
        if target["ssid"] not in original_ssids:
            client.mutate("PUT", SSID, {"ssid": target["ssid"]})
        client.mutate("PUT", SETTINGS, settings)
        compared = FIELDS | ({"_mode"} if "_mode" in settings else set())
        compared |= {key for key in ("armedPineAP", "broadcast_ssid_pool_random") if key in original}
        for attempt in range(6):
            current = client.settings()
            changed = sorted(key for key in compared if current.get(key) != settings.get(key))
            if not changed:
                break
            if attempt < 5:
                wait(1)
        else:
            detail = ", ".join(f"{key}={settings.get(key)!r}->{current.get(key)!r}" for key in changed)
            raise PineappleError(f"裝置未套用預期 PineAP 設定（{detail}）；開始還原。")
        print(f"[evil-twin] 正以相同 SSID/BSSID/頻道廣播，{evil['duration_seconds']} 秒後還原；"
              "不啟用自動接入或憑證蒐集。", flush=True)
        sleep(evil["duration_seconds"])
    finally:
        try:
            restore(client, snapshot_path)
        except Exception as exc:
            raise PineappleError(f"還原未完成：{exc}。重新接線後執行 restore；復原檔：{snapshot_path}") from None


def run_evil_twin_wpa(client, config, snapshot_path, sleep=time.sleep, wait=time.sleep):
    original_open = client.request("GET", OPEN_AP)
    original_wpa = client.request("GET", WPA_AP)
    if not isinstance(original_open, dict) or not isinstance(original_wpa, dict):
        raise PineappleError("Open AP / Evil WPA 設定格式不符，未變更裝置。")
    if "channel" not in original_open or not ({"disabled", "enabled"} & set(original_wpa)):
        raise PineappleError("Open AP / Evil WPA 設定缺少必要欄位，未變更裝置。")
    save_snapshot(snapshot_path, {"base_url": client.base, "strategy": "wpa",
                                  "open_ap": original_open, "wpa_ap": original_wpa})
    target, evil = config["target"], config["evil_twin"]
    test_open = copy.deepcopy(original_open)
    test_open["channel"] = target["channel"]
    password = secrets.token_urlsafe(12)
    test_wpa = copy.deepcopy(original_wpa)
    test_wpa.update(ssid=target["ssid"], bssid=target["bssid"].upper(),
                    auth="psk2+ccmp", password=password, confirm_password=password,
                    hidden=False, capture_handshakes=False)
    if "disabled" in test_wpa:
        test_wpa["disabled"] = False
    if "enabled" in test_wpa:
        test_wpa["enabled"] = True
    try:
        client.mutate("PUT", OPEN_AP, test_open)
        client.mutate("PUT", WPA_AP, test_wpa)
        current_open = client.request("GET", OPEN_AP)
        current_wpa = client.request("GET", WPA_AP)
        if (not isinstance(current_open, dict) or not isinstance(current_wpa, dict)
                or int(current_open.get("channel", 0)) != target["channel"]
                or current_wpa.get("ssid") != target["ssid"]
                or str(current_wpa.get("bssid", "")).lower() != target["bssid"].lower()):
            raise PineappleError("裝置未套用預期 Evil WPA Twin 設定；開始還原。")
        print(f"[evil-twin] 設定已接受；等待無線服務啟動 {EVIL_TWIN_WARMUP_SECONDS} 秒。", flush=True)
        wait(EVIL_TWIN_WARMUP_SECONDS)
        print(f"[evil-twin] 開始 {evil['duration_seconds']} 秒 RF 觀測窗："
              f"SSID/BSSID 於頻道 {target['channel']}；已關閉握手擷取。", flush=True)
        sleep(evil["duration_seconds"])
    finally:
        try:
            restore(client, snapshot_path)
        except Exception as exc:
            raise PineappleError(f"還原未完成：{exc}。重新接線後執行 restore；復原檔：{snapshot_path}") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="WiFi Pineapple VII 測試控制器（預設僅離線預覽）")
    parser.add_argument("action", choices=("plan", "check", "deauth", "evil-twin", "restore"))
    parser.add_argument("--config", type=Path, default=Path(os.environ.get("PINEAPPLE_CONFIG", DEFAULT_CONFIG)))
    parser.add_argument("--execute", action="store_true", help="實際執行測試；仍需 enabled=true")
    parser.add_argument("--bssid", help="本次測試目標 BSSID")
    parser.add_argument("--ssid", help="本次測試目標 SSID")
    parser.add_argument("--channel", type=int, help="本次測試目標頻道")
    parser.add_argument("--management-interface", help="Pineapple USB 管理介面（例如 eth1）")
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text())
    if not isinstance(config, dict):
        raise PineappleError("設定檔需為 JSON object。")
    snapshot = args.config.resolve().with_suffix(".recovery.json")
    if args.action == "plan" or (args.action in ("deauth", "evil-twin") and not args.execute):
        print("[plan] 離線預覽：未連線、未傳送無線測試訊框。")
        print(json.dumps({"action": args.action, "base_url": config.get("base_url"), "target": config.get("target"),
                          "deauth": config.get("deauth"), "evil_twin": config.get("evil_twin"),
                          "enabled": config.get("enabled", False)}, ensure_ascii=False, indent=2))
        return 0
    if args.action in ("deauth", "evil-twin"):
        if config.get("enabled") is not True:
            raise PineappleError("裝置尚未啟用：完成設定後將 enabled 改為 true。")
        bssid, ssid, channel = validate(config, args.action, args.bssid, args.channel, args.ssid)
        config["target"].update(bssid=bssid, ssid=ssid, channel=channel)
    management_interface = args.management_interface or config.get("management_interface")
    verify_management_route(config.get("base_url", ""), management_interface)
    client = Client(config)
    # One local job per config; retain recovery state if a prior process was killed.
    with args.config.resolve().with_suffix(".lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PineappleError("此 Pineapple 設定已有工作執行中。") from None
        client.login()
        if snapshot.exists() and args.action not in ("restore", "check"):
            print("[recovery] 偵測到上次未完成復原，先還原裝置。", flush=True)
            restore(client, snapshot)
        if args.action == "check":
            settings = client.settings()
            print(json.dumps({"connected": True, "enablePineAP": settings["enablePineAP"],
                              "channel": settings["ap_channel"], "recovery_pending": snapshot.exists()}, ensure_ascii=False))
        elif args.action == "restore":
            if not snapshot.exists():
                raise PineappleError("沒有待還原的復原檔。")
            restore(client, snapshot)
        elif args.action == "deauth":
            run_deauth(client, config)
        else:
            run_evil_twin(client, config, snapshot)
    return 0


def interrupt(signum, frame):
    # Let the normal finally block restore device state before exiting.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("[stopped] 工作已中斷；已送出的 deauth 請求無法撤回。", file=sys.stderr)
        sys.exit(130)
    except (PineappleError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        sys.exit(1)

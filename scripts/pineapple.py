#!/usr/bin/env python3
"""WiFi Pineapple Mark VII lab controller. Default invocation never transmits.

Uses the documented MK7 REST API, no extra Python dependencies. Configuration
and pending recovery state are server-side, never supplied by browser clients.
"""
import argparse
import copy
import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs/pineapple.local.json"
SETTINGS = "/api/pineap/settings"
SSID = "/api/pineap/ssids/ssid"
FIELDS = {"enablePineAP", "AutoStart", "ap_channel", "beacon_interval",
          "beacon_response_interval", "beacon_responses", "broadcast_ssid_pool",
          "capture_ssids", "connect_notifications", "disconnect_notifications",
          "karma", "logging", "pineap_mac", "target_mac"}


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


def validate(config, scenario, bssid=None, channel=None):
    target = config.get("target", {})
    target_mac = mac(target.get("bssid"))
    if bssid is not None and mac(bssid) != target_mac:
        raise PineappleError("UI 選定 BSSID 與 Pineapple 設定中的測試目標不符。")
    configured_channel = target.get("channel")
    bounded(configured_channel, 1, 14, "target.channel（此設定限 2.4 GHz）")
    if type(configured_channel) is not int:
        raise PineappleError("頻道必須為整數。")
    if channel is not None and channel != configured_channel:
        raise PineappleError("UI 頻道與 Pineapple 測試設定不符。")
    if scenario == "deauth":
        mac(target.get("client_mac"))
        cfg = config.get("deauth", {})
        for key, low, high in (("bursts", 1, 10), ("multiplier", 1, 5)):
            bounded(cfg.get(key), low, high, key)
            if type(cfg[key]) is not int:
                raise PineappleError(f"{key} 必須為整數。")
        bounded(cfg.get("interval_seconds"), 0.5, 3, "interval_seconds")
    elif scenario == "evil-twin":
        ssid = target.get("ssid")
        if not isinstance(ssid, str) or not 1 <= len(ssid.encode()) <= 32 or any(c in ssid for c in '\r\n\x00'):
            raise PineappleError("請填寫 1–32 bytes 的單一測試 SSID。")
        evil = config.get("evil_twin", {})
        if mac(evil.get("bssid")) == target_mac:
            raise PineappleError("同名 SSID 偵測測試需使用不同的 Evil Twin BSSID。")
        bounded(evil.get("duration_seconds"), 1, 30, "duration_seconds")


class Client:
    def __init__(self, config):
        self.base = config.get("base_url", "").rstrip("/")
        url = urlparse(self.base)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
            raise PineappleError("base_url 應為 http(s)://裝置位址:連接埠。")
        self.timeout = bounded(config.get("request_timeout", 5), 1, 10, "request_timeout")
        self.token = None
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
            body = copy.deepcopy(body)
            mode = body.pop("_mode")
            body["autostartPineAP"] = body.pop("AutoStart")
            body = {"mode": mode, "settings": body}
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


def restore(client, path):
    snapshot = json.loads(path.read_text())
    if snapshot.get("base_url") != client.base:
        raise PineappleError("復原檔的裝置位址不符。")
    # Restore the original settings first, stopping our beacon transmission.
    client.mutate("PUT", SETTINGS, snapshot["settings"])
    pool = client.request("GET", "/api/pineap/ssids")
    if not isinstance(pool, str):
        raise PineappleError("SSID pool 格式不符，保留復原檔。")
    if snapshot["ssid"] in pool.splitlines():
        client.mutate("DELETE", SSID, {"ssid": snapshot["ssid"]})
    current = client.settings()
    if current != snapshot["settings"]:
        raise PineappleError("裝置尚未還原原始設定，保留復原檔。")
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


def run_evil_twin(client, config, snapshot_path, sleep=time.sleep):
    original = client.settings()
    if original["enablePineAP"] or original["AutoStart"]:
        raise PineappleError("請先在裝置管理頁停止 PineAP 並關閉自動啟動，再執行此獨立測試。")
    pool = client.request("GET", "/api/pineap/ssids")
    if not isinstance(pool, str) or pool.strip():
        raise PineappleError("此測試需要空的 SSID pool；請先自行備份並在管理頁清空。")
    target, evil = config["target"], config["evil_twin"]
    save_snapshot(snapshot_path, {"base_url": client.base, "settings": original, "ssid": target["ssid"]})
    settings = copy.deepcopy(original)
    if "_mode" in settings:
        settings["_mode"] = "advanced"
    settings.update(enablePineAP=True, AutoStart=False, ap_channel=str(target["channel"]),
                    broadcast_ssid_pool=True, capture_ssids=False, beacon_responses=False,
                    karma=False, logging=True, pineap_mac=evil["bssid"], target_mac="ff:ff:ff:ff:ff:ff")
    try:
        client.mutate("PUT", SSID, {"ssid": target["ssid"]})
        client.mutate("PUT", SETTINGS, settings)
        current = client.settings()
        if any(current[key] != value for key, value in settings.items()):
            raise PineappleError("裝置未套用預期 PineAP 設定；開始還原。")
        print(f"[evil-twin] 同名 SSID 廣播中，{evil['duration_seconds']} 秒後還原；不啟用自動接入。", flush=True)
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
    parser.add_argument("--bssid", help="驗證 UI 目標與設定一致")
    parser.add_argument("--channel", type=int, help="驗證 UI 頻道與設定一致")
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
        validate(config, args.action, args.bssid, args.channel)
    client = Client(config)
    # One local job per config; retain recovery state if a prior process was killed.
    with args.config.resolve().with_suffix(".lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PineappleError("此 Pineapple 設定已有工作執行中。") from None
        if snapshot.exists() and args.action not in ("restore", "check"):
            raise PineappleError("偵測到未完成復原，請先執行 restore。")
        client.login()
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

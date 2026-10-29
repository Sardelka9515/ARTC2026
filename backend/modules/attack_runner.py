"""
Attack runner — manages long-running attack/test subprocesses
and streams stdout/stderr lines to the frontend via Socket.IO.

Primary engine: wifite2  (https://github.com/kimocoder/wifite2)
Fallbacks: aireplay-ng, reaver, bully, hcxdumptool
Evil Twin (rogue_ap) runs on the WiFi Pineapple over eth1 (engine=pineapple),
not local hostapd.
"""
import json
import os
import shlex
import shutil
import threading
import subprocess
import time
import sys
import re
from pathlib import Path


# ---- scenario -> command template map --------------------------------------
# {placeholders} are filled from the `params` dict coming from the UI.
SCENARIOS = {
    # Full automated run via wifite2 against a specific BSSID.
    "wifite_auto": {
        "cmd": "wifite --bssid {bssid} --channel {channel} -i {interface} "
               "--kill --no-wps-pixie --dict {wordlist}",
        "desc": "wifite2 automated audit (WPA/WPA2/WPA3 handshake & crack)",
        "requires": ["bssid", "channel", "interface"],
        "defaults": {"wordlist": "/usr/share/wordlists/rockyou.txt"},
    },
    # Capture WPA handshake only (non-destructive recon).
    "handshake_cap": {
        "cmd": "wifite --bssid {bssid} --channel {channel} -i {interface} "
               "--no-crack --no-wps",
        "desc": "Capture 4-way handshake with wifite2 (no cracking)",
        "requires": ["bssid", "channel", "interface"],
        "defaults": {},
    },
    # 802.11 deauth attack to test PMF/802.11w effectiveness.
    "deauth": {
        "cmd": "python3 scripts/deauth_test.py --interface {interface} --bssid {bssid} --channel {channel} --count {count}",
        "desc": "Deauth flood — verifies PMF (802.11w) protection",
        "requires": ["bssid", "channel", "interface"],
        "defaults": {"count": "50"},
    },
    # WPS PIN brute-force (Reaver) — checks if WPS is properly disabled.
    "wps_bruteforce": {
        "cmd": "reaver -i {interface} -b {bssid} -c {channel} -vv -N",
        "desc": "Reaver WPS PIN brute-force (tests WPS-disabled requirement)",
        "requires": ["bssid", "channel", "interface"],
        "defaults": {},
    },
    # Evil Twin / Rogue AP — Pineapple only (engine="pineapple"); no local
    # engine exists. The Pineapple broadcasts the twin, driven over REST via
    # eth1. Kept here as a known scenario name for validation and the UI.
    "rogue_ap": {
        "cmd": None,
        "desc": "Spawn Evil Twin access point (WiFi Pineapple over eth1)",
        "requires": [],
        "defaults": {},
        "pineapple_only": True,
    },
    # PMF probe — sends spoofed mgmt frames and observes rejection.
    "pmf_probe": {
        "cmd": "python3 scripts/pmf_probe.py --iface {interface} --bssid {bssid}",
        "desc": "Management-frame protection behaviour probe",
        "requires": ["bssid", "interface"],
        "defaults": {},
    },
}


class AttackJob:
    def __init__(self, job_id, scenario, cmd):
        self.job_id = job_id
        self.scenario = scenario
        self.cmd = cmd
        self.proc = None
        self.status = "pending"       # pending | running | finished | killed | error
        self.started_at = None
        self.ended_at = None
        self.return_code = None
        self.stop_requested = False

    def to_dict(self):
        return {
            "job_id": self.job_id,
            "scenario": self.scenario,
            "cmd": self.cmd,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "return_code": self.return_code,
        }


class AttackRunner:
    def __init__(self, socketio, logger):
        self.socketio = socketio
        self.logger = logger
        self.jobs = {}          # job_id -> AttackJob
        self._lock = threading.Lock()

    # ---- public API ---------------------------------------------------------
    def start(self, job_id, scenario, params):
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario: {scenario}")

        engine = (params or {}).get("engine", "local")
        if engine not in ("local", "pineapple"):
            raise ValueError("unknown attack engine")
        if SCENARIOS[scenario].get("pineapple_only") and engine != "pineapple":
            raise ValueError(f"{scenario} runs on the Pineapple only (engine='pineapple')")
        if engine == "pineapple":
            if scenario not in ("deauth", "rogue_ap"):
                raise ValueError("Pineapple currently supports deauth and rogue_ap only")
            root = Path(__file__).resolve().parents[2]
            config = Path(os.environ.get("PINEAPPLE_CONFIG", root / "configs/pineapple.local.json"))
            if not config.is_file():
                raise ValueError("尚未設定 Pineapple：請先建立 configs/pineapple.local.json")
            try:
                config_data = json.loads(config.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"Pineapple 設定檔無法讀取：{exc}") from None
            if not isinstance(config_data, dict):
                raise ValueError("Pineapple 設定檔需為 JSON object")
            password_env = config_data.get("password_env", "PINEAPPLE_PASSWORD")
            if not isinstance(password_env, str) or not password_env:
                raise ValueError("Pineapple password_env 設定無效")
            if not os.environ.get(password_env):
                raise ValueError(
                    f"Pineapple 密碼環境變數 {password_env} 未設定；請重新啟動平台並在終端輸入密碼。"
                )
            management_interface = str(params.get("management_interface", "")).strip()
            if management_interface:
                if not re.fullmatch(r"[A-Za-z0-9_.:-]+", management_interface):
                    raise ValueError("invalid Pineapple management interface")
                if not (Path("/sys/class/net") / management_interface).exists():
                    raise ValueError(f"Pineapple management interface not found: {management_interface}")
            # Never accept a config path or command from the browser.
            argv = [sys.executable, "-u", str(root / "scripts/pineapple.py"),
                    "deauth" if scenario == "deauth" else "evil-twin",
                    "--config", str(config.resolve()), "--execute",
                    "--bssid", str(params.get("bssid", "")),
                    "--channel", str(params.get("channel", ""))]
            if scenario == "rogue_ap":
                argv.extend(["--ssid", str(params.get("ssid", ""))])
            if management_interface:
                argv.extend(["--management-interface", management_interface])
            cmd = shlex.join(argv)
        else:
            cmd = self._local_command(scenario, params)
        job = AttackJob(job_id, scenario, cmd)
        with self._lock:
            self.jobs[job_id] = job
        t = threading.Thread(target=self._run, args=(job,), daemon=True)
        t.start()
        return job

    def _local_command(self, scenario, params):
        spec = SCENARIOS[scenario]
        merged = {**spec["defaults"], **(params or {})}

        missing = [k for k in spec["requires"] if not merged.get(k)]
        if missing:
            raise ValueError(f"missing required params: {missing}")

        if scenario == "deauth":
            iface = str(merged["interface"])
            if (not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface)
                    or not (Path("/sys/class/net") / iface).exists()):
                raise ValueError("invalid or missing deauth interface")
            if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", str(merged["bssid"])):
                raise ValueError("invalid BSSID")
            try:
                channel, count = int(merged["channel"]), int(merged["count"])
            except (TypeError, ValueError):
                raise ValueError("channel and count must be integers") from None
            if not 1 <= channel <= 233 or not 1 <= count <= 200:
                raise ValueError("channel or count outside the lab safety limit")
            merged.update(channel=channel, count=count)

        return spec["cmd"].format(**merged)

    def stop(self, job_id):
        with self._lock:
            job = self.jobs.get(job_id)
        if not job or job.status in ("finished", "killed", "error"):
            return False
        job.stop_requested = True
        if not job.proc:
            return True
        try:
            job.proc.terminate()
            return True
        except Exception:
            return False

    def list_jobs(self):
        with self._lock:
            return [j.to_dict() for j in self.jobs.values()]

    # ---- worker -------------------------------------------------------------
    def _emit(self, channel, payload):
        try:
            self.socketio.emit(channel, payload, namespace="/")
        except Exception:
            pass

    def _run(self, job):
        job.started_at = time.time()
        job.status = "running"
        self.logger.info("attack", f"[{job.job_id}] start: {job.cmd}")
        self._emit("job_update", job.to_dict())

        # Dry-run safety: if binary is missing we simulate output so the
        # UI still demonstrates the streaming pipeline.
        binary = shlex.split(job.cmd)[0]
        if shutil.which(binary) is None:
            self._simulate(job)
            return

        try:
            job.proc = subprocess.Popen(
                shlex.split(job.cmd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                cwd=Path(__file__).resolve().parents[2],
            )
            if job.stop_requested:
                job.proc.terminate()
            for line in job.proc.stdout:
                line = line.rstrip()
                self._emit("job_output", {"job_id": job.job_id, "line": line})
                self.logger.info("attack", f"[{job.job_id}] {line}")
            job.proc.wait()
            job.return_code = job.proc.returncode
            job.status = ("killed" if job.stop_requested and job.return_code in (0, 130, -15)
                          else "finished" if job.return_code == 0 else "error")
        except Exception as e:
            job.status = "error"
            self._emit("job_output",
                       {"job_id": job.job_id, "line": f"[runner-error] {e}"})
        finally:
            job.ended_at = time.time()
            self._emit("job_update", job.to_dict())
            self.logger.info("attack", f"[{job.job_id}] end status={job.status}")

    def _simulate(self, job):
        """Fake output so the frontend pipeline can be tested without tools installed."""
        fake = [
            f"[*] SIMULATED run of: {job.cmd}",
            "[*] (install wifite2 / aircrack-ng / reaver to run for real)",
            "[+] putting interface into monitor mode ...",
            "[+] scanning target ...",
            "[+] capturing frames ... 25%",
            "[+] capturing frames ... 60%",
            "[+] capturing frames ... 100%",
            "[+] done.",
        ]
        for line in fake:
            if job.stop_requested:
                job.status = "killed"
                job.return_code = 130
                job.ended_at = time.time()
                self._emit("job_update", job.to_dict())
                return
            self._emit("job_output", {"job_id": job.job_id, "line": line})
            self.logger.info("attack", f"[{job.job_id}] {line}")
        job.status = "finished"
        job.return_code = 0
        job.ended_at = time.time()
        self._emit("job_update", job.to_dict())

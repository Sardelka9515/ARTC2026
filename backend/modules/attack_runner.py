"""
Attack runner — manages long-running attack/test subprocesses
and streams stdout/stderr lines to the frontend via Socket.IO.

Primary engine: wifite2  (https://github.com/kimocoder/wifite2)
Fallbacks: aireplay-ng, hostapd, reaver, bully, hcxdumptool
"""
import os
import shlex
import shutil
import threading
import subprocess
import time


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
        "cmd": "aireplay-ng --deauth {count} -a {bssid} {interface}",
        "desc": "Deauth flood — verifies PMF (802.11w) protection",
        "requires": ["bssid", "interface"],
        "defaults": {"count": "50"},
    },
    # WPS PIN brute-force (Reaver) — checks if WPS is properly disabled.
    "wps_bruteforce": {
        "cmd": "reaver -i {interface} -b {bssid} -c {channel} -vv -N",
        "desc": "Reaver WPS PIN brute-force (tests WPS-disabled requirement)",
        "requires": ["bssid", "channel", "interface"],
        "defaults": {},
    },
    # Evil Twin / Rogue AP via hostapd — checks client-side validation.
    "rogue_ap": {
        "cmd": "hostapd {config_path}",
        "desc": "Spawn Evil Twin access point (hostapd)",
        "requires": ["config_path"],
        "defaults": {},
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

        spec = SCENARIOS[scenario]
        merged = {**spec["defaults"], **(params or {})}

        missing = [k for k in spec["requires"] if not merged.get(k)]
        if missing:
            raise ValueError(f"missing required params: {missing}")

        cmd = spec["cmd"].format(**merged)
        job = AttackJob(job_id, scenario, cmd)

        with self._lock:
            self.jobs[job_id] = job

        t = threading.Thread(target=self._run, args=(job,), daemon=True)
        t.start()
        return job

    def stop(self, job_id):
        with self._lock:
            job = self.jobs.get(job_id)
        if not job or not job.proc:
            return False
        try:
            job.proc.terminate()
            job.status = "killed"
            return True
        except Exception:
            return False

    def list_jobs(self):
        with self._lock:
            return [j.to_dict() for j in self.jobs.values()]

    # ---- worker -------------------------------------------------------------
    def _emit(self, job_id, channel, payload):
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
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in job.proc.stdout:
                line = line.rstrip()
                self._emit("job_output", {"job_id": job.job_id, "line": line})
                self.logger.info("attack", f"[{job.job_id}] {line}")
            job.proc.wait()
            job.return_code = job.proc.returncode
            job.status = "finished" if job.return_code == 0 else "error"
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
            self._emit("job_output", {"job_id": job.job_id, "line": line})
            self.logger.info("attack", f"[{job.job_id}] {line}")
            time.sleep(0.4)
        job.status = "finished"
        job.return_code = 0
        job.ended_at = time.time()
        self._emit("job_update", job.to_dict())

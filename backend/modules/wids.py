"""
Wireless Intrusion Detection System — Evil-Twin oriented.

Implements the two-branch WIDS design from the mid-term report
(slide 11「WIDS設計 針對Evil Twin」):

  ┌ 普通模仿 SSID（基礎防禦）─ EvilTwinFingerprintDetector
  │   · BSSID 白名單            · 嚴格設定頻道
  │   · Beacon/Probe-Response 指紋（IE 順序 / HT·VHT·HE / Vendor Tags）
  │
  └ 模仿 BSSID(MAC)（802.11 底層）─ MacSpoofDetector + BehavioralDetector
      · Sequence Number 跳躍      · Timestamp (TSF) 衝突
      · RSSI 不自然突增           · Deauth 突發 + 異常重連

Plus DoSDetector for the broader spec items (slides 5/7/10):
mass retransmission, illegal 4-way handshake, deauth flood.

Capture is real-only: startup fails when the selected interface cannot be
placed in monitor mode or opened for raw packet capture.  The WIDS must never
replace failed capture with synthetic security events.
"""
import threading
import time
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field

# ---- tunable detection thresholds (field-tunable) --------------------------
SEQ_JUMP_TOLERANCE = 300         # max plausible signed seq delta between frames of one BSSID
TSF_DRIFT_BOUND_US = 2_000_000   # 2 s: TSF divergence beyond this ⇒ a second radio
RSSI_SPIKE_DBM = 15              # sudden RSSI change (dBm) for a "stable" BSSID
DEAUTH_FLOOD_WINDOW_S = 5
DEAUTH_FLOOD_THRESHOLD = 20      # deauth frames per window ⇒ flood
DEAUTH_REDIRECT_WINDOW_S = 8     # reconnect-to-twin must follow a burst within this window
RETRANS_RATIO_THRESHOLD = 0.20   # retry-flagged data ratio over baseline
RETRANS_MIN_SAMPLES = 25         # data frames per retransmission evaluation

# An empty baseline still enables sequence, TSF, RSSI, deauth, retry, and EAPOL
# detectors. Evil-Twin whitelist/fingerprint checks activate only when the UI
# supplies an explicitly trusted scan baseline; no fictional APs are injected.
DEFAULT_BASELINE = []


# ---------------------------------------------------------------------------
@dataclass
class FrameObservation:
    """Normalized 802.11 frame view fed to every detector."""
    fc_type: int = 0             # 0=mgmt 1=ctrl 2=data
    subtype: int = 0             # 8=Beacon 5=ProbeResp 12=Deauth ...
    bssid: str = ""
    ssid: str = ""
    channel: int = None
    seq: int = None              # 0..4095 sequence number
    tsf: int = None              # 64-bit TSF microsecond timer (beacons only)
    rssi: int = None             # dBm
    ie_order: list = field(default_factory=list)   # ordered IE tag ids
    ht_vht_he: bytes = b""       # concatenated HT/VHT/HE capability bytes
    vendor_tags: list = field(default_factory=list)  # vendor OUIs
    retry: bool = False
    reason_code: int = None      # deauth reason
    is_deauth: bool = False
    is_eapol: bool = False
    eapol_msg: int = None        # 1..4 in the 4-way handshake

    def fingerprint(self):
        return (tuple(self.ie_order), self.ht_vht_he, tuple(self.vendor_tags))


def _ev(etype, message, severity, category, obs=None, evidence=None):
    """Build an enriched event dict (subject fields pulled from obs when present)."""
    return {
        "type": etype,
        "message": message,
        "severity": severity,
        "category": category,
        "bssid": (obs.bssid if obs else "") or "",
        "ssid": (obs.ssid if obs else "") or "",
        "channel": (obs.channel if obs else None),
        "evidence": evidence or {},
    }


# ---- detectors -------------------------------------------------------------
class EvilTwinFingerprintDetector:
    """Left branch — SSID clone on a different BSSID (基礎防禦)."""

    def __init__(self, baseline):
        self.ssid_to_bssids = {}     # ssid -> set(bssid)
        self.bssid_channel = {}      # bssid -> expected channel
        self.all_bssids = set()
        for b in baseline:
            ssid, bssid = b.get("ssid", ""), (b.get("bssid") or "").upper()
            if not bssid:
                continue
            self.ssid_to_bssids.setdefault(ssid, set()).add(bssid)
            self.all_bssids.add(bssid)
            if b.get("channel") is not None:
                self.bssid_channel[bssid] = b["channel"]
        self.learned_fp = {}         # bssid -> fingerprint (from first trusted sighting)

    def feed(self, obs, state):
        if obs.fc_type != 0 or obs.subtype not in (8, 5):  # Beacon / ProbeResp only
            return []
        bssid = (obs.bssid or "").upper()
        known_ssid = obs.ssid in self.ssid_to_bssids
        trusted_bssid = bssid in self.all_bssids
        out = []

        # 1) BSSID whitelist — known SSID advertised from an unlisted BSSID = clone.
        if known_ssid and not trusted_bssid:
            legit = sorted(self.ssid_to_bssids[obs.ssid])
            ev = {"expected_bssid": legit, "observed_bssid": bssid}
            legit_fp = next((self.learned_fp[b] for b in legit if b in self.learned_fp), None)
            if legit_fp is not None and legit_fp != obs.fingerprint():
                ev["ie_order_expected"] = list(legit_fp[0])
                ev["ie_order_observed"] = obs.ie_order
            out.append(_ev("evil_twin",
                           f"SSID '{obs.ssid}' 出現於白名單外 BSSID {bssid}"
                           f"（合法 {', '.join(legit)}）", "high", "fingerprint", obs, ev))
            return out

        if trusted_bssid:
            # 2) Strict channel — trusted AP seen off its assigned channel.
            exp_ch = self.bssid_channel.get(bssid)
            if exp_ch is not None and obs.channel is not None and obs.channel != exp_ch:
                out.append(_ev("rogue_channel",
                               f"{bssid} 於非預期頻道 ch{obs.channel}（應為 ch{exp_ch}）",
                               "high", "fingerprint", obs,
                               {"expected_channel": exp_ch, "observed_channel": obs.channel}))
            # 3) Fingerprint — learn once, then flag any drift for this BSSID.
            fp = obs.fingerprint()
            if bssid not in self.learned_fp:
                self.learned_fp[bssid] = fp
                out.append(_ev("baseline",
                               f"已學習合法 AP 指紋 {bssid}（{obs.ssid}）",
                               "info", "baseline", obs,
                               {"ie_order": obs.ie_order,
                                "vendor_tags": obs.vendor_tags}))
            elif self.learned_fp[bssid] != fp:
                good = self.learned_fp[bssid]
                out.append(_ev("fingerprint_mismatch",
                               f"{bssid} Beacon 指紋與學習基準不符（疑似偽造）",
                               "high", "fingerprint", obs,
                               {"ie_order_expected": list(good[0]),
                                "ie_order_observed": obs.ie_order,
                                "vendor_expected": list(good[2]),
                                "vendor_observed": obs.vendor_tags}))
        return out


class MacSpoofDetector:
    """Right branch — BSSID/MAC spoof, via 802.11 low-level invariants."""

    def __init__(self):
        self.last_seq = {}    # bssid -> last seq
        self.last_tsf = {}    # bssid -> (tsf, wall_clock)

    def feed(self, obs, state):
        if obs.fc_type == 2 and not obs.is_deauth:  # skip bulk data for seq (noisy)
            pass
        bssid = (obs.bssid or "").upper()
        if not bssid:
            return []
        out = []

        # Sequence-number jump: two radios sharing one BSSID interleave counters,
        # producing a backward jump larger than any single-radio gap.
        if obs.seq is not None:
            prev = self.last_seq.get(bssid)
            if prev is not None:
                signed = ((obs.seq - prev + 2048) % 4096) - 2048
                if signed < -SEQ_JUMP_TOLERANCE:
                    out.append(_ev("seq_anomaly",
                                   f"{bssid} 序號回跳 {prev}→{obs.seq}（Δ{signed}，疑似第二台發射機）",
                                   "high", "mac_layer", obs,
                                   {"seq_prev": prev, "seq_now": obs.seq, "delta": signed}))
            self.last_seq[bssid] = obs.seq

        # TSF collision: a real AP's µs timer advances monotonically with wall time;
        # a spoofing radio cannot mirror it.
        if obs.tsf is not None:
            prev = self.last_tsf.get(bssid)
            now = time.time()
            if prev is not None:
                exp = prev[0] + int((now - prev[1]) * 1_000_000)
                drift = abs(obs.tsf - exp)
                if drift > TSF_DRIFT_BOUND_US:
                    out.append(_ev("tsf_collision",
                                   f"{bssid} TSF 衝突：期望≈{exp} 觀測={obs.tsf}（偏移 {drift}µs）",
                                   "high", "mac_layer", obs,
                                   {"tsf_expected": exp, "tsf_observed": obs.tsf,
                                    "drift_us": drift}))
            self.last_tsf[bssid] = (obs.tsf, now)
        return out


class BehavioralDetector:
    """Right branch — behavioural analysis (RSSI spike, deauth→reconnect)."""

    def __init__(self, baseline):
        self.last_rssi = {}   # bssid -> last rssi
        self.ssid_home = {}   # ssid -> trusted bssid (for redirect detection)
        for b in baseline:
            if b.get("ssid") and b.get("bssid"):
                self.ssid_home.setdefault(b["ssid"], (b["bssid"] or "").upper())

    def feed(self, obs, state):
        bssid = (obs.bssid or "").upper()
        out = []

        # RSSI unnatural spike for a stable BSSID.
        if obs.rssi is not None and bssid:
            prev = self.last_rssi.get(bssid)
            if prev is not None and abs(obs.rssi - prev) >= RSSI_SPIKE_DBM:
                sev = "high" if abs(obs.rssi - prev) >= 2 * RSSI_SPIKE_DBM else "medium"
                out.append(_ev("rssi_spike",
                               f"{bssid} RSSI 不自然突增 {prev}→{obs.rssi} dBm",
                               sev, "behavioral", obs,
                               {"rssi_prev": prev, "rssi_now": obs.rssi,
                                "delta": obs.rssi - prev}))
            self.last_rssi[bssid] = obs.rssi

        # Deauth burst + abnormal reconnect: SSID re-appears on a *different* BSSID
        # shortly after a deauth burst against its home AP.
        if obs.fc_type == 0 and obs.subtype in (8, 5) and obs.ssid:
            burst = state.get("deauth_burst")
            home = self.ssid_home.get(obs.ssid)
            if burst and home and bssid and bssid != home:
                if time.time() - burst[0] <= DEAUTH_REDIRECT_WINDOW_S:
                    out.append(_ev("deauth_redirect",
                                   f"Deauth 突發後 '{obs.ssid}' 改由 {bssid} 提供（原 {home}）— 疑似導向邪惡雙子",
                                   "high", "behavioral", obs,
                                   {"home_bssid": home, "twin_bssid": bssid}))
        return out


class DoSDetector:
    """DoS / integrity — deauth flood, retransmission spike, illegal handshake."""

    def __init__(self):
        self.deauth_window = []          # timestamps
        self.deauth_flood_active = False # debounce: one event per flood episode
        self.data_total = 0
        self.data_retry = 0
        self.eapol_seen = {}             # bssid -> highest handshake msg observed in order

    def feed(self, obs, state):
        out = []
        bssid = (obs.bssid or "").upper()

        # Deauth flood (sliding window) — also arms the behavioural redirect check.
        if obs.is_deauth:
            now = time.time()
            self.deauth_window.append(now)
            while self.deauth_window and now - self.deauth_window[0] > DEAUTH_FLOOD_WINDOW_S:
                self.deauth_window.pop(0)
            n = len(self.deauth_window)
            if n >= DEAUTH_FLOOD_THRESHOLD:
                state["deauth_burst"] = (now, obs.ssid, bssid)
                # Debounce: emit a single alert when the flood starts, not one
                # per frame. Re-arms only after the window falls below threshold.
                if not self.deauth_flood_active:
                    self.deauth_flood_active = True
                    out.append(_ev("deauth_flood",
                                   f"{n} 個 Deauth／{DEAUTH_FLOOD_WINDOW_S}s"
                                   + (f"（reason {obs.reason_code}）" if obs.reason_code is not None else "")
                                   + f" 來源 {bssid}", "high", "dos", obs,
                                   {"count": n, "window_s": DEAUTH_FLOOD_WINDOW_S,
                                    "reason_code": obs.reason_code}))
            elif self.deauth_flood_active and n < DEAUTH_FLOOD_THRESHOLD:
                self.deauth_flood_active = False   # episode ended → re-arm

        # Retransmission ratio over baseline.
        if obs.fc_type == 2:
            self.data_total += 1
            if obs.retry:
                self.data_retry += 1
            if self.data_total >= RETRANS_MIN_SAMPLES:
                ratio = self.data_retry / self.data_total
                if ratio >= RETRANS_RATIO_THRESHOLD:
                    out.append(_ev("retrans_spike",
                                   f"重傳比例 {ratio*100:.0f}%（基準 <{RETRANS_RATIO_THRESHOLD*100:.0f}%）",
                                   "medium", "dos", obs,
                                   {"ratio": round(ratio, 3),
                                    "samples": self.data_total}))
                self.data_total = self.data_retry = 0

        # Illegal 4-way handshake ordering (e.g. M2 before M1).
        if obs.is_eapol and obs.eapol_msg and bssid:
            highest = self.eapol_seen.get(bssid, 0)
            if obs.eapol_msg > highest + 1:
                out.append(_ev("handshake_bad",
                               f"{bssid} 非法握手序列：收到 M{obs.eapol_msg} 但缺少 M{highest+1}",
                               "medium", "dos", obs,
                               {"expected_msg": highest + 1, "observed_msg": obs.eapol_msg}))
            self.eapol_seen[bssid] = max(highest, obs.eapol_msg)
        return out


# ---------------------------------------------------------------------------
class WIDSMonitor:
    def __init__(self, socketio, logger):
        self.socketio = socketio
        self.logger = logger
        self._thread = None
        self._running = False
        self._iface = None
        self._detectors = []
        self._state = {}
        self._status_lock = threading.Lock()
        self._status = self._new_status()
        self._original_type = None
        self._changed_type = False

    @staticmethod
    def _new_status(**updates):
        value = {
            "state": "stopped", "iface": None, "channel": None,
            "capture_source": None, "frames": 0, "last_frame_ts": None,
            "error": None,
        }
        value.update(updates)
        return value

    @staticmethod
    def list_interfaces():
        """Return real wireless interfaces only; never return demo placeholders."""
        if shutil.which("iw") is None:
            return []
        try:
            result = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                return []
            return re.findall(r"^\s*Interface\s+(\S+)", result.stdout, re.MULTILINE)
        except (OSError, subprocess.SubprocessError):
            return []

    def status(self):
        with self._status_lock:
            return dict(self._status)

    def _set_status(self, **updates):
        with self._status_lock:
            self._status.update(updates)
            current = dict(self._status)
        try:
            self.socketio.emit("wids_status", current, namespace="/")
        except Exception:
            pass
        return current

    @staticmethod
    def _run_command(command):
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"Required command not found: {command[0]}") from exc
        except subprocess.SubprocessError as exc:
            raise RuntimeError(f"Command failed: {' '.join(command)}: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or f"exit {result.returncode}"
            raise RuntimeError(f"{' '.join(command)}: {detail}")
        return result.stdout

    def _prepare_interface(self, iface, channel):
        if iface not in self.list_interfaces():
            raise RuntimeError(f"Wireless interface '{iface}' was not found")
        if shutil.which("ip") is None or shutil.which("iw") is None:
            raise RuntimeError("The ip and iw commands are required")

        info = self._run_command(["iw", "dev", iface, "info"])
        match = re.search(r"^\s*type\s+(\S+)", info, re.MULTILINE)
        if not match:
            raise RuntimeError(f"Could not determine the mode of '{iface}'")
        self._original_type = match.group(1)
        self._changed_type = self._original_type != "monitor"

        if self._changed_type:
            self._run_command(["ip", "link", "set", iface, "down"])
            try:
                self._run_command(["iw", "dev", iface, "set", "type", "monitor"])
            finally:
                # Bring the adapter back up even when the mode change fails.
                self._run_command(["ip", "link", "set", iface, "up"])
        else:
            self._run_command(["ip", "link", "set", iface, "up"])

        if channel is not None:
            self._run_command(["iw", "dev", iface, "set", "channel", str(channel)])

        verified = self._run_command(["iw", "dev", iface, "info"])
        if not re.search(r"^\s*type\s+monitor\s*$", verified, re.MULTILINE):
            raise RuntimeError(f"'{iface}' did not enter monitor mode")
        active_channel = re.search(r"^\s*channel\s+(\d+)", verified, re.MULTILINE)
        return int(active_channel.group(1)) if active_channel else channel

    @staticmethod
    def _verify_capture_access(iface):
        try:
            from scapy.all import sniff  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("Scapy is not installed; real WIDS capture cannot start") from exc

        # Opening a raw packet socket catches missing CAP_NET_RAW/root permission
        # synchronously, before the API tells the dashboard that WIDS is running.
        try:
            probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            try:
                probe.bind((iface, 0))
            finally:
                probe.close()
        except (OSError, PermissionError) as exc:
            raise RuntimeError(f"Cannot capture on '{iface}': {exc}") from exc

    def _restore_interface(self):
        if not self._changed_type or not self._iface or not self._original_type:
            return None
        try:
            self._run_command(["ip", "link", "set", self._iface, "down"])
            self._run_command(
                ["iw", "dev", self._iface, "set", "type", self._original_type]
            )
            self._run_command(["ip", "link", "set", self._iface, "up"])
            return None
        except RuntimeError as exc:
            return str(exc)
        finally:
            self._changed_type = False

    def start(self, iface, baseline=None, channel=None):
        if self._running:
            return {"ok": False, "error": "WIDS is already running", "status": self.status()}
        iface = (iface or "").strip()
        if not iface:
            return {"ok": False, "error": "A wireless interface is required", "status": self.status()}
        if channel in (None, ""):
            channel = None
        else:
            try:
                channel = int(channel)
            except (TypeError, ValueError):
                return {"ok": False, "error": "Channel must be a number", "status": self.status()}
            if not 1 <= channel <= 233:
                return {"ok": False, "error": "Channel must be between 1 and 233", "status": self.status()}

        self._iface = iface
        self._set_status(**self._new_status(state="starting", iface=iface, channel=channel,
                                            capture_source="real"))
        try:
            active_channel = self._prepare_interface(iface, channel)
            self._verify_capture_access(iface)
        except Exception as exc:
            restore_error = self._restore_interface()
            message = str(exc)
            if restore_error:
                message += f"; interface restore also failed: {restore_error}"
            self.logger.error("wids", f"WIDS failed to start on {iface}: {message}")
            status = self._set_status(state="error", error=message)
            return {"ok": False, "error": message, "status": status}

        self._running = True
        self._state = {}
        base = baseline or DEFAULT_BASELINE
        # normalize baseline entries to {bssid, ssid, channel}
        norm = [{"bssid": (b.get("bssid") or "").upper(),
                 "ssid": b.get("ssid", ""),
                 "channel": b.get("channel")} for b in base if b.get("bssid")]
        self._detectors = [
            EvilTwinFingerprintDetector(norm),
            MacSpoofDetector(),
            BehavioralDetector(norm),
            DoSDetector(),
        ]
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.logger.info("wids", f"WIDS started on {iface} (baseline: {len(norm)} trusted AP)")
        status = self._set_status(state="running", channel=active_channel, error=None)
        return {"ok": True, "status": status}

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        restore_error = self._restore_interface()
        self.logger.info("wids", "WIDS stopped")
        status = self._set_status(state="stopped", error=restore_error)
        return {"ok": restore_error is None, "error": restore_error, "status": status}

    # ---- dispatch ----------------------------------------------------------
    def _dispatch(self, obs):
        # Ignore broadcast/undirected frames (e.g. probe requests carry the
        # broadcast BSSID) — bucketing many distinct transmitters under
        # FF:FF:FF:FF:FF:FF produces spurious seq/RSSI anomalies. WIDS keys on
        # real per-AP identity, so only dispatch AP-addressed observations.
        if not obs.bssid or obs.bssid == "FF:FF:FF:FF:FF:FF":
            return
        for det in self._detectors:
            try:
                for evt in det.feed(obs, self._state):
                    self._emit_event(evt)
            except Exception as e:  # a detector fault must not kill the monitor
                self.logger.info("wids", f"detector {det.__class__.__name__} error: {e}")

    def _loop(self):
        try:
            self._scapy_loop()
        except Exception as exc:
            self._running = False
            message = f"Real capture stopped: {exc}"
            restore_error = self._restore_interface()
            if restore_error:
                message += f"; interface restore also failed: {restore_error}"
            self.logger.error("wids", message)
            self._set_status(state="error", error=message)

    # ---- real capture ------------------------------------------------------
    def _scapy_loop(self):
        from scapy.all import (sniff, Dot11, Dot11Beacon, Dot11ProbeResp,
                               Dot11Deauth, Dot11Elt, RadioTap, EAPOL)

        def handler(pkt):
            if not self._running:
                return True
            if not pkt.haslayer(Dot11):
                return
            with self._status_lock:
                self._status["frames"] += 1
                self._status["last_frame_ts"] = time.time()
            try:
                self._dispatch(self._parse(pkt, Dot11, Dot11Beacon, Dot11ProbeResp,
                                           Dot11Deauth, Dot11Elt, RadioTap, EAPOL))
            except Exception:
                pass

        # A short timeout makes Stop responsive even on a quiet/deaf adapter.
        while self._running:
            sniff(iface=self._iface, prn=handler, store=False, timeout=1)

    @staticmethod
    def _parse(pkt, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Deauth,
               Dot11Elt, RadioTap, EAPOL):
        d = pkt[Dot11]
        obs = FrameObservation(
            fc_type=int(d.type), subtype=int(d.subtype),
            bssid=(d.addr3 or d.addr2 or "").upper(),
            retry=bool(int(d.FCfield) & 0x08),
        )
        if d.SC is not None:
            obs.seq = int(d.SC) >> 4
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            obs.rssi = getattr(rt, "dBm_AntSignal", None)

        beacon = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
        if beacon is not None:
            obs.tsf = getattr(beacon, "timestamp", None)
            el = pkt.getlayer(Dot11Elt)
            caps = []
            while el is not None and el.name in ("802.11 Information Element", "Dot11Elt"):
                idn = int(el.ID)
                obs.ie_order.append(idn)
                if idn == 0:  # SSID
                    try:
                        obs.ssid = el.info.decode(errors="ignore")
                    except Exception:
                        obs.ssid = ""
                elif idn == 3 and el.info:  # DS Parameter set → channel
                    obs.channel = el.info[0]
                elif idn in (45, 191, 255):  # HT / VHT / HE capabilities
                    caps.append(bytes(el.info or b""))
                elif idn == 221 and el.info:  # vendor specific → OUI
                    obs.vendor_tags.append(bytes(el.info[:3]).hex(":"))
                el = el.payload.getlayer(Dot11Elt)
            obs.ht_vht_he = b"".join(caps)

        if pkt.haslayer(Dot11Deauth):
            obs.is_deauth = True
            obs.reason_code = int(pkt[Dot11Deauth].reason)
        if pkt.haslayer(EAPOL):
            obs.is_eapol = True
            obs.eapol_msg = WIDSMonitor._eapol_msg(pkt[EAPOL])
        return obs

    @staticmethod
    def _eapol_msg(eapol):
        """Best-effort 4-way handshake message number from Key Information bits."""
        try:
            raw = bytes(eapol)
            key_info = int.from_bytes(raw[5:7], "big")  # after type/len
            mic = bool(key_info & 0x0100)
            ack = bool(key_info & 0x0080)
            secure = bool(key_info & 0x0200)
            install = bool(key_info & 0x0040)
            if ack and not mic:
                return 1
            if mic and not ack and not secure:
                return 2
            if install and ack and mic:
                return 3
            if mic and secure and not ack:
                return 4
        except Exception:
            pass
        return None

    # ---- emit --------------------------------------------------------------
    def _emit_event(self, evt):
        evt.setdefault("ts", time.time())
        evt.setdefault("iface", self._iface)
        evt.setdefault("severity", "info")
        evt.setdefault("category", "dos")
        try:
            self.socketio.emit("wids_event", evt, namespace="/")
        except Exception:
            pass
        self.logger.info(
            "wids",
            f"{evt['severity'].upper()} [{evt['category']}] {evt['type']}: {evt['message']}")

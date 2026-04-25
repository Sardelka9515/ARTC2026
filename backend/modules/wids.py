"""
Wireless Intrusion Detection skeleton.

Detects (per project spec):
  - Deauth floods (anomalous Reason Codes)
  - Beacon flooding / mass retransmissions
  - Illegal 4-way handshake sequences
  - Rogue AP / Evil Twin (same SSID, different BSSID or channel)

This skeleton uses scapy if available, otherwise emits synthetic events
so the UI can be developed and demoed without monitor-mode hardware.
"""
import threading
import time
import random


class WIDSMonitor:
    def __init__(self, socketio, logger):
        self.socketio = socketio
        self.logger = logger
        self._thread = None
        self._running = False
        self._iface = None

    def start(self, iface):
        if self._running:
            return
        self._iface = iface
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.logger.info("wids", f"WIDS started on {iface}")

    def stop(self):
        self._running = False
        self.logger.info("wids", "WIDS stopped")

    # ------------------------------------------------------------------
    def _loop(self):
        try:
            from scapy.all import sniff, Dot11, Dot11Deauth  # noqa
            self._scapy_loop()
        except Exception:
            self._simulated_loop()

    def _scapy_loop(self):
        from scapy.all import sniff, Dot11, Dot11Deauth

        deauth_window = []

        def handler(pkt):
            if not self._running:
                return True
            if pkt.haslayer(Dot11Deauth):
                now = time.time()
                deauth_window.append(now)
                # keep only last 5s
                while deauth_window and now - deauth_window[0] > 5:
                    deauth_window.pop(0)
                if len(deauth_window) > 20:
                    self._emit_event("deauth_flood",
                                     f"{len(deauth_window)} deauth frames in 5s",
                                     severity="high")
            # TODO: beacon flood, handshake anomaly, rogue AP detection.

        sniff(iface=self._iface, prn=handler, store=False,
              stop_filter=lambda p: not self._running)

    def _simulated_loop(self):
        """Synthetic events for demo without real hardware."""
        samples = [
            ("beacon_normal",   "beacon rate within baseline", "info"),
            ("deauth_flood",    "27 deauth frames / 5s from AA:BB:CC:11:22:33", "high"),
            ("rogue_ap",        "SSID 'ARTC-TBOX-Test' seen on 2 BSSIDs", "high"),
            ("handshake_bad",   "4-way handshake M2 without M1", "medium"),
            ("retrans_spike",   "retransmission ratio 34% (baseline 4%)", "medium"),
        ]
        while self._running:
            time.sleep(random.uniform(2.5, 5.0))
            if not self._running:
                break
            etype, msg, sev = random.choice(samples)
            self._emit_event(etype, msg, sev)

    def _emit_event(self, etype, message, severity="info"):
        evt = {
            "ts": time.time(),
            "type": etype,
            "message": message,
            "severity": severity,
            "iface": self._iface,
        }
        try:
            self.socketio.emit("wids_event", evt, namespace="/")
        except Exception:
            pass
        self.logger.info("wids", f"{severity.upper()} {etype}: {message}")

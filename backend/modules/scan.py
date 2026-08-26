"""
Wireless scanning module.
Wraps `iw` / `airodump-ng` for AP discovery.

NOTE: This is a skeleton. In production, parse airodump-ng CSV output
or use scapy with a monitor-mode interface.
"""
import subprocess
import re
import shutil


def list_interfaces():
    """Return wireless interfaces visible to `iw dev`."""
    out = []
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        for m in re.finditer(r"Interface\s+(\S+)", r.stdout):
            out.append(m.group(1))
    except Exception:
        pass
    if not out:
        # fallback stub so the UI still renders in dev environments
        out = ["wlan0", "wlan1", "wlan0mon"]
    return out


def scan_networks(iface="wlan0", duration=10):
    """
    Passive scan for nearby APs.
    Returns a list of dicts: { bssid, ssid, channel, signal, encryption, wps }

    Strategy:
      1. `iw dev <iface> scan` — works when the interface is in *managed* mode.
      2. If that yields nothing (e.g. the interface is in *monitor* mode, where
         `iw scan` is unsupported), fall back to a passive scapy beacon sniff so
         the *same monitor interface* used for WIDS also serves discovery.
      3. If neither works (no hardware / no scapy), return a stub dataset so the
         dashboard still renders.
    """
    if shutil.which("iw") is not None:
        try:
            r = subprocess.run(
                ["iw", "dev", iface, "scan"],
                capture_output=True, text=True, timeout=duration + 5
            )
            nets = _parse_iw_scan(r.stdout)
            if nets:
                return nets
        except Exception:
            pass

    # monitor-mode / iw-scan-failed path: passive scapy beacon sniff
    nets = _scapy_scan(iface, duration)
    if nets:
        return nets
    return _stub_results()


def _scapy_scan(iface, duration=8):
    """Passive AP discovery by sniffing beacons/probe-responses (monitor mode)."""
    try:
        from scapy.all import (sniff, Dot11, Dot11Beacon, Dot11ProbeResp,
                               Dot11Elt, RadioTap)
    except Exception:
        return []
    try:
        from scapy.layers.dot11 import Dot11EltRSN
    except Exception:
        Dot11EltRSN = None

    nets = {}

    def handle(pkt):
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            return
        d = pkt.getlayer(Dot11)
        bssid = (d.addr3 or "").lower()
        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            return
        n = nets.setdefault(bssid, {
            "bssid": bssid, "ssid": "", "channel": None, "signal": None,
            "encryption": "OPEN", "wps": False, "pmf": "unknown",
        })
        try:
            n["signal"] = int(pkt.dBm_AntSignal)
        except Exception:
            pass

        has_rsn = has_wpa = sae = False
        el = pkt.getlayer(Dot11Elt)
        while isinstance(el, Dot11Elt):
            idn = int(el.ID)
            if idn == 0:  # SSID
                try:
                    s = el.info.decode(errors="ignore")
                except Exception:
                    s = ""
                n["ssid"] = s if s else "<hidden>"
            elif idn == 3 and el.info:  # DS Parameter set → channel
                n["channel"] = el.info[0]
            elif idn == 48:  # RSN
                has_rsn = True
            elif idn == 221 and el.info:  # vendor specific
                info = bytes(el.info)
                if info[:3] == b"\x00\x50\xf2" and len(info) > 3:
                    if info[3] == 1:
                        has_wpa = True          # Microsoft WPA IE
                    elif info[3] == 4:
                        n["wps"] = True         # WPS IE
            el = el.payload.getlayer(Dot11Elt)

        # richer RSN parse (AKM=SAE → WPA3, PMF capability) if scapy exposes it
        if Dot11EltRSN is not None:
            rsn = pkt.getlayer(Dot11EltRSN)
            if rsn is not None:
                has_rsn = True
                try:
                    if any(getattr(s, "suite", None) == 8 for s in rsn.akm_suites):
                        sae = True              # AKM 8 = SAE (WPA3)
                except Exception:
                    pass
                try:
                    if getattr(rsn, "mfp_required", 0):
                        n["pmf"] = "required"
                    elif getattr(rsn, "mfp_capable", 0):
                        n["pmf"] = "capable"
                except Exception:
                    pass

        if sae:
            n["encryption"] = "WPA3"
        elif has_rsn:
            n["encryption"] = "WPA2/WPA3"
        elif has_wpa:
            n["encryption"] = "WPA"

        if n["channel"] is None:
            try:
                freq = int(pkt[RadioTap].ChannelFrequency)
                if 2412 <= freq <= 2484:
                    n["channel"] = 14 if freq == 2484 else (freq - 2407) // 5
            except Exception:
                pass

    try:
        sniff(iface=iface, prn=handle, timeout=duration, store=False)
    except Exception:
        return []
    return list(nets.values())


def _parse_iw_scan(text):
    nets = []
    current = None
    for line in text.splitlines():
        line = line.rstrip()
        m = re.match(r"BSS ([0-9a-f:]{17})", line)
        if m:
            if current:
                nets.append(current)
            current = {
                "bssid": m.group(1),
                "ssid": "",
                "channel": None,
                "signal": None,
                "encryption": "OPEN",
                "wps": False,
                "pmf": "unknown",
            }
            continue
        if not current:
            continue
        if "SSID:" in line:
            current["ssid"] = line.split("SSID:", 1)[1].strip() or "<hidden>"
        elif "signal:" in line:
            sig = re.search(r"-?\d+\.\d+", line)
            if sig:
                current["signal"] = float(sig.group(0))
        elif "DS Parameter set: channel" in line:
            ch = re.search(r"channel (\d+)", line)
            if ch:
                current["channel"] = int(ch.group(1))
        elif "RSN:" in line:
            current["encryption"] = "WPA2/WPA3"
        elif "WPA:" in line and current["encryption"] == "OPEN":
            current["encryption"] = "WPA"
        elif "WPS:" in line:
            current["wps"] = True
        elif "SAE" in line:
            current["encryption"] = "WPA3"
        elif "MFPR" in line or "Management frame protection required" in line:
            current["pmf"] = "required"
        elif "MFPC" in line:
            current["pmf"] = "capable"
    if current:
        nets.append(current)
    return nets


def _stub_results():
    """Fallback dataset so the dashboard renders without real hardware."""
    return [
        {"bssid": "AA:BB:CC:11:22:33", "ssid": "ARTC-TBOX-Test",
         "channel": 6, "signal": -42, "encryption": "WPA2",
         "wps": True, "pmf": "capable"},
        {"bssid": "AA:BB:CC:44:55:66", "ssid": "Vehicle-Guest",
         "channel": 11, "signal": -58, "encryption": "OPEN",
         "wps": False, "pmf": "unknown"},
        {"bssid": "AA:BB:CC:77:88:99", "ssid": "OTA-Secure",
         "channel": 36, "signal": -61, "encryption": "WPA3",
         "wps": False, "pmf": "required"},
    ]

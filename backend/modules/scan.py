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
    """
    # Prefer `iw` for a quick scan (does not require monitor mode).
    if shutil.which("iw") is None:
        return _stub_results()

    try:
        r = subprocess.run(
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=duration + 5
        )
        return _parse_iw_scan(r.stdout)
    except Exception:
        return _stub_results()


def _parse_iw_scan(text):
    nets = []
    current = None

    def finish_current():
        if not current:
            return
        auth = current.pop("_auth_suites", set())
        has_rsn = current.pop("_has_rsn", False)
        has_wpa = current.pop("_has_wpa", False)

        if "SAE" in auth and ("PSK" in auth or "802.1X" in auth):
            current["encryption"] = "WPA3-Transition"
        elif "SAE" in auth or "OWE" in auth:
            current["encryption"] = "WPA3"
        elif any(a.startswith("802.1X") for a in auth):
            current["encryption"] = "WPA2-Enterprise"
        elif "PSK" in auth:
            current["encryption"] = "WPA2"
        elif has_rsn:
            current["encryption"] = "WPA2/WPA3"
        elif has_wpa:
            current["encryption"] = "WPA"

    for line in text.splitlines():
        line = line.rstrip()
        m = re.match(r"BSS ([0-9a-f:]{17})", line)
        if m:
            if current:
                finish_current()
                nets.append(current)
            current = {
                "bssid": m.group(1),
                "ssid": "",
                "channel": None,
                "signal": None,
                "encryption": "OPEN",
                "wps": False,
                "pmf": "unknown",
                "_has_rsn": False,
                "_has_wpa": False,
                "_auth_suites": set(),
            }
            continue
        if not current:
            continue
        ssid = re.match(r"\s*SSID:\s*(.*)$", line)
        if ssid:
            current["ssid"] = ssid.group(1).strip() or "<hidden>"
        elif "signal:" in line:
            sig = re.search(r"-?\d+\.\d+", line)
            if sig:
                current["signal"] = float(sig.group(0))
        elif "DS Parameter set: channel" in line:
            ch = re.search(r"channel (\d+)", line)
            if ch:
                current["channel"] = int(ch.group(1))
        elif "RSN:" in line:
            current["_has_rsn"] = True
        elif "WPA:" in line and current["encryption"] == "OPEN":
            current["_has_wpa"] = True
        elif "WPS:" in line:
            current["wps"] = True
        elif "Authentication suites:" in line:
            suites = line.split("Authentication suites:", 1)[1]
            for suite in ("SAE", "OWE", "PSK", "802.1X", "802.1X/SHA-256",
                          "802.1X/SHA-384"):
                if suite in suites:
                    current["_auth_suites"].add(suite)
            if "FT/SAE" in suites:
                current["_auth_suites"].add("SAE")
            if "FT/PSK" in suites:
                current["_auth_suites"].add("PSK")
        elif ("MFPR" in line
              or "MFP-required" in line
              or "Management frame protection required" in line):
            current["pmf"] = "required"
        elif "MFPC" in line or "MFP-capable" in line:
            current["pmf"] = "capable"
    if current:
        finish_current()
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

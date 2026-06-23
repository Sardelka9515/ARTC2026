"""
Baseline security-config audit for a target AP.

Checks implemented (per project requirements):
  1. WPS disabled
  2. WPA3 or 802.1X enforced
  3. PMF (802.11w) enabled
  4. SSID broadcast policy
  5. Client isolation hint (cannot be detected passively; flagged as manual)
"""
from .scan import scan_networks


def audit_target(iface, bssid):
    nets = scan_networks(iface=iface, duration=8)
    target = next((n for n in nets if n["bssid"].lower() == bssid.lower()), None)

    report = {
        "bssid": bssid,
        "target_found": target is not None,
        "checks": [],
        "summary": "",
    }
    if not target:
        report["summary"] = "Target BSSID not visible in scan."
        return report

    def add(name, status, detail):
        report["checks"].append({"name": name, "status": status, "detail": detail})

    # 1. WPS
    add("WPS disabled",
        "FAIL" if target.get("wps") else "PASS",
        "WPS advertised in beacons." if target.get("wps")
        else "No WPS IE detected.")

    # 2. WPA3 / 802.1X
    enc = target.get("encryption", "OPEN")
    if enc == "WPA3":
        add("Strong auth (WPA3 / 802.1X)", "PASS", "WPA3-SAE in use.")
    elif enc == "WPA2-Enterprise":
        add("Strong auth (WPA3 / 802.1X)", "PASS", "802.1X authentication in use.")
    elif enc == "WPA3-Transition":
        add("Strong auth (WPA3 / 802.1X)", "WARN",
            "WPA3 transition mode detected; WPA2 clients may still connect.")
    elif enc in ("OPEN", "WPA"):
        add("Strong auth (WPA3 / 802.1X)", "FAIL",
            f"Weak/none encryption: {enc}")
    else:
        add("Strong auth (WPA3 / 802.1X)", "WARN",
            f"{enc} detected — upgrade to WPA3 or 802.1X recommended.")

    # 3. PMF / 802.11w
    pmf = target.get("pmf", "unknown")
    if pmf == "required":
        add("PMF (802.11w)", "PASS", "Management-frame protection required.")
    elif pmf == "capable":
        add("PMF (802.11w)", "WARN", "PMF capable but not required.")
    else:
        add("PMF (802.11w)", "FAIL", "PMF not advertised.")

    # 4. SSID broadcast
    hidden = target.get("ssid", "") in ("", "<hidden>")
    add("SSID broadcast policy",
        "PASS" if hidden else "INFO",
        "SSID is hidden/not broadcast."
        if hidden else f"SSID is broadcast as: {target['ssid']}")

    # 5. Client isolation — needs active probing
    add("Client isolation", "MANUAL",
        "Requires active L2 probe between two associated stations.")

    fails = sum(1 for c in report["checks"] if c["status"] == "FAIL")
    warns = sum(1 for c in report["checks"] if c["status"] == "WARN")
    report["summary"] = f"{fails} FAIL / {warns} WARN / {len(report['checks'])} checks"
    return report

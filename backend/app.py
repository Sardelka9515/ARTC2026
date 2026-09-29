"""
IoV Wi-Fi Security Testing Platform
Backend entry point (Flask + Socket.IO)

Project: 車聯網資安測試技術研究 (ARTC / NCU CSIE)
UN R155 / ISO-SAE 21434 oriented Wi-Fi security test UI skeleton.
"""
import os
import uuid
import threading
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

from modules.scan import scan_networks, interface_choices
from modules.attack_runner import AttackRunner
from modules.config_audit import AUDIT_CHECKS, audit_target
from modules.wids import WIDSMonitor
from modules.logger import TestLogger

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "frontend", "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config["SECRET_KEY"] = "iov-wifi-sec-dev-key"
# manage_session=False: this app keeps no Flask session state, and enabling it
# triggers a flask-socketio/Flask 3.x incompatibility ("property 'session' of
# 'RequestContext' object has no setter") that crashes the Socket.IO connect
# handler and blocks all live event pushes to the UI.
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                    manage_session=False)

# ---- singletons -------------------------------------------------------------
logger = TestLogger(os.path.join(BASE_DIR, "logs"))
runner = AttackRunner(socketio=socketio, logger=logger)
wids = WIDSMonitor(socketio=socketio, logger=logger)


# ---- interface contention guard --------------------------------------------
# wlan0 does double duty: recon scans it in *managed* mode, then WIDS flips it
# to *monitor* mode. A scan and WIDS must never hold the same adapter at once —
# WIDS toggling the mode mid-scan (or a scan racing WIDS capture) breaks both.
# Track which role holds each interface and refuse an overlapping claim.
_iface_lock = threading.Lock()
_iface_owner = {}  # iface -> "scan" | "wids"


def _claim_iface(iface, owner):
    """Atomically reserve `iface` for `owner`. Return the current holder if the
    interface is already busy (claim refused), else None (claim granted)."""
    with _iface_lock:
        held = _iface_owner.get(iface)
        if held is not None:
            return held
        _iface_owner[iface] = owner
        return None


def _release_iface(iface=None, owner=None):
    """Release a specific interface, or every interface held by a given owner."""
    with _iface_lock:
        if iface is not None:
            _iface_owner.pop(iface, None)
        if owner is not None:
            for held in [i for i, o in _iface_owner.items() if o == owner]:
                _iface_owner.pop(held, None)


# ---- page routes ------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/legacy")
def legacy():
    """Original tabbed dashboard."""
    return render_template("legacy.html")


@app.route("/flow")
def flow():
    """Flow-based pipeline view: runs Scan → Audit → Attack → WIDS in sequence."""
    return render_template("flow.html")


# ---- REST API ---------------------------------------------------------------
@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """List wireless interfaces available on the host."""
    from modules.scan import list_interfaces
    return jsonify(interface_choices(list_interfaces(), "scan"))


@app.route("/api/attack/interfaces", methods=["GET"])
def api_attack_interfaces():
    """List wireless interfaces for the deauth step, preferring the TP-Link (wlan1)."""
    from modules.scan import list_interfaces
    return jsonify(interface_choices(list_interfaces(), "deauth"))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Passive scan of nearby APs. Returns BSSID/SSID/channel/encryption."""
    data = request.get_json() or {}
    iface = data.get("interface", "wlan0")
    duration = int(data.get("duration", 10))
    held = _claim_iface(iface, "scan")
    if held:
        return jsonify({"ok": False,
                        "error": f"介面 {iface} 正由 {held.upper()} 使用中；請先停止該工作或改用其他介面。"}), 409
    try:
        results = scan_networks(iface=iface, duration=duration)
        logger.info("scan", f"Scanned {len(results)} networks on {iface}")
        return jsonify({"ok": True, "networks": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        _release_iface(iface=iface)


@app.route("/api/audit", methods=["POST"])
def api_audit():
    """
    Run baseline security-config audit on a target BSSID:
    WPS disabled?  WPA3/802.1X?  PMF (802.11w)?  SSID hidden?  Client isolation?
    """
    data = request.get_json() or {}
    bssid = data.get("bssid")
    iface = data.get("interface", "wlan0")
    if not bssid:
        return jsonify({"ok": False, "error": "bssid required"}), 400
    checks = data.get("checks")
    if checks is not None and (
        not isinstance(checks, list)
        or any(not isinstance(name, str) or name not in AUDIT_CHECKS for name in checks)
    ):
        return jsonify({"ok": False, "error": "Invalid audit checks"}), 400
    report = audit_target(iface, bssid, checks=checks)
    logger.info("audit", f"Audit {bssid}: {report['summary']}")
    return jsonify({"ok": True, "report": report})


@app.route("/api/attack/start", methods=["POST"])
def api_attack_start():
    """
    Launch an attack scenario. Streams output over Socket.IO room = job_id.
    Supported scenarios:
      - wifite_auto   : full wifite2 run against a target BSSID
      - deauth        : 802.11 deauth flood (aireplay-ng)
      - rogue_ap      : spawn Evil Twin (WiFi Pineapple over eth1; engine=pineapple)
      - wps_bruteforce: reaver/bully against WPS PIN
      - pmf_probe     : verify 802.11w handling
      - handshake_cap : capture WPA handshake
    """
    data = request.get_json() or {}
    scenario = data.get("scenario")
    params = data.get("params", {})
    if not scenario:
        return jsonify({"ok": False, "error": "scenario required"}), 400

    job_id = str(uuid.uuid4())[:8]
    try:
        runner.start(job_id, scenario, params)
        return jsonify({"ok": True, "job_id": job_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/attack/stop", methods=["POST"])
def api_attack_stop():
    data = request.get_json() or {}
    job_id = data.get("job_id")
    ok = runner.stop(job_id)
    return jsonify({"ok": ok})


@app.route("/api/attack/jobs", methods=["GET"])
def api_attack_jobs():
    return jsonify({"jobs": runner.list_jobs()})


@app.route("/api/wids/start", methods=["POST"])
def api_wids_start():
    data = request.get_json() or {}
    iface = data.get("interface", "")
    channel = data.get("channel")
    baseline = data.get("baseline")  # optional trusted [{bssid, ssid, channel}]
    # Reserve the adapter before touching its mode, so a scan can't be racing it.
    claimed = False
    if iface:
        held = _claim_iface(iface, "wids")
        if held and held != "wids":
            return jsonify({"ok": False,
                            "error": f"介面 {iface} 正由 {held.upper()} 使用中；請先停止該工作再啟動 WIDS。",
                            "status": wids.status()}), 409
        claimed = held is None  # True only when this call newly reserved it
    result = wids.start(iface, baseline=baseline, channel=channel,
                        scope=data.get("scope", "all"), target_bssid=data.get("target_bssid"))
    if not result["ok"] and claimed:
        _release_iface(iface=iface)  # our claim failed to start → release it
    return jsonify(result), (200 if result["ok"] else 400)


@app.route("/api/wids/stop", methods=["POST"])
def api_wids_stop():
    result = wids.stop()
    _release_iface(owner="wids")
    return jsonify(result), (200 if result["ok"] else 500)


@app.route("/api/wids/status", methods=["GET"])
def api_wids_status():
    return jsonify({"ok": True, "status": wids.status()})


@app.route("/api/wids/interfaces", methods=["GET"])
def api_wids_interfaces():
    """List real wireless interfaces, preferring the recon/WIDS adapter (wlan0)."""
    return jsonify(interface_choices(wids.list_interfaces(), "wids"))


@app.route("/api/logs", methods=["GET"])
def api_logs():
    limit = int(request.args.get("limit", 200))
    return jsonify({"logs": logger.tail(limit)})


# ---- Socket.IO --------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    emit("hello", {"msg": "connected to IoV Wi-Fi Sec backend"})


if __name__ == "__main__":
    print("[*] IoV Wi-Fi Security Testing Platform")
    print("[*] Listening on http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True,
                 allow_unsafe_werkzeug=True)

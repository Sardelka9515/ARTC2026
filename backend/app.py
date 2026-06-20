"""
IoV Wi-Fi Security Testing Platform
Backend entry point (Flask + Socket.IO)

Project: 車聯網資安測試技術研究 (ARTC / NCU CSIE)
UN R155 / ISO-SAE 21434 oriented Wi-Fi security test UI skeleton.
"""
import os
import uuid
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

from modules.scan import scan_networks
from modules.attack_runner import AttackRunner
from modules.config_audit import audit_target
from modules.wids import WIDSMonitor
from modules.logger import TestLogger

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "frontend", "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config["SECRET_KEY"] = "iov-wifi-sec-dev-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---- singletons -------------------------------------------------------------
logger = TestLogger(os.path.join(BASE_DIR, "logs"))
runner = AttackRunner(socketio=socketio, logger=logger)
wids = WIDSMonitor(socketio=socketio, logger=logger)


# ---- page routes ------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/flow")
def flow():
    """Flow-based pipeline view: runs Scan → Audit → Attack → WIDS in sequence."""
    return render_template("flow.html")


# ---- REST API ---------------------------------------------------------------
@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """List wireless interfaces available on the host."""
    from modules.scan import list_interfaces
    return jsonify({"interfaces": list_interfaces()})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Passive scan of nearby APs. Returns BSSID/SSID/channel/encryption."""
    data = request.get_json() or {}
    iface = data.get("interface", "wlan0")
    duration = int(data.get("duration", 10))
    try:
        results = scan_networks(iface=iface, duration=duration)
        logger.info("scan", f"Scanned {len(results)} networks on {iface}")
        return jsonify({"ok": True, "networks": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


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
    report = audit_target(iface, bssid)
    logger.info("audit", f"Audit {bssid}: {report['summary']}")
    return jsonify({"ok": True, "report": report})


@app.route("/api/attack/start", methods=["POST"])
def api_attack_start():
    """
    Launch an attack scenario. Streams output over Socket.IO room = job_id.
    Supported scenarios:
      - wifite_auto   : full wifite2 run against a target BSSID
      - deauth        : 802.11 deauth flood (aireplay-ng)
      - rogue_ap      : spawn Evil Twin (hostapd)
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
    iface = data.get("interface", "wlan0mon")
    wids.start(iface)
    return jsonify({"ok": True})


@app.route("/api/wids/stop", methods=["POST"])
def api_wids_stop():
    wids.stop()
    return jsonify({"ok": True})


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

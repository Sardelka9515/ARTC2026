import sys, time
import os
# repo/backend derived from this script's location (docs/testing-scripts/../../backend),
# overridable with REPO=/path/to/repo
_repo = os.environ.get('REPO') or os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(_repo, 'backend'))
from modules import wids as widsmod

IFACE = sys.argv[1] if len(sys.argv) > 1 else "wlx90de80e1832b"
events = []
frames = {"n": 0}

class SIO:
    def emit(self, ev, data, namespace=None): events.append(data)
class LOG:
    def info(self, tag, msg): print(f"  [{tag}] {msg}")
    def error(self, tag, msg): print(f"  [{tag}] ERROR: {msg}")

m = widsmod.WIDSMonitor(socketio=SIO(), logger=LOG())
# count real dispatched observations
orig = m._dispatch
def counting(obs):
    frames["n"] += 1
    return orig(obs)
m._dispatch = counting
print(f"Starting WIDS on {IFACE} for 15s ...")
result = m.start(IFACE)
print("start_result:", result)
if not result["ok"]:
    print("VERDICT: FAILED_TO_START_REAL_CAPTURE")
    raise SystemExit(1)
time.sleep(15)
m.stop()
time.sleep(1.5)

print("---- RESULT ----")
print("real_frames_dispatched:", frames["n"])
print("events_emitted:", len(events))
for e in events[:25]:
    print("  EVT:", e.get("severity"), "|", e.get("category"), "|", e.get("type"), "|", e.get("message"))
print("VERDICT:", "WIDS_REAL_CAPTURE_OK" if frames["n"] > 0 else "NO_REAL_FRAMES")

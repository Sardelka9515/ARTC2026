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
fell_back = {"v": False}

class SIO:
    def emit(self, ev, data, namespace=None): events.append(data)
class LOG:
    def info(self, tag, msg): print(f"  [{tag}] {msg}")

m = widsmod.WIDSMonitor(socketio=SIO(), logger=LOG())
# count real dispatched observations
orig = m._dispatch
def counting(obs):
    frames["n"] += 1
    return orig(obs)
m._dispatch = counting
# guard: detect silent fallback to simulated loop
def no_sim():
    fell_back["v"] = True
    print("  !! FELL BACK TO SIMULATED LOOP (real capture failed)")
m._simulated_loop = no_sim

print(f"Starting WIDS on {IFACE} for 15s ...")
m.start(IFACE)
time.sleep(15)
m.stop()
time.sleep(1.5)

print("---- RESULT ----")
print("fell_back_to_simulated:", fell_back["v"])
print("real_frames_dispatched:", frames["n"])
print("events_emitted:", len(events))
for e in events[:25]:
    print("  EVT:", e.get("severity"), "|", e.get("category"), "|", e.get("type"), "|", e.get("message"))
print("VERDICT:", "WIDS_REAL_CAPTURE_OK" if (not fell_back["v"] and frames["n"] > 0) else "FAILED")

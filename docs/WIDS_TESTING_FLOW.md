# WIDS Hardware Testing Flow — Runbook

End-to-end procedure to validate the WIDS engine (`backend/modules/wids.py`) on
real hardware, with the helper scripts under [`docs/testing-scripts/`](testing-scripts/).
Background, root-cause analysis, and results are in
[`WIDS_HARDWARE_TESTING.md`](WIDS_HARDWARE_TESTING.md); this file is the "how to run it".

> All privileged steps need `sudo` (raw sockets, module load, monitor mode).
> Scripts read `WORK` (build/output dir, default `~/wids-aic8800`) and `REPO`
> (repo root, auto-derived). Driver build/DKMS lives under `$WORK`.

## Hardware roles

| Role | Adapter | Interface | Why |
|---|---|---|---|
| **WIDS monitor / capture** | Realtek RTL8821CU (`rtw88_8821cu`, mac80211) | `wlx90de80e1832b` (phy0) | monitor RX delivers real 802.11 frames |
| **Attack injector** (demo) | AIC8800DC (FullMAC) | `wlxec750c0bb89d` (phy5) | monitor TX injects (intermittently); RX delivers nothing |

The AIC8800DC is the chip we brought up (report focus); it works as a normal
client but is **not** the WIDS sniffer. A dedicated `ath9k_htc` (AR9271) is the
recommended injector for a reliable attack demo.

---

## Phase 0 — Prerequisites (one-time)

- Kernel headers for the running kernel; **Secure Boot disabled** (unsigned .ko).
- Toolchain: `sudo apt install -y build-essential dkms iw usb-modeswitch python3-scapy aircrack-ng`
- App deps for root: `sudo apt install -y python3-flask python3-flask-socketio`
  (scapy is system `python3-scapy`; the repo's `.venv` is a stale Windows venv — ignore).

## Phase 1 — AIC8800DC driver bring-up

The chip reports `chip_id=7, chip_sub_id=1` (legacy MCU rev 1) and needs the
**V3** firmware/loader, not the V5 that most trees ship (see §8–9 of the
hardware doc). Use `shenmintao/aic8800d80` branch `legacy-mcu1`:

```bash
git clone -b legacy-mcu1 https://github.com/shenmintao/aic8800d80 $WORK/shenmintao-legacy-mcu1
cd $WORK/shenmintao-legacy-mcu1 && sudo ./install.sh   # DKMS build + fw + udev rules
# then PHYSICALLY unplug the dongle >=10s and replug (bootrom/DPD flash reset)
```

Verify it came up (interface created, no `err_lmac`/timeout):

```bash
sudo docs/testing-scripts/5_verify_mcu1.sh
```

Diagnostic (only if bring-up fails) — capture the full clean probe log:

```bash
sudo docs/testing-scripts/4_clean_capture.sh   # writes $WORK/clean_dmesg.txt
```

**Expected:** firmware md5 `bfd8ea1d…` (legacy V3), `HT/VHT/HE supp 1`, a new
`wlx…` interface for the AIC.

## Phase 2 — Prepare the WIDS capture adapter (Realtek)

rtw88 monitor goes **deaf after an in-place `iw set type monitor` toggle**, so the
setup script **reloads the module** for a clean monitor, then sets monitor + ch6:

```bash
sudo docs/testing-scripts/setup_flow_env.sh
```

Confirm it captures real ambient traffic:

```bash
sudo docs/testing-scripts/7_monitor_test_rtl.sh   # scapy sniff; expect beacons/probes
```

**Expected:** `MONITOR_WORKS` with a nonzero frame count; dmesg shows
`entered promiscuous mode`.

## Phase 3 — WIDS engine on real capture (headless)

Runs the actual `WIDSMonitor` against the monitor interface, with a guard that
flags the silent simulated-fallback:

```bash
sudo docs/testing-scripts/8_run_wids_integration.sh
```

**Expected:** `VERDICT: WIDS_REAL_CAPTURE_OK`, `fell_back_to_simulated: False`,
nonzero `real_frames_dispatched`.

## Phase 4 — Web UI

```bash
cd <repo> && sudo python3 backend/app.py        # MUST be root, or capture silently simulates
```

Open `http://localhost:5000` → **WIDS Monitor** tab → set interface to
`wlx90de80e1832b` → **Start**. `/api/wids/start` returns 200 and real capture
runs (quiet on clean traffic thanks to the broadcast-frame filter).

## Phase 5 — Live attack-detection demo

With WIDS running in the app, inject a deauth burst from the AIC; the Realtek
captures it and WIDS raises a **`deauth_flood`** (HIGH/dos) in the UI:

```bash
sudo docs/testing-scripts/inject_deauth_from_aic.sh
```

Verify the AIC→Realtek path (parallel sniff prints `REACHED`/`NOT REACHED`) if the
alert doesn't appear — AIC injection is intermittent:

```bash
sudo docs/testing-scripts/12_tx_rx_deauth_diag.sh   # or 13_relive_demo.sh (tight re-assert)
```

**Expected:** one `deauth_flood` alert per burst (debounced — was one-per-frame
before the fix), source `DE:AD:BE:EF:00:01`.

---

## Script inventory (`docs/testing-scripts/`)

| Script | Phase | Purpose |
|---|---|---|
| `5_verify_mcu1.sh` | 1 | Verify AIC8800DC came up after the legacy-mcu1 install |
| `4_clean_capture.sh` | 1 | Capture full clean probe dmesg (bring-up diagnostic) |
| `setup_flow_env.sh` | 2 | Reload rtw88 → clean Realtek monitor on ch6 |
| `7_monitor_test_rtl.sh` | 2 | Confirm Realtek monitor captures real frames (scapy) |
| `8_run_wids_integration.sh` + `8_wids_integration.py` | 3 | Drive real `wids.py` on the monitor iface, with fallback guard |
| `inject_deauth.py` | 5 | Deauth-frame injector (helper; takes iface, count) |
| `inject_deauth_from_aic.sh` | 5 | Set AIC→monitor ch6 and inject a deauth burst |
| `12_tx_rx_deauth_diag.sh` | 5 | Parallel-sniff proof that AIC deauths reach the Realtek |
| `13_relive_demo.sh` | 5 | Tight channel re-assert + inject (for a clean live run) |

Path conventions: scripts use `WORK` (default `~/wids-aic8800`) for the driver
build tree and captured logs, and `REPO` (auto-derived) for the app.

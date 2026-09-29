# TODO — issues found while wiring the fixed 3-radio bench setup

Bench mapping: `wlan0` (MediaTek) = recon + WIDS · `wlan1` (TP-Link) = deauth ·
`eth1` = REST link to the WiFi Pineapple (evil twin).

## Fixed in this change
- [x] **WIDS auto-selected the wrong adapter.** `interface_choices` mapped
  `wids` → TP-Link; now pinned to `wlan0` (reuses the recon radio).
  (`backend/modules/scan.py`)
- [x] **Deauth reused the recon/WIDS radio.** The flow sent `interface:
  ctx.iface` (wlan0) for deauth, colliding with WIDS on wlan0. Added a dedicated
  deauth interface (`#attack-iface`, default wlan1) and `GET
  /api/attack/interfaces`. (`flow.js`, `flow.html`, `index.html`, `app.py`)
- [x] **Evil twin could fall back to local hostapd.** `rogue_ap` is now
  Pineapple-only: the local `hostapd` scenario was removed and `start()` rejects
  `rogue_ap` unless `engine == "pineapple"`. (`attack_runner.py`)

## Still open — need hardware/bench validation
- [ ] **Local deauth needs monitor mode.** `aireplay-ng --deauth ... {interface}`
  (`attack_runner.py`) needs wlan1 in monitor mode. The raw-aireplay path does
  not enable it (only wifite `--kill` self-manages). Add an explicit
  monitor-mode prep for wlan1, or document the manual `airmon-ng start wlan1`
  step. Likely runtime failure otherwise.
- [x] **wlan0 mode contention.** Recon holds wlan0 in managed mode; WIDS flips it
  to monitor, so a scan and WIDS must never hold the same adapter at once. Added
  an interface-reservation guard in `backend/app.py` (`_claim_iface`/
  `_release_iface`): `/api/scan` reserves the adapter for the scan's duration and
  `/api/wids/start` reserves it for the WIDS session; an overlapping claim on the
  same interface is refused with HTTP 409, while different interfaces (e.g. wlan1
  deauth) never contend. Covered by `tests/test_iface_contention.py`.
- [ ] **Pineapple not configured out of the box.** Only
  `configs/pineapple.example.json` exists; real deauth/evil-twin needs
  `configs/pineapple.local.json` (see `docs/PINEAPPLE_SETUP_ZH.md`). Add a setup
  check / clearer first-run error.
- [ ] **`test_pineapple` can't run on Windows.** `scripts/pineapple.py` imports
  `fcntl` (Unix-only), so the test errors on import off the Linux bench. Consider
  guarding the import or skipping the test on non-POSIX platforms.

## Notes / possible enhancements
- Recon channel scope: `scan_networks()` does a full `iw dev scan` or a
  single-channel passive scapy sniff (no channel hopping). Confirmed with the
  user that "(1,2,3,4)" refers to spec 檢測項目 1–4, not channels — no change
  needed, but a passive sniff still only sees the current channel.

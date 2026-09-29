# IoV Wi-Fi Security Testing Platform (Skeleton)

Web-based UI skeleton for the NCU CSIE × ARTC project
**「車聯網資安測試技術研究」** (115年度 / UN R155 compliance).

This is a starting scaffold. Attack scenarios can still provide development
fallback output when their external tools are unavailable. WIDS is deliberately
real-capture-only: it reports a startup error instead of manufacturing security
events when monitor-mode capture is unavailable.

## Architecture

```
┌─────────────── Browser (Dashboard) ───────────────┐
│   Scan · Audit · Attack · WIDS · Logs             │
└──────────────┬──────────────────┬─────────────────┘
               │ REST             │ Socket.IO (live)
┌──────────────▼──────────────────▼─────────────────┐
│                 Flask backend                     │
│  ┌─────────┐ ┌───────────┐ ┌────────┐ ┌────────┐  │
│  │  scan   │ │  audit    │ │ runner │ │ wids   │  │
│  │ (iw)    │ │ (config)  │ │wifite2 │ │ scapy  │  │
│  └─────────┘ └───────────┘ └────────┘ └────────┘  │
│                   TestLogger (JSONL)              │
└───────────────────────────────────────────────────┘
                        │
              ┌─────────▼──────────┐
              │ ARTC T-BOX bench   │
              └────────────────────┘
```

## Features mapped to project spec

| Spec item | Where |
|---|---|
| WPS disabled check | `modules/config_audit.py` |
| WPA3 / 802.1X enforcement | `config_audit.py` |
| PMF (802.11w) verify | `audit` + `pmf_probe` scenario |
| SSID broadcast / hidden | `config_audit.py` |
| Deauth attack simulation | `attack_runner.py` → `deauth` |
| Rogue AP / Evil Twin | `attack_runner.py` → `rogue_ap` |
| WPS brute-force test | `attack_runner.py` → `wps_bruteforce` |
| Handshake capture | `attack_runner.py` → `handshake_cap` |
| wifite2 automated audit | `attack_runner.py` → `wifite_auto` |
| WIDS (retrans/handshake/rogue) | `modules/wids.py` |
| Full logging for audit trail | `modules/logger.py` (JSONL) |

## Run

```bash
pip install -r requirements.txt
cd backend
python app.py
# open http://localhost:5000
```

## Bench interface layout (fixed 3-radio setup)

The platform is wired for a fixed three-interface bench, each pinned to one role:

| Interface | Hardware        | Role                                             |
|-----------|-----------------|--------------------------------------------------|
| `wlan0`   | MediaTek        | Recon / scan (spec 檢測項目 1–4), then **reused** for WIDS monitor |
| `wlan1`   | TP-Link         | Deauth (aireplay-ng, local engine)               |
| `eth1`    | WiFi Pineapple  | Evil Twin — driven over the Pineapple REST API; **no local hostapd** |

`wlan0` does double duty: it runs recon first, then flips to monitor mode for
WIDS. `wlan1` fires deauth and the Pineapple broadcasts the evil twin
concurrently, so WIDS on `wlan0` can observe both. Role→interface defaults live
in `interface_choices()` (`backend/modules/scan.py`); the deauth radio is chosen
via `GET /api/attack/interfaces`. Evil Twin (`rogue_ap`) runs on the Pineapple
engine only.

## Install the real tooling (Kali / Parrot recommended)

```bash
sudo apt install aircrack-ng reaver bully hcxdumptool  # hostapd not needed: evil twin runs on the Pineapple
git clone https://github.com/kimocoder/wifite2
cd wifite2 && sudo python setup.py install
pip install scapy
```

## Safety

⚠ Only run attack scenarios against:
- The ARTC T-BOX test bench
- Lab APs you own
- Targets explicitly authorised in writing

All activity is logged to `logs/testing.jsonl` for audit (ISO 21434 traceability).

## TODO / next milestones

- [ ] Parse `wifite2` structured results (cracked.txt, *.cap)
- [ ] Add scenario: DragonBlood (WPA3 SAE side-channel)
- [ ] Add scenario: Downgrade attack detection
- [ ] Integrate scapy-based real deauth-reason-code classifier in WIDS
- [ ] Add role-based auth for the web UI
- [ ] Export report → PDF (UN R155 evidence package)

## WiFi Pineapple Mark VII

Item 28's Evil Twin always runs on the USB-connected Pineapple (over `eth1`) via
its REST API; deauth stays local on `wlan1`. There is no local hostapd evil-twin.
Start with `configs/pineapple.example.json` and the Traditional Chinese guide:
[USB / VM setup, test configuration, WIDS baseline and recovery](docs/PINEAPPLE_SETUP_ZH.md).
The controller is `scripts/pineapple.py`; `plan` is offline, and hardware operation
requires a configured local file and explicit enablement. Hardware validation is pending.

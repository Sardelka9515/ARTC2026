# IoV Wi-Fi Security Testing Platform (Skeleton)

Web-based UI skeleton for the NCU CSIE × ARTC project
**「車聯網資安測試技術研究」** (115年度 / UN R155 compliance).

This is a starting scaffold — all backend modules gracefully fall back
to simulated output when the underlying tools (`wifite2`, `aircrack-ng`,
`reaver`, `hostapd`, `scapy`) are not present, so you can develop the UI
on any machine and deploy to the Kali/Parrot test bench later.

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

## Install the real tooling (Kali / Parrot recommended)

```bash
sudo apt install aircrack-ng reaver bully hostapd hcxdumptool
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

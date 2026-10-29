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
| Item 5: WPA2/3-Enterprise + 802.1X | `config_audit.py` |
| PMF (802.11w) verify | `audit` + `pmf_probe` scenario |
| SSID broadcast / hidden | `config_audit.py` |
| Deauth attack simulation | `attack_runner.py` → `deauth` |
| Rogue AP / Evil Twin | `attack_runner.py` → `rogue_ap` |
| WPS brute-force test | `attack_runner.py` → `wps_bruteforce` |
| Handshake capture | `attack_runner.py` → `handshake_cap` |
| wifite2 automated audit | `attack_runner.py` → `wifite_auto` |
| WIDS (retrans/handshake/rogue) | `modules/wids.py` |
| Full logging for audit trail | `modules/logger.py` (JSONL) |

## 完整啟動流程

以下命令均從專案根目錄執行：

```bash
cd /home/kali/ARTC2026
```

### 1. 第一次使用：安裝依賴

```bash
sudo apt update
sudo apt install -y aircrack-ng iw iproute2 reaver bully hcxdumptool
./tboxvenv/bin/pip install -r requirements.txt scapy
```

### 2. 確認硬體介面

接妥兩張無線網卡及 WiFi Pineapple 後執行：

```bash
iw dev
ip -br link
ip -br addr
```

預設分工如下；實際名稱不同時，可在網頁中重新選擇：

| 預設介面 | 設備 | 用途 |
|---|---|---|
| `wlan0` | MediaTek | Recon，完成後切換為 WIDS |
| `wlan1` | TP-Link | 有限次數 Deauth 測試 |
| `eth1` | WiFi Pineapple USB Ethernet | Pineapple REST 管理及 Evil Twin |

### 3. 設定 WiFi Pineapple

尚未建立本機設定檔時：

```bash
cp configs/pineapple.example.json configs/pineapple.local.json
chmod 600 configs/pineapple.local.json
```

編輯 `configs/pineapple.local.json`，至少確認：

```json
{
  "enabled": true,
  "base_url": "http://172.16.42.1:1471",
  "management_interface": "eth1",
  "password_env": "PINEAPPLE_PASSWORD",
  "target": {
    "client_mac": "受測 STA MAC（僅 Pineapple deauth 使用）"
  },
  "evil_twin": {
    "duration_seconds": 15
  }
}
```

- Evil Twin 的 BSSID、SSID 與頻道都由網頁目前選定的測試目標傳入，不固定寫在 JSON。
- Pineapple 密碼不可寫入 JSON。

### 4. 每次啟動前：準備網卡

停止可能干擾 monitor mode 的程序：

```bash
sudo airmon-ng check kill
sudo ip link set wlan0 up
sudo ip link set wlan1 up
```

`airmon-ng check kill` 會停止 NetworkManager，因此需手動設定 Pineapple 管理介面：

```bash
sudo ip link set eth1 up
sudo ip addr replace 172.16.42.42/24 dev eth1
ip route get 172.16.42.1
```

路由檢查結果必須包含 `dev eth1`；若 Pineapple 介面名稱不同，請同步替換上述命令與 JSON 設定。

### 5. 輸入 Pineapple 密碼並檢查連線

```bash
read -rs 'PINEAPPLE_PASSWORD?Pineapple password: '
export PINEAPPLE_PASSWORD
export PINEAPPLE_CONFIG="$PWD/configs/pineapple.local.json"
```

先執行唯讀檢查。此命令會驗證路由、登入及 PineAP settings API，但不會啟動 Evil Twin：

```bash
sudo --preserve-env=PINEAPPLE_PASSWORD,PINEAPPLE_CONFIG \
  ./tboxvenv/bin/python3 scripts/pineapple.py check
```

看到 `"connected": true` 後再啟動平台。

### 6. 啟動平台

```bash
sudo --preserve-env=PINEAPPLE_PASSWORD,PINEAPPLE_CONFIG \
  ./tboxvenv/bin/python3 backend/app.py
```

重新開機後環境變數會消失。若 `enabled` 為 `true` 且未先匯出密碼，互動式啟動會在
後端終端提示一次 Pineapple 密碼；非互動式啟動則會立即報錯。網頁啟動的工作不會
讀取終端輸入，因此不會再因等待隱藏的密碼提示而於 120 秒後逾時。

瀏覽器開啟：

```text
http://127.0.0.1:5000
```

網頁中確認：

1. Recon 介面選擇 `wlan0`。
2. 掃描並選擇受測 AP。
3. WIDS 介面選擇 `wlan0`。
4. Deauth 介面選擇 `wlan1`。
5. Pineapple 管理介面選擇 `eth1`。
6. 勾選需要的測項並按下「開始檢測」。

### 7. 停止與恢復網路

先在終端按 `Ctrl+C` 停止後端，再恢復 NetworkManager：

```bash
sudo systemctl restart NetworkManager
```

若 Pineapple 測試遭到強制中斷且留下 recovery 檔，重新接妥裝置後執行：

```bash
sudo --preserve-env=PINEAPPLE_PASSWORD,PINEAPPLE_CONFIG \
  ./tboxvenv/bin/python3 scripts/pineapple.py restore
```

## Bench interface layout (fixed 3-radio setup)

The platform is wired for a fixed three-interface bench, each pinned to one role:

| Interface | Hardware        | Role                                             |
|-----------|-----------------|--------------------------------------------------|
| `wlan0`   | MediaTek        | Recon / scan (spec 檢測項目 1–4), then **reused** for WIDS monitor |
| `wlan1`   | TP-Link         | Deauth (aireplay-ng, local engine)               |
| `eth1`    | WiFi Pineapple  | Evil Twin — driven over the Pineapple REST API; **no local hostapd** |

`wlan0` does double duty: it runs recon first, then flips to monitor mode for
WIDS and stays active through item 28. `wlan1` fires the finite deauth probe and
the Pineapple broadcasts a same-SSID/same-BSSID clone, so WIDS on `wlan0` can
observe both. Role→interface defaults live
in `interface_choices()` (`backend/modules/scan.py`); the deauth radio is chosen
via `GET /api/attack/interfaces`. Evil Twin (`rogue_ap`) runs on the Pineapple
engine only.

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
The controller is `scripts/pineapple.py`; the management link is user-selectable
(default `eth1`) and is route-checked before credentials are sent. `plan` is offline, and hardware operation
requires a configured local file and explicit enablement. Hardware validation is pending.

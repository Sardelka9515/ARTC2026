# WiFi Pineapple Mark VII：VM 接線與檢測設定

本專案已加入 `scripts/pineapple.py`，透過 USB Ethernet 上的官方 REST API 控制 Pineapple；Python 僅使用標準函式庫。首頁第 28 項可選 Pineapple 或原本的本機工具。

已確認本次 VM 可連到實機管理頁；登入後的韌體 API 格式、無線傳送與 WIDS 實際告警仍待驗證。

本次接入紀錄：

- VM 管理介面為 `eth1`，DHCP 位址為 `172.16.42.248/24`；重新連接後位址可能改變。
- `http://172.16.42.1:1471/` 回應 HTTP 200，頁面標題為 WiFi Pineapple。
- 未登入讀取 `/api/pineap/settings` 回應 HTTP 401；後續使用者執行 `check` 已通過登入，原腳本在 settings 格式檢查失敗。
- 已核對實機管理頁程式：settings API 使用 `{mode, settings}` 包裝，自動啟動欄位為 `autostartPineAP`。腳本已加入此格式的讀寫相容處理，保留原模式及額外設定供復原；待重新執行實機 `check` 確認。
- 已建立 `configs/pineapple.local.json`（權限 `0600`），現有腳本與後端會預設讀取此檔。測試目標尚未填入，`enabled` 保持 `false`。
- 現有 Pineapple 整合的 15 項模擬測試通過；這不代表實機無線測試通過。

下一步從專案根目錄執行 `python3 scripts/pineapple.py check`，在本機終端依提示輸入管理密碼。

## 1. 拓樸與本次支援範圍

```text
VM ── USB Ethernet ── Pineapple VII（測試訊框發送）
 │                            )))
 └── 獨立 monitor-mode 網卡   )))  合法測試 AP ↔ 受測 T-BOX／測試 STA
       （WIDS 接收）
```

- `deauth`：對設定的合法 AP 與單一測試 STA 送出有限次數的解除認證請求，供 DoS／PMF 檢測使用。不是 RF 干擾器，也不保證 PMF 受保護的連線會中斷。
- `evil-twin`：使用相同 SSID、不同 BSSID，定時廣播供 Rogue AP 偵測。這是同名熱點的**偵測測試**，不包含完整 WPA2/WPA3 接入複製、釣魚登入頁、帳密蒐集或 MAC 複製攻擊。廣播測試不要求 T-BOX 實際連入。
- 第 9 項的非法握手與重傳偵測是另一組偵測器；deauth 不必然產生這兩種事件。
- 此設定範本限定 2.4 GHz 頻道；先使用測試 AP 的合法固定頻道（例如 6）。
- 用於本專案的 ARTC 實驗設備／已授權測試網路。設定中的 AP、SSID 與 STA 應為同一組測試對象。

Pineapple 插入 VM 後呈現的是 Ethernet 管理介面，不會直接成為本專案 Scapy 所需的無線監聽介面。[官方接線說明](https://documentation.hak5.org/wifi-pineapple/setup/connecting-the-wifi-pineapple)

## 2. USB 接到 VM

1. 先接妥天線，再用可傳輸資料的 USB 線接上 Pineapple。
2. 在虛擬化軟體將 Pineapple USB 裝置交給 VM。若使用 VMware，可從 VM 的 Removable Devices 選擇 Connect；重新插拔後需確認仍由 VM 持有。
3. VM 內執行 `ip -br link`、`ip -br addr`，找出新增的 USB Ethernet（可能是 `enx...`，不要把原本 NAT 網卡當成 Pineapple）。
4. 在 NetworkManager 把該介面的 IPv4 設為 `172.16.42.42/24`，不填 gateway。保留 VM 原本的 NAT／Internet 連線。[官方 Linux 設定](https://documentation.hak5.org/wifi-pineapple/setup/connecting-to-the-wifi-pineapple-on-linux)
5. 在 VM 瀏覽器開啟 `http://172.16.42.1:1471`，完成初次設定並設定 root 密碼。[官方管理頁說明](https://documentation.hak5.org/wifi-pineapple/ui-overview/introduction)
6. 記錄韌體版本。在 Pineapple 管理頁停止 PineAP、關閉自動啟動；備份需要的 SSID pool 後自行清空。控制器不會清除既有的無關 SSID。

若位址無法連線，先確認 USB passthrough、VM IPv4 與路由，而不是改 Wi-Fi 攻擊設定。若裝置管理位址已改過，同步更改下列 `base_url`。

## 3. 補齊設定檔

以下命令皆從專案根目錄執行：

```bash
cp configs/pineapple.example.json configs/pineapple.local.json
chmod 600 configs/pineapple.local.json
```

編輯 `configs/pineapple.local.json`：

| 欄位 | 需要填入的內容 |
|---|---|
| `enabled` | 全部確認後才設為 `true`；預設 `false` |
| `base_url` | Pineapple 管理頁位址，預設 `http://172.16.42.1:1471` |
| `username` | 預設 `root` |
| `password_env` | 保存密碼的環境變數名稱，預設 `PINEAPPLE_PASSWORD`；不是密碼本身 |
| `target.bssid` | 合法測試 AP 的 BSSID，須與首頁選擇相同 |
| `target.ssid` | 合法 AP 的完整 SSID，大小寫與空白必須一致 |
| `target.channel` | 合法 AP、Pineapple 測試與 WIDS 共同使用的頻道 |
| `target.client_mac` | 已連上合法 AP 的測試 STA／T-BOX MAC，注意裝置的隨機 MAC 設定 |
| `evil_twin.bssid` | 不同於合法 AP 的測試 BSSID；範本為 `02:00:00:00:28:01`，須確認無位址衝突 |
| `evil_twin.duration_seconds` | 同名熱點廣播時間，預設 15 秒，最多 30 秒 |
| `deauth.bursts` | API 請求次數，預設 5，最多 10 |
| `deauth.interval_seconds` | 請求間隔，預設 1 秒 |
| `deauth.multiplier` | 裝置 API 的 multiplier，預設 1；不是精確的實體封包數 |

本機設定檔、復原檔及鎖檔已加入 `.gitignore`。密碼不寫入 JSON，不會放進命令列、瀏覽器或日誌。

先離線預覽，不需 Pineapple：

```bash
python3 scripts/pineapple.py plan --config configs/pineapple.local.json
```

連上裝置後檢查登入及 settings API（不啟動測試）：

```bash
python3 scripts/pineapple.py check --config configs/pineapple.local.json
```

互動終端會隱藏輸入密碼。腳本支援公開文件的平面 `AutoStart` 格式，以及本次實機前端使用的 `{mode, settings}`／`autostartPineAP` 格式。若仍出現 settings 格式錯誤，需再核對韌體版本與回應欄位，不要把它當成檢測通過。

若登入回傳 HTTP 400／401，本次實機管理頁將其視為帳密無效；`root` 是帳號，密碼需使用裝置設定時建立的管理密碼。先確認相同帳密可登入管理頁。腳本優先讀取環境變數，若曾保存舊密碼，可執行 `env -u PINEAPPLE_PASSWORD python3 scripts/pineapple.py check`，改由互動終端重新輸入（自訂 `password_env` 時請替換變數名稱）。

## 4. 啟動 Web 後端並傳入登入資料

後端啟動前，在同一個終端設定環境變數。以下可用於此專案的 zsh：

```zsh
read -rs 'PINEAPPLE_PASSWORD?Pineapple 密碼：'
export PINEAPPLE_PASSWORD
export PINEAPPLE_CONFIG="$PWD/configs/pineapple.local.json"
tboxvenv/bin/python backend/app.py
```

若已由 IDE、服務或另一個終端啟動後端，必須在**該程序的啟動環境**設定變數後重新啟動；在不相關終端 export 不會改變已執行程序。WIDS 的無線擷取權限沿用原專案設定。

不要將目前未加入登入驗證的專案控制 API 暴露到不受信任網路。

## 5. WIDS 與實際執行順序

本次雙網卡分工為 MediaTek 掃描（目前 `wlan1`）、TP-Link WIDS（目前 `wlan0`）。首頁會依 USB 廠商 ID 預選對應介面，並在選單顯示品牌；介面名稱改變後仍依硬體辨識，可手動調整。未發現 AP 時顯示空結果，不產生示範 AP 或虛構介面。

1. 先讓合法測試 AP 固定頻道，確認測試 STA 已連上它；此時 Pineapple 不廣播測試 SSID。
2. 首頁掃描並選擇合法 AP，確保 BSSID／SSID／channel 與 JSON 相同。
3. 右側 WIDS 選擇 VM 的**獨立無線監聽介面**與相同頻道，手動按「啟動」。選定的合法 AP 會作為信任基準。沒有基準時，同名 SSID 的 Evil Twin 檢查不會生效。
4. 等待 WIDS 顯示監聽中，確認 frames 增加；不是只看到 REST 連線成功就算完成。
5. 將 JSON 的 `enabled` 改為 `true`。首頁「第 28 項攻擊裝置」選 WiFi Pineapple VII，第一次可只勾第 28 項，按「開始檢測」。會依序執行 deauth、同名 SSID 廣播。前一段失敗或停止時，不繼續後一段。
6. 保持右側 WIDS 手動啟動狀態，觀察 `deauth_flood`、`evil_twin` 等事件。第 5／8／9 項的流程觀測窗本來在第 28 項之前；那些先前結果不會回溯更新成攻擊後的結果，**本次攻擊證據請看右側即時事件及日誌**。
7. 完成後確認 PineAP 已還原，再停止 WIDS。紀錄 AP／STA、頻道、時間、Pineapple 工作結果、WIDS 告警與受測端是否斷線。

也可以分開用 CLI 執行，方便逐項驗證（WIDS 仍需事先啟動）：

```bash
python3 scripts/pineapple.py deauth --config configs/pineapple.local.json --execute
python3 scripts/pineapple.py evil-twin --config configs/pineapple.local.json --execute
```

未加 `--execute` 只會預覽。API 接受命令不等於實際 RF 傳送成功，也不等於 T-BOX 防護失敗。

本專案的 deauth 告警門檻目前為 5 秒內 20 個訊框；小型測試未觸發告警時，先確認實際捕獲訊框、頻道及 PMF 狀態，不能由 API multiplier 推算接收到的封包數。Evil Twin 測試若無告警，先確認合法 AP 信任基準、SSID 與 Pineapple 廣播訊框。

## 6. 停止與故障復原

- CLI 按 Ctrl+C，或首頁按「停止攻擊測試」：停止後續 deauth 請求；Evil Twin 會嘗試還原原設定與移除本次 SSID。
- 每次 Evil Twin 變更前保存 `configs/pineapple.local.recovery.json`。若還原失敗或程序被強制終止，會保留此檔，禁止下一次測試直接覆蓋它。
- **USB 拔除、VM 當機或強制殺掉程序時，VM 上的計時器無法停止仍有電的 Pineapple。** 需從管理頁停用 PineAP，或停止裝置供電；恢復管理連線後執行下列復原命令，不可只刪掉復原檔：

```bash
python3 scripts/pineapple.py restore --config configs/pineapple.local.json
python3 scripts/pineapple.py check --config configs/pineapple.local.json
```

`restore` 不要求 `enabled=true`；復原時請使用原本的設定檔與裝置位址。操作期間不要同時從 Pineapple 管理頁修改 PineAP 設定，也不要以不同設定檔同時控制同一台裝置。

目前使用的是本機計時與還原，尚未提供裝置端 watchdog。正式長時間無人值守前需另行完成此項實機整合。

## 官方 API 依據

- [登入與 Bearer token](https://hak5.github.io/mk7-docs/docs/rest/authentication/authentication/)
- [PineAP settings、SSID pool 與定向 deauth](https://hak5.github.io/mk7-docs/docs/rest/pineap/pineap/)

尚待填寫／確認：VM USB 介面名稱、Pineapple 韌體版本與管理密碼、合法 AP BSSID／SSID／頻道、測試 STA MAC、WIDS 網卡 monitor-mode 能力，以及實機 RF 告警結果。

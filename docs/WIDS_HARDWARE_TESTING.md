# WIDS Real-Hardware Bring-up — Session Notes & Solution Options

**Date:** 2026-08-25/26
**Goal:** Test the WIDS implementation (`backend/modules/wids.py`) on real hardware.
WIDS needs a wireless interface in **monitor mode** so scapy can sniff 802.11
management frames (deauth floods, beacons, rogue APs). Without monitor mode the
module silently falls back to `_simulated_loop()` (synthetic events).

---

## 1. Environment

| Item | Value |
|---|---|
| Host of driver | `kubuntu-vm` — **VMware guest** |
| Distro | Ubuntu 24.04.4 LTS |
| Kernel | `7.0.0-30-generic` (headers installed, DKMS-capable) |
| Secure Boot | off (VM) |
| USB adapter | **AICSemi AIC8800DC** (FullMAC Wi‑Fi) |
| USB id (CD mode) | `a69c:5721` — "Aic MSC" (ships as USB mass-storage / driver CD) |
| USB id (Wi‑Fi mode) | `3625:0110` — "AIC8800DC" (after mode-switch) |
| Endpoints (Wi‑Fi mode) | 4 bulk: OUT `0x01`,`0x02` · IN `0x81`,`0x82` |

**Tools installed during the session** (`apt`): `build-essential dkms iw
usb-modeswitch python3-scapy aircrack-ng`. scapy = 2.5.0. Internet works.

> ⚠️ `sudo` in this VM requires a password; the assistant could not run privileged
> commands directly — every root step was run by the user.

---

## 2. What was done (and works)

1. **Toolchain + scapy + aircrack** installed.
2. **Driver source:** `goecho/aic8800_linux_drvier` (GitHub) — this tree **compiles
   cleanly on kernel 7.0**. (The `radxa-pkg/aic8800` USB tree is the *matched*
   driver+firmware but does **not** compile on 7.0 without patching — see options.)
3. **Firmware:** the goecho tree ships only `aic8800D80` firmware. The DC firmware
   was taken from `radxa-pkg/aic8800` → `src/USB/driver_fw/fw/aic8800DC/` and staged
   to `/lib/firmware/aic8800DC/`. **Both driver and radxa firmware are `v6.4.3.0`**
   (ABI matches — the `fmacfw_patch_8800dc_u02.bin` hash is identical either way).
4. **VMware mode-switch flow** (this dongle switches CD→Wi‑Fi via SCSI eject):
   - Remove the auto-eject udev rule so the dongle stays as a CD until we choose.
   - `eject /dev/sdX` (the `a69c` node) → device re-enumerates as `3625:0110`.
   - **VMware detaches the re-enumerated device to the host.** Must manually
     re-attach it: **VM ▸ Removable Devices ▸ AICSemi AIC8800DC ▸ Connect**.
   - A **fresh chip** is required for each clean attempt — the ROM bootloader hangs
     after a failed probe; only a physical unplug/replug resets it.
5. **Result:** the driver **binds**, recognizes the chip, **downloads all firmware,
   and boots it** (`Start app: 00150000`).

### The blocker
After the firmware boots, the driver's **first message to the running firmware
times out**:
```
userconfig download complete
Start app: 00150000, 5
(4 s later) err_lmac_reqs        # rwnx_ic_system_init() → no response
aicwf_rwnx_usb_platform_init err -1
probe with driver aic8800_fdrv failed with error -1
```
Firmware **downloads** (bulk OUT) succeed; firmware **responses** (message IN
channel — the 2nd IN endpoint `0x82`) never arrive. Over VMware's emulated USB the
async second-IN-endpoint path is a known weak spot. This is **not** an ABI or config
mismatch (driver/fw both 6.4.3.0; USB/IPC Makefile options identical to radxa's).

Additional caveat: the AIC8800DC is **FullMAC**, so even after association its
**monitor-mode** support (the whole point of WIDS) is limited and unproven.

---

## 3. Exact patches applied to the goecho tree

Repo: `git clone https://github.com/goecho/aic8800_linux_drvier`
Driver path: `drivers/aic8800/aic8800_fdrv/`

**a) `aicwf_usb.c` — add our Wi‑Fi-mode USB id to the id table** (outside the
`#ifdef CONFIG_USB_BT`, before the terminating `{}`):
```c
    {USB_DEVICE_AND_INTERFACE_INFO(0x3625, 0x0110, 0xff, 0xff, 0xff)},
```

**b) `aicwf_usb.c` — map that id to the DC chip in `aicwf_usb_chipmatch()`**
(first branch):
```c
    if(vid == 0x3625 && pid == 0x0110){
        usb_dev->chipid = PRODUCT_ID_AIC8800DC;
        AICWFDBG(LOGINFO, "%s USE AIC8800DC (3625:0110)\r\n", __func__);
        return 0;
    }else if(pid == USB_PRODUCT_ID_AIC8801){
    ...
```

**c) `aicwf_usb.h` — define D41/D83/D84/D85 in the `#ifndef CONFIG_USB_BT` branch**
(needed so the tree compiles with `CONFIG_USB_BT=n`):
```c
#define USB_PRODUCT_ID_AIC8800D41		0x8d41
#define USB_PRODUCT_ID_AIC8800D83       0x8d83
#define USB_PRODUCT_ID_AIC8800D84		0x8d84
#define USB_PRODUCT_ID_AIC8800D85		0x8d85
```

**d) `drivers/aic8800/aic8800_fdrv/Makefile` — three config changes:**
```make
CONFIG_USB_BT=n          # was y. Our dongle is 1-interface Wi-Fi-only; =y expects a
                         # 3-interface BT combo and wrongly reclassifies DC→DW.
CONFIG_DPD = n           # was y. Skips on-chip DPD RF calibration (a "Start app" step
CONFIG_FORCE_DPD_CALIB = n  # was y.  that timed out -110). TX-only; irrelevant for RX/WIDS.
```

**Build:** `make clean && make build` in `drivers/aic8800/` → produces
`aic8800_fdrv.ko` + `aic_load_fw.ko` (vermagic `7.0.0-30-generic`, builds clean).

**Load order:** `insmod aic_load_fw.ko` then `insmod aic8800_fdrv.ko`
(depends on `cfg80211`, `aic_load_fw`).

> The build lived in the session scratchpad (temporary). To keep it, re-clone and
> re-apply the four patches above, or copy the patched tree into the repo (e.g.
> `hardware/aic8800/`) and wrap it in DKMS so it survives kernel updates.

---

## 4. Possible solutions (ranked)

### A. Switch to a mac80211 adapter — *recommended for WIDS*
Use a chipset with first-class **monitor mode + injection** and an in-kernel
`mac80211` driver — no out-of-tree build, no FullMAC limitation:
- Atheros **AR9271** (`ath9k_htc`) — the classic, rock-solid monitor/injection.
- Ralink **RT3070 / RT5370** (`rt2800usb`).
- MediaTek **MT7601U** (`mt7601u`) / **MT7612U** (`mt76x2u`).
- Realtek **RTL8812AU** (`8812au`, dual-band; needs a small DKMS but well-supported).

Then: `iw dev wlan0 interface add mon0 type monitor` (or `airmon-ng start wlan0`),
point `wids.py` at `mon0`, and confirm scapy sees frames. **Fastest path to a
working WIDS demo.** Verify the 2nd USB adapter's chipset first with `lsusb`.

### B. Rule out VMware USB (cheap, decisive)
The firmware-message timeout smells like VMware's USB emulation dropping the async
IN channel. Test the *same* AIC8800DC + patched driver on **bare metal** (a Ubuntu
live USB, or the physical host):
- If it brings up `wlan` bare-metal → VMware USB is the blocker. Options: set the VM
  USB controller to **USB 2.0** (not 3.1), or use **`usbip`** to pass the device, or
  run the WIDS tests on the host instead of the guest.
- If it also fails bare-metal → the issue is the driver/firmware pairing, go to C/D.

### C. Swap the bulk/msg IN-endpoint roles in the goecho driver
"Boots but never answers" is classically an endpoint-role mismatch: firmware may send
command-responses on the endpoint the driver treats as *data*. In `aicwf_usb_probe()`
endpoint loop, try assigning `msg_in_pipe` to the **first** IN bulk EP (`0x81`) and
`bulk_in_pipe` to the second (`0x82`) — and/or the OUT pair — then rebuild. One-build
experiment with decent odds. (Also worth trying `CONFIG_USB_MSG_IN_EP`/`OUT_EP`
toggles.)

### D. Port the matched radxa USB driver to kernel 7.0
`radxa-pkg/aic8800` `src/USB/driver_fw/` is the driver *shipped with* the DC firmware.
It fails to compile on 7.0; known fixes so far:
- `rwnx_rx.c`: `in_irq()` → `in_hardirq()` (removed in modern kernels).
- `rwnx_main.c:6430`: a `cfg80211` op signature gained params (link_id) — update the
  callback prototype. Expect a few more cfg80211 signature drifts to patch.

Guarantees a driver/firmware pair known-good on real hardware, but more porting and it
may still hit the same VMware-USB message wall (see B).

### E. Try a newer/alternative AIC8800 fork
Other forks may handle DC-USB + newer kernels + the message channel better. Lower
confidence; only if A–D are undesirable.

---

## 5. Monitor-mode verification checklist (whichever adapter)
Once an interface exists:
```bash
iw phy | sed -n '/Supported interface modes/,/^\s*[A-Za-z]/p'   # must list "monitor"
sudo iw dev wlan0 set type monitor && sudo ip link set wlan0 up # or: airmon-ng start wlan0
sudo python3 -c "from scapy.all import sniff,Dot11; sniff(iface='wlan0',count=10,prn=lambda p:print(p.summary()) if p.haslayer(Dot11) else None)"
```
If scapy prints live 802.11 frames, point WIDS at that iface (its scapy path in
`wids.py:_scapy_loop` activates automatically when scapy + a monitor iface are present).

## 6. Handy references from this session
- Driver (compiles on 7.0): `https://github.com/goecho/aic8800_linux_drvier`
- Matched driver+DC firmware: `https://github.com/radxa-pkg/aic8800`
  (`src/USB/driver_fw/fw/aic8800DC/`)
- DC firmware install dir: `/lib/firmware/aic8800DC/`
- VMware note: after every CD→Wi‑Fi mode-switch, re-attach the device via
  **VM ▸ Removable Devices**; a **physical replug** is needed to reset a hung chip.

---

# BARE-METAL SESSION — 2026-08-26 (physical machine `cp712`)

Work moved off the VMware VM to the user's **physical machine**. This section
supersedes the VM-era conclusions above.

## 7. Environment changes vs. the VM

| Item | VM (old) | Bare metal (now) |
|---|---|---|
| Host | VMware guest | physical `cp712` |
| Kernel | "7.0.0-30" | **6.17.0-14-generic** (headers installed) |
| Secure Boot | off | **was ON → user disabled it in BIOS** (required for unsigned .ko) |
| Toolchain | preinstalled | fresh box; installed `build-essential dkms iw usb-modeswitch python3-scapy aircrack-ng` |
| Extra adapter | — | **Realtek RTL8821CU `0bda:c820`**, in-kernel `rtw88_8821cu`, iface `wlx90de80e1832b` = phy0 |
| AIC dongle | AIC8800DC | same; CD mode `a69c:5721`, Wi-Fi mode `3625:0110`; it is a **TP-Link Archer TX1U Nano clone** |
| CD block node | `/dev/sdX` | `/dev/sda` (3.7 MB "AIC flash"); no usb-modeswitch rule → eject `/dev/sda` to switch |

`sudo` still needs a password → the user runs every privileged step.

## 8. ROOT CAUSE of the bring-up failure (finally identified)

Rebuilt the goecho tree (4 patches from §3) on 6.17 — **compiles & loads clean**,
firmware downloads and boots (`Start app: 00150000`). Then the **same** failure as
the VM. Captured the full clean dmesg and decoded it:

- The timing-out command is **`DBG_START_APP_REQ`** (msg id 1037, waits for
  `DBG_START_APP_CFM` 1038) — the "start the main application" handshake.
- The chip logs **`chip_id=7, chip_sub_id=1`** → a **legacy MCU revision 1** part.
- Verified against the radxa *matched* driver: endpoint mapping and the DUMMY
  start-app path are **byte-identical** → the VM notes' options **B (VMware USB)**
  and **C (endpoint swap)** are both **wrong**.

**The real cause: a firmware-generation mismatch.** mcu_id=1 chips need the **V3**
firmware+loader; radxa/goecho ship **V5**, which deterministically times out at
`DBG_START_APP_REQ`. (Documented upstream: `shenmintao/aic8800d80` issue #71 — a
TX1U Nano user with the identical symptom.)

## 9. THE FIX (works)

Use **`shenmintao/aic8800d80` branch `legacy-mcu1`** — ships matched **V3**
firmware + loader for mcu_id=1, natively lists our `3625:0110` id (Tenda vid
0x3625 / TX1U_NANO pid 0x0110 — no id-table patch needed), auto-mode-switches
`a69c:5721` via its `aic.rules`, and **builds clean on kernel 6.17**.

```bash
git clone -b legacy-mcu1 https://github.com/shenmintao/aic8800d80
cd aic8800d80 && sudo ./install.sh      # DKMS install: replaces fw, udev rules, module
# then PHYSICALLY power-cycle the dongle (unplug >=10 s) — DPD calib is in flash,
# the bootrom must fully reset. udev then auto-switches + DKMS auto-loads the driver.
```

Legacy V3 `fmacfw_patch_8800dc_u02.bin` md5 = **`bfd8ea1d174242e7ec823813b6c5d849`**
(the wrong V5 one was `72b397133e3e8503fa992c02a18548cd`).

**Result — CONFIRMED WORKING:** no `err_lmac`/timeout, `HT/VHT/HE supp 1`, MAC
`ec:75:0c:0b:b8:9d`, interface **`wlxec750c0bb89d`** (phy#5) created. Both wireless
adapters now live: **phy#5 = AIC8800DC**, phy#0 = Realtek RTL8821CU.

## 10. Monitor mode for WIDS — the FullMAC wall

- `iw phy phy5 info` **does** advertise `monitor` (also AP, mesh).
- `iw dev wlxec750c0bb89d set type monitor` + `set channel 6` **succeeds** (iface
  reports `type monitor`, channel locked).
- **But scapy captures ZERO frames** — confirming the doc's FullMAC warning: the
  MAC lives in firmware, which filters raw 802.11 frames before the host sees them.
  (Investigating whether the driver's `rwnx_rx_monitor` radiotap path can be made to
  deliver frames; not yet resolved.)

→ For a working WIDS demo, fall back to the **mac80211 Realtek RTL8821CU (phy0,
`wlx90de80e1832b`)** — testing that next.

## 11. Persistent artifacts on `cp712`

Everything lives in **`~/wids-aic8800/`** (survives reboot):
- `shenmintao-legacy-mcu1/` — the working driver (DKMS-installed) + V3 firmware
- `aic8800_linux_drvier/` — the goecho tree (patched; superseded, kept for reference)
- `radxa-aic8800/` — V5 firmware source (the WRONG generation for this chip)
- Scripts: `1_stage_fw.sh` `2_switch_and_load.sh` `3_reload_capture.sh`
  `4_clean_capture.sh` `5_verify_mcu1.sh` `6_monitor_test.sh`
- Captured logs: `clean_dmesg.txt`, `mcu1_result.txt`, `monitor_result.txt`

## 12. WIDS capture adapter — Realtek RTL8821CU (WORKS, with a caveat)

Monitor-mode 802.11 capture **works** on the Realtek RTL8821CU (phy0,
`wlx90de80e1832b`, `rtw88_8821cu`). Verified two ways:
- Ambient: scapy saw 81 frames/20 s (beacons + probe requests) on channel 6.
- **Controlled TX/RX:** drove the AIC8800DC (managed) in an active-scan loop so it
  transmitted probe requests; the Realtek monitor captured **57 frames from the
  AIC's MAC** `ec:75:0c:0b:b8:9d` (probe-req + control-ack), total 85, kernel
  `rx_packets` +88. End-to-end proof, not reliant on nearby APs.

**CAVEAT (important):** rtw88 monitor mode goes **deaf after an in-place `iw set
type monitor` toggle** — it reports `type monitor` + correct channel but delivers
zero frames. **Fix: reload the module for a clean monitor**, then set type/channel:
```bash
sudo nmcli dev set wlx90de80e1832b managed no
sudo modprobe -r rtw88_8821cu && sudo modprobe rtw88_8821cu && sleep 3
sudo nmcli dev set wlx90de80e1832b managed no
sudo ip link set wlx90de80e1832b down
sudo iw dev wlx90de80e1832b set type monitor
sudo ip link set wlx90de80e1832b up
sudo iw dev wlx90de80e1832b set channel 6
```
dmesg shows the healthy path: `entered promiscuous mode` when capture starts.

**Adapter roles for the WIDS demo:**
- **Realtek RTL8821CU (phy0) = WIDS monitor/capture** (point `wids.py` here).
- **AIC8800DC (phy5) = managed client / traffic generator** (FullMAC: monitor RX
  delivers nothing, so it is NOT the WIDS sniffer despite advertising `monitor`).

Runner scripts on `cp712`: `~/wids-aic8800/11_tx_rx_test.sh` (controlled TX/RX),
`8_run_wids_integration.sh` (drives real `backend/modules/wids.py`).

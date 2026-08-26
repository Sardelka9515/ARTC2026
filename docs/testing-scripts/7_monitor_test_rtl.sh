#!/bin/bash
# Test Realtek RTL8821CU (rtw88, mac80211) monitor mode + scapy capture. sudo.
IF=wlx90de80e1832b
PHY=phy0
CH=6
OUT=${WORK:-$HOME/wids-aic8800}/monitor_rtl_result.txt

echo "== phy modes ==" | tee "$OUT"
iw phy $PHY info 2>&1 | sed -n '/Supported interface modes/,/Band /p' | grep -iE "\*" | tee -a "$OUT"

echo "== release from NetworkManager ==" | tee -a "$OUT"
nmcli dev set "$IF" managed no 2>/dev/null || true

echo "== set monitor on channel $CH ==" | tee -a "$OUT"
ip link set "$IF" down 2>&1 | tee -a "$OUT"
iw dev "$IF" set type monitor 2>&1 | tee -a "$OUT"
ip link set "$IF" up 2>&1 | tee -a "$OUT"
iw dev "$IF" set channel "$CH" 2>&1 | tee -a "$OUT"
echo "== iface state ==" | tee -a "$OUT"
iw dev "$IF" info 2>&1 | grep -iE "type|channel" | tee -a "$OUT"

echo "== scapy sniff: 20s ==" | tee -a "$OUT"
timeout 30 python3 - "$IF" <<'PY' 2>&1 | tee -a "$OUT"
import sys
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth
iface=sys.argv[1]
seen={"beacon":0,"probe":0,"deauth":0,"other":0,"total":0}
def h(p):
    if not p.haslayer(Dot11): return
    seen["total"]+=1
    if p.haslayer(Dot11Beacon): seen["beacon"]+=1
    elif p.haslayer(Dot11ProbeReq): seen["probe"]+=1
    elif p.haslayer(Dot11Deauth): seen["deauth"]+=1
    else: seen["other"]+=1
    if seen["total"]<=10: print("  ", p.summary()[:100])
print("sniffing on", iface, "...")
sniff(iface=iface, prn=h, timeout=20, count=300, store=0)
print("RESULT:", seen)
print("MONITOR_WORKS" if seen["total"]>0 else "NO_FRAMES_CAPTURED")
PY
chmod 644 "$OUT"
echo "--- saved to $OUT ---"

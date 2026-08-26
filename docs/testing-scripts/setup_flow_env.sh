#!/bin/bash
# One-shot environment setup for the Flow UI demo. Run with sudo.
# Prepares the Realtek RTL8821CU as a clean monitor interface (serves BOTH the
# scapy scan fallback AND WIDS), on channel 6.
RX=wlx90de80e1832b       # Realtek RTL8821CU (rtw88) — the flow interface
CH=6

echo "== [1/3] reload rtw88 for a clean monitor =="
nmcli dev set "$RX" managed no 2>/dev/null || true
modprobe -r rtw88_8821cu 2>/dev/null
sleep 1
modprobe rtw88_8821cu
sleep 3

echo "== [2/3] set monitor + channel $CH =="
nmcli dev set "$RX" managed no 2>/dev/null || true
ip link set "$RX" down
iw dev "$RX" set type monitor
ip link set "$RX" up
iw dev "$RX" set channel "$CH"
iw dev "$RX" info | grep -iE "Interface|type|channel"

echo "== [3/3] quick capture sanity (5s) =="
timeout 10 python3 -c "
from scapy.all import sniff,Dot11
c={'n':0}
sniff(iface='$RX',prn=lambda p:c.__setitem__('n',c['n']+1) if p.haslayer(Dot11) else None,store=False,timeout=5)
print('  captured Dot11 frames in 5s:',c['n'], '->', 'OK' if c['n']>0 else 'NO FRAMES (retry / check nearby APs)')
"
echo ""
echo "Environment ready. Now launch the app AS ROOT (scapy needs it):"
echo "  cd ${REPO:-/media/sardelka/Data/repos/ARTC2026} && sudo python3 backend/app.py"
echo "Then open http://localhost:5000/flow and select interface '$RX'."

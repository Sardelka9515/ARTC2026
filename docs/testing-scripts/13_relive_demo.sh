#!/bin/bash
# Tight re-test: re-assert both cards on ch6, then inject from AIC. sudo.
RX=wlx90de80e1832b; AIC=wlxec750c0bb89d; CH=6
echo "== re-assert Realtek monitor channel (WIDS keeps sniffing) =="
iw dev "$RX" set channel "$CH" 2>&1
iw dev "$RX" info | grep -iE "type|channel"
echo "== AIC -> monitor ch$CH =="
nmcli dev set "$AIC" managed no 2>/dev/null || true
ip link set "$AIC" down; iw dev "$AIC" set type monitor 2>/dev/null
ip link set "$AIC" up; iw dev "$AIC" set channel "$CH" 2>&1
iw dev "$AIC" info | grep -iE "type|channel"
echo "== verify AIC->RX path with a parallel sniff while injecting 40 deauth =="
python3 - "$RX" "$AIC" <<'PY'
import sys, threading, time
from scapy.all import sniff, sendp, RadioTap, Dot11, Dot11Deauth
rx, aic = sys.argv[1], sys.argv[2]
c={"d":0}
def h(p):
    from scapy.all import Dot11 as D
    if p.haslayer(Dot11Deauth) and (p.getlayer('Dot11').addr2 or '').lower()=='de:ad:be:ef:00:01': c["d"]+=1
t=threading.Thread(target=lambda: sniff(iface=rx,prn=h,store=False,timeout=8),daemon=True); t.start()
time.sleep(1)
pkt=RadioTap()/Dot11(type=0,subtype=12,addr1="ff:ff:ff:ff:ff:ff",addr2="de:ad:be:ef:00:01",addr3="de:ad:be:ef:00:01")/Dot11Deauth(reason=7)
sendp(pkt,iface=aic,count=40,inter=0.04,verbose=False)
t.join()
print("Realtek captured deauth-from-rogue:", c["d"], "->", "REACHED" if c["d"]>0 else "NOT REACHED")
PY

#!/bin/bash
# Definitive: does AIC-injected deauth reach the Realtek monitor? sudo.
RX=wlx90de80e1832b   # Realtek monitor (also running WIDS in the app)
AIC=wlxec750c0bb89d  # AIC injector
CH=6
BSSID="de:ad:be:ef:00:01"
OUT=${WORK:-$HOME/wids-aic8800}/deauth_diag.txt
: > "$OUT"

echo "== RX iface state ==" | tee -a "$OUT"
iw dev "$RX" info 2>&1 | grep -iE "type|channel" | tee -a "$OUT"
echo "== AIC -> monitor ch$CH ==" | tee -a "$OUT"
nmcli dev set "$AIC" managed no 2>/dev/null || true
ip link set "$AIC" down; iw dev "$AIC" set type monitor 2>&1 | tee -a "$OUT"
ip link set "$AIC" up; iw dev "$AIC" set channel "$CH" 2>&1 | tee -a "$OUT"
iw dev "$AIC" info 2>&1 | grep -iE "type|channel" | tee -a "$OUT"

echo "== start parallel capture on $RX (12s), then inject 40 deauth from $AIC ==" | tee -a "$OUT"
python3 - "$RX" "$AIC" "$BSSID" >>"$OUT" 2>&1 <<'PY'
import sys, threading, time
from scapy.all import sniff, sendp, Dot11, Dot11Deauth, RadioTap
rx, aic, bssid = sys.argv[1], sys.argv[2], sys.argv[3]
cnt={"deauth_from_bssid":0,"total_deauth":0,"total":0}
def h(p):
    if not p.haslayer(Dot11): return
    cnt["total"]+=1
    if p.haslayer(Dot11Deauth):
        cnt["total_deauth"]+=1
        if (p[Dot11].addr2 or "").lower()==bssid: cnt["deauth_from_bssid"]+=1
t=threading.Thread(target=lambda: sniff(iface=rx,prn=h,store=False,timeout=12),daemon=True)
t.start(); time.sleep(2)
pkt=RadioTap()/Dot11(type=0,subtype=12,addr1="ff:ff:ff:ff:ff:ff",addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
print("injecting 40 deauth from",aic)
try:
    sendp(pkt,iface=aic,count=40,inter=0.05,verbose=False)
    print("inject: sendp completed")
except Exception as e:
    print("inject ERROR:",e)
t.join()
print("CAPTURED on Realtek:",cnt)
print("VERDICT:", "AIC_INJECT_REACHES_REALTEK" if cnt["deauth_from_bssid"]>0 else "NO_INJECTED_DEAUTH_SEEN")
PY
cat "$OUT" | tail -6

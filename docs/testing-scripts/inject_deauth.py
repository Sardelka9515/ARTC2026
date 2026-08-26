#!/usr/bin/env python3
# Inject a deauth burst on the monitor interface to trigger WIDS DoSDetector.
# Usage: sudo python3 inject_deauth.py [iface] [count]
import sys, time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
IFACE = sys.argv[1] if len(sys.argv) > 1 else "wlx90de80e1832b"
COUNT = int(sys.argv[2]) if len(sys.argv) > 2 else 40
BSSID = "de:ad:be:ef:00:01"     # fake rogue AP identity (not broadcast → passes WIDS filter)
VICTIM = "ff:ff:ff:ff:ff:ff"    # deauth-all
pkt = (RadioTap() /
       Dot11(type=0, subtype=12, addr1=VICTIM, addr2=BSSID, addr3=BSSID) /
       Dot11Deauth(reason=7))
print(f"Injecting {COUNT} deauth frames on {IFACE} (BSSID {BSSID}) ...")
sendp(pkt, iface=IFACE, count=COUNT, inter=0.05, verbose=False)  # ~2s for 40
print("done — WIDS should flag a deauth_flood (>=20 in 5s) if it self-captures TX.")

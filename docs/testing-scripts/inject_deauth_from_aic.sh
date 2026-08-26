#!/bin/bash
# Inject deauth from the AIC while the Realtek (running WIDS) captures. sudo.
AIC=wlxec750c0bb89d
CH=6
echo "== put AIC in monitor mode on ch$CH for injection =="
nmcli dev set "$AIC" managed no 2>/dev/null || true
ip link set "$AIC" down
iw dev "$AIC" set type monitor 2>&1
ip link set "$AIC" up
iw dev "$AIC" set channel "$CH" 2>&1
iw dev "$AIC" info | grep -iE "type|channel"
echo "== inject 40 deauth frames from AIC =="
python3 ${WORK:-$HOME/wids-aic8800}/inject_deauth.py "$AIC" 40

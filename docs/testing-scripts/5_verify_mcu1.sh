#!/bin/bash
# Run AFTER install.sh + power-cycling the dongle (unplug >=10s, replug). sudo.
OUT=${WORK:-$HOME/wids-aic8800}/mcu1_result.txt
echo "== usb ==" | tee "$OUT"
lsusb | grep -iE "3625:0110|a69c:5721|aic" | tee -a "$OUT"
echo "== firmware md5 (expect bfd8ea1d174242e7ec823813b6c5d849 = legacy V3) ==" | tee -a "$OUT"
md5sum /lib/firmware/aic8800DC/fmacfw_patch_8800dc_u02.bin 2>&1 | tee -a "$OUT"
echo "== modules ==" | tee -a "$OUT"
lsmod | grep -iE "aic8800_fdrv|aic_load_fw" | tee -a "$OUT"
echo "== wlan interfaces ==" | tee -a "$OUT"
iw dev 2>/dev/null | grep -iE "phy#|Interface|type" | tee -a "$OUT"
echo "== dmesg (aic: start app / timeout / interface) ==" | tee -a "$OUT"
dmesg | grep -iE "aic|rwnx|chip_id|chip_sub_id|start app|err_lmac|timed-out|register.*wiphy|wlan|Tx power" | tail -40 | tee -a "$OUT"
chmod 644 "$OUT"
echo "--- saved to $OUT ---"

#!/bin/bash
# CLEAN capture: run AFTER physically unplugging+replugging the dongle (fresh CD mode).
# Ejects to Wi-Fi mode, loads driver ONCE, captures full dmesg. Run with sudo.
FDRV=${WORK:-$HOME/wids-aic8800}/aic8800_linux_drvier/drivers/aic8800/aic8800_fdrv/aic8800_fdrv.ko
LOAD=${WORK:-$HOME/wids-aic8800}/aic8800_linux_drvier/drivers/aic8800/aic_load_fw/aic_load_fw.ko
OUT=${WORK:-$HOME/wids-aic8800}/clean_dmesg.txt

# ensure modules unloaded
rmmod aic8800_fdrv 2>/dev/null || true
rmmod aic_load_fw  2>/dev/null || true

echo "== usb state =="
if lsusb | grep -q "a69c:5721"; then
    echo "CD mode -> ejecting /dev/sda"
    eject /dev/sda 2>/dev/null || true
    for i in $(seq 1 15); do sleep 1; lsusb | grep -q "3625:0110" && { echo "switched after ${i}s"; break; }; done
elif lsusb | grep -q "3625:0110"; then
    echo "already Wi-Fi mode (NOTE: for a truly clean test, unplug/replug first!)"
else
    echo "NO aic device found -- plug the dongle in"; exit 1
fi

dmesg -C
insmod "$LOAD"
insmod "$FDRV" 2>&1 || true
sleep 6
dmesg > "$OUT"
chmod 644 "$OUT"
echo "== captured $(wc -l < $OUT) lines to $OUT =="
echo "== result =="
lsmod | grep -q aic8800_fdrv && iw dev 2>/dev/null | grep -iE "Interface" || echo "(probe failed - see $OUT)"

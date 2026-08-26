#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Run wids.py end-to-end against the Realtek monitor iface. sudo.
# NOTE: does NOT re-toggle monitor (that makes rtw88 deaf). Assumes a clean monitor
# already set (e.g. via 11_tx_rx_test.sh or the reload recipe). Only sets channel.
IF=wlx90de80e1832b
iw dev "$IF" set channel 6 2>/dev/null
echo "=== iface state ==="; iw dev "$IF" info | grep -iE "type|channel"
echo "=== running wids.py integration harness ==="
python3 "$SCRIPT_DIR/8_wids_integration.py" "$IF" 2>&1 | tee ${WORK:-$HOME/wids-aic8800}/wids_integration_result.txt

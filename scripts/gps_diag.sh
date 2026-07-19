#!/bin/bash
# gps_diag.sh
# One-shot GPS diagnostic: answers "is the receiver actually getting a fix, or is
# Ragnar failing to parse one?" — the two causes of a permanent "Searching...".
#
# It briefly stops ragnar/gpsd to read the raw serial port (nothing else can hold
# it open while we sample), captures ~10 s of NMEA, then restarts ragnar. Output
# is deliberately compact so it can be pasted into a chat/issue without the
# terminal pager chopping lines.
#
# Usage:  sudo bash scripts/gps_diag.sh
#
# Reading the result:
#   * GGA fix quality >= 1, or RMC status 'A'  -> the receiver HAS a fix. If
#     Ragnar still shows "Searching", that is a parsing/plumbing bug worth
#     reporting with this output attached.
#   * GGA fix quality 0, or RMC status 'V'     -> the receiver has NO fix. That
#     is antenna/sky view, not software: a cold start needs a clear view of the
#     sky and can take several minutes.
#   * No sentences at all                      -> wrong device, wrong baud, or
#     something else is holding the port.

set -u

SECONDS_TO_SAMPLE="${1:-10}"
RAW=/tmp/ragnar_nmea.raw
OUT=/tmp/ragnar_gpsdiag.txt

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo bash scripts/gps_diag.sh" >&2
    exit 1
fi

# Pick the GPS device: prefer an explicit arg, else the first tty that is not an
# Espressif companion (a Piglet/Huginn ESP32 also shows up as /dev/ttyACM*).
pick_device() {
    for dev in /dev/ttyACM* /dev/ttyUSB*; do
        [ -e "$dev" ] || continue
        # Skip Espressif VID (303a) — that's a companion board, not a GPS.
        if udevadm info -q property -n "$dev" 2>/dev/null | grep -qi 'ID_VENDOR_ID=303a'; then
            continue
        fi
        echo "$dev"
        return
    done
}

GPSDEV="${GPSDEV:-$(pick_device)}"

# Stop anything holding the serial port, sample, then bring ragnar back up.
systemctl stop ragnar >/dev/null 2>&1
systemctl stop gpsd.socket gpsd >/dev/null 2>&1
sleep 1
: > "$RAW"
if [ -n "${GPSDEV:-}" ]; then
    timeout "$SECONDS_TO_SAMPLE" cat "$GPSDEV" > "$RAW" 2>/dev/null
fi
systemctl start ragnar >/dev/null 2>&1

{
    echo "=== Ragnar GPS diagnostic ==="
    echo "commit    : $(git -C "$(dirname "$0")/.." log --oneline -1 2>/dev/null || echo unknown)"
    echo "gps device: ${GPSDEV:-NONE FOUND}"
    echo "tty list  : $(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null | tr '\n' ' ' || echo none)"
    echo "sampled   : ${SECONDS_TO_SAMPLE}s, $(wc -l < "$RAW") lines"
    echo

    if [ ! -s "$RAW" ]; then
        echo "NO DATA on ${GPSDEV:-<no device>}."
        echo "  -> wrong device/baud, or another process held the port."
        exit 0
    fi

    echo "--- sentence types seen ---"
    awk -F, '/^\$/ {print $1}' "$RAW" | sort | uniq -c | sort -rn | head -12
    echo

    echo "--- sample GGA (field 6 = fix quality: 0=no fix, 1=GPS, 2=DGPS) ---"
    grep -m3 'GGA' "$RAW" || echo "(no GGA sentences)"
    echo
    echo "--- sample RMC (field 2 = status: A=valid fix, V=void) ---"
    grep -m3 'RMC' "$RAW" || echo "(no RMC sentences)"
    echo

    # Machine-readable verdict so the answer doesn't depend on eyeballing fields.
    gga_fix=$(awk -F, '/GGA/ && $7 ~ /^[0-9]+$/ {if ($7+0 > m) m=$7+0} END {print m+0}' "$RAW")
    # grep -c exits 1 when the count is 0, so guard with `|| true` rather than a
    # `|| echo 0` fallback — the latter appends a second line to the count.
    rmc_a=$(grep -c 'RMC,[^,]*,A,' "$RAW" 2>/dev/null || true)
    rmc_a=${rmc_a:-0}
    echo "--- verdict ---"
    echo "best GGA fix quality : $gga_fix"
    echo "RMC sentences w/ 'A' : $rmc_a"
    if [ "$gga_fix" -ge 1 ] 2>/dev/null || [ "$rmc_a" -ge 1 ] 2>/dev/null; then
        echo "RECEIVER HAS A FIX. If Ragnar still shows 'Searching', it is a"
        echo "software/parsing issue — report this output."
    else
        echo "RECEIVER HAS NO FIX (searching). This is antenna / sky view, not"
        echo "software. Give it a clear view of the sky; a cold start can take"
        echo "several minutes."
    fi
} 2>&1 | tee "$OUT"

echo
echo "Saved to $OUT — paste that file's contents to share the result."

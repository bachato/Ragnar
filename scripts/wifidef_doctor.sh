#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Ragnar WiFi-Defense monitor-mode doctor
#
# Diagnoses why 802.11 monitor capture ("ragmon0") fails or hears nothing.
# It captures the environment, enables monitor via the SAME code the webapp
# uses, then compares an OS-level capture (tcpdump) against Ragnar's own
# capture — that contrast tells us whether the bug is our code or the driver.
#
# Usage:   sudo ./scripts/wifidef_doctor.sh [interface]
#   (interface is auto-detected if omitted, e.g. the USB Alfa's wlanX)
#
# Output is printed AND saved to /tmp/wifidef_doctor_<timestamp>.log
# Paste the whole log back.
# ---------------------------------------------------------------------------
set -u

# Re-exec as root (monitor ops + sniffing need it).
if [ "$(id -u)" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

IW="$(command -v iw || echo /usr/sbin/iw)"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG="/tmp/wifidef_doctor_$(date +%Y%m%d_%H%M%S).log"
MON="ragmon0"

# Mirror everything to the log file.
exec > >(tee "$LOG") 2>&1

section() { echo; echo "===================== $* ====================="; }
run()     { echo "\$ $*"; "$@" 2>&1; echo; }

phy_supports_monitor() {
  "$IW" phy "$1" info 2>/dev/null \
    | grep -A25 "Supported interface modes" | grep -q "\* monitor"
}

freq_to_chan() {
  local f="$1"
  if   [ "$f" -eq 2484 ] 2>/dev/null; then echo 14
  elif [ "$f" -ge 2412 ] 2>/dev/null && [ "$f" -le 2472 ]; then echo $(((f-2407)/5))
  elif [ "$f" -ge 5000 ] 2>/dev/null; then echo $(((f-5000)/5))
  else echo 6; fi
}

# ---- summarise a wifi_defense.py JSON result --------------------------------
summarize() {
  python3 - <<'PY'
import sys, json
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    print("  (could not parse JSON) ->", raw[:400]); sys.exit()
print("  frames=%s  monitor=%s  channel=%s  error=%s  detections=%d"
      % (d.get("frames"), d.get("monitor"), d.get("channel"),
         d.get("error"), len(d.get("detections", []))))
aps = d.get("aps") or []
if aps:
    print("  APs heard: %d  e.g. %s"
          % (len(aps), ", ".join(sorted({a.get("ssid") or "?" for a in aps})[:6])))
PY
}

capture_test() {
  local ch="$1"
  run "$IW" dev "$MON" info
  if command -v tcpdump >/dev/null; then
    echo "\$ tcpdump -i $MON on channel $ch (OS-level oracle, 8s)"
    timeout 8 tcpdump -i "$MON" -c 30 -en 2>&1 | tail -n 12
    echo
  else
    echo "  (tcpdump not installed — skipping OS oracle; 'apt install tcpdump')"
  fi
  echo "\$ Ragnar scan --channel $ch (fixed):"
  python3 "$REPO/wifi_defense.py" scan --interface "$IFACE" --seconds 8 --channel "$ch" | summarize
  echo "\$ Ragnar scan hopping (all bands, 12s):"
  python3 "$REPO/wifi_defense.py" scan --interface "$IFACE" --seconds 12 | summarize
}

# ===========================================================================
section "META / BUILD"
date
run uname -a
run "$IW" --version
echo "repo: $REPO"
run git -C "$REPO" log --oneline -3
echo -n "ragnar.service last (re)start: "
systemctl show ragnar.service -p ActiveEnterTimestamp --value 2>/dev/null
command -v tcpdump >/dev/null && echo "tcpdump: present" || echo "tcpdump: MISSING (apt install tcpdump)"
python3 -c 'import scapy; print("scapy:", scapy.__version__)' 2>/dev/null || echo "scapy: MISSING"

section "RADIOS / INTERFACES"
run "$IW" dev
run rfkill list
for d in /sys/class/net/wlan*; do
  n="$(basename "$d")"
  echo -n "$n driver: "; basename "$(readlink "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null || echo "?"
done
echo; lsusb | grep -iE 'ralink|mediatek|realtek|atheros|0e8d|0bda' || echo "(no known USB wifi vendor lines)"

# ---- choose interface -------------------------------------------------------
IFACE="${1:-}"
if [ -z "$IFACE" ]; then
  CAND=""
  for n in $("$IW" dev 2>/dev/null | awk '/Interface/{print $2}'); do
    wp="$("$IW" dev "$n" info 2>/dev/null | awk '/wiphy/{print $2}')"
    [ -n "$wp" ] || continue
    if phy_supports_monitor "phy$wp"; then
      if [ "$n" != "wlan0" ]; then IFACE="$n"; break; fi
      CAND="$n"
    fi
  done
  [ -z "$IFACE" ] && IFACE="$CAND"
fi
if [ -z "$IFACE" ]; then
  echo; echo "!! No monitor-capable interface found. Plug in the adapter, or pass one explicitly:"
  echo "   sudo $0 wlan1"
  exit 1
fi
PHY="phy$("$IW" dev "$IFACE" info 2>/dev/null | awk '/wiphy/{print $2}')"
echo; echo ">> Testing interface: $IFACE  ($PHY)"

section "RADIO CAPABILITIES ($PHY)"
"$IW" phy "$PHY" info 2>/dev/null | sed -n '/Supported interface modes/,/valid interface combinations/p' | head -n 30

# ---- pick a channel that actually has traffic -------------------------------
TESTCH=6
LINKFREQ="$("$IW" dev "$IFACE" link 2>/dev/null | awk '/freq:/{print $2}')"
if [ -n "$LINKFREQ" ]; then
  TESTCH="$(freq_to_chan "$LINKFREQ")"
  echo ">> $IFACE is associated on freq $LINKFREQ -> testing channel $TESTCH (guaranteed traffic)"
else
  echo ">> $IFACE not associated; will test on channel $TESTCH plus a hopping scan"
fi

section "CURRENT RAGNAR STATE"
run cat "$REPO/data/wifi_defense.json"
echo "recent ragnar.service log lines (monitor/scan/ragmon):"
journalctl -u ragnar.service --no-pager -n 400 2>/dev/null | grep -iE "wifidef|monitor|ragmon" | tail -n 30

# ===========================================================================
section "TEST 1 — ENABLE MONITOR (Ragnar's code path)"
python3 "$REPO/wifi_defense.py" monitor --interface "$IFACE" --enable
echo
capture_test "$TESTCH"

section "TEST 2 — DISABLE -> RE-ENABLE (the reported failure)"
python3 "$REPO/wifi_defense.py" monitor --interface "$IFACE" --disable
sleep 1
python3 "$REPO/wifi_defense.py" monitor --interface "$IFACE" --enable
echo
capture_test "$TESTCH"

section "TEST 3 — MANUAL vif REBUILD (bypasses Ragnar, tests the driver alone)"
run "$IW" dev "$MON" del
sleep 1
run "$IW" phy "$PHY" interface add "$MON" type monitor
run ip link set "$MON" up
run "$IW" dev "$MON" set channel "$TESTCH"
run "$IW" dev "$MON" info
if command -v tcpdump >/dev/null; then
  echo "\$ tcpdump -i $MON (raw driver, 8s):"
  timeout 8 tcpdump -i "$MON" -c 30 -en 2>&1 | tail -n 12
fi

section "KERNEL / DRIVER MESSAGES"
dmesg --ctime 2>/dev/null | tail -n 40 || dmesg | tail -n 40

section "DONE"
echo "Full log saved to: $LOG"
echo "Please paste the entire log back."

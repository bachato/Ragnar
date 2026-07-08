#!/bin/bash
# Ragnar kiosk wrapper — auto-detects environment:
#   * Already inside a Wayland/X session (autostart mode): just launch
#     chromium in --kiosk pointed at the configured URL.
#   * No session present (systemd service mode on Pi OS Lite): spawn our
#     own Xorg on vt7, xauth cookie, openbox WM, then chromium.
#
# Reads live config from the running Ragnar instance via /api/config so
# rotation / URL changes only require re-running the wrapper.

set -euo pipefail

REPO_ROOT="${RAGNAR_REPO:-$(cd "$(dirname "$0")/.." && pwd -P 2>/dev/null || echo /opt/ragnar)}"
CONFIG_API="http://127.0.0.1:8000/api/config"
BROWSER="${RAGNAR_BROWSER:-chromium-browser}"
if ! command -v "$BROWSER" >/dev/null 2>&1; then
    for bin in chromium-browser chromium firefox-esr; do
        if command -v "$bin" >/dev/null 2>&1; then BROWSER="$bin"; break; fi
    done
fi

LOG_DIR="${RAGNAR_KIOSK_LOG_DIR:-/var/log/ragnar}"
mkdir -p "$LOG_DIR" 2>/dev/null || true
WRAPPER_LOG="$LOG_DIR/kiosk-wrapper.log"
if : > >(tee -a "$WRAPPER_LOG" 2>/dev/null) 2>/dev/null; then
    exec > >(tee -a "$WRAPPER_LOG") 2>&1
fi
echo "[kiosk-run] start $(date -Iseconds) user=$(id -un) HOME=${HOME:-unset} DISPLAY=${DISPLAY:-unset} WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-unset} XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-unset}"

# Pi model + RAM — used to tune Chromium for low-memory boards (Pi Zero 2 W has
# only 512 MB, where Chromium OOM-crashes without the low-end flags below).
PI_MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo unknown)"
MEM_KB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
MEM_MB=$(( MEM_KB / 1024 ))
LOW_MEM=0
[[ "$MEM_MB" -gt 0 && "$MEM_MB" -le 1024 ]] && LOW_MEM=1
echo "[kiosk-run] board: ${PI_MODEL} | RAM: ${MEM_MB}MB | low_mem=${LOW_MEM}"

# Default config values (mirror shared.py defaults)
KIOSK_URL="http://localhost:8000"
KIOSK_ROTATION="0"
KIOSK_HIDE_CURSOR="true"
WARDRIVING_ENABLED="false"

if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    cfg="$(curl -fsS --max-time 5 "$CONFIG_API" 2>/dev/null || true)"
    if [[ -n "$cfg" ]]; then
        parsed="$(printf '%s' "$cfg" | python3 -c '
import json, shlex, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print("KIOSK_URL=" + shlex.quote(str(d.get("kiosk_url", "http://localhost:8000"))))
print("KIOSK_ROTATION=" + shlex.quote(str(d.get("kiosk_rotation", 0))))
print("KIOSK_HIDE_CURSOR=" + ("true" if d.get("kiosk_hide_cursor", True) else "false"))
print("WARDRIVING_ENABLED=" + ("true" if d.get("wardriving_enabled", False) else "false"))
' 2>/dev/null || true)"
        if [[ -n "$parsed" ]]; then eval "$parsed"; fi
    fi
fi

QS_SEP="?"
if [[ "$KIOSK_URL" == *"?"* ]]; then QS_SEP="&"; fi
FINAL_URL="${KIOSK_URL}${QS_SEP}kiosk=1"
if [[ "$WARDRIVING_ENABLED" == "true" ]]; then
    FINAL_URL="${FINAL_URL}#wardriving"
fi
echo "[kiosk-run] target URL: $FINAL_URL"

# Per-kiosk chromium profile so we don't trip "restore tabs" prompts.
PROFILE_DIR="$HOME/.config/ragnar-kiosk-chromium"
mkdir -p "$PROFILE_DIR" 2>/dev/null || true

# After a power-cut the Pi never shuts Chromium down cleanly, so it shows the
# "Restore pages? Chrome didn't shut down correctly" banner over the kiosk —
# the #1 kiosk complaint. Rewrite the last-session exit state to clean so the
# banner never appears. (--disable-session-crashed-bubble alone isn't reliable
# across Chromium versions; this is.)
PREFS="$PROFILE_DIR/Default/Preferences"
if [[ -f "$PREFS" ]]; then
    sed -i 's/"exit_type":"[^"]*"/"exit_type":"Normal"/; s/"exited_cleanly":false/"exited_cleanly":true/' "$PREFS" 2>/dev/null || true
fi

# Chromium flags. Kept identical across both launch modes (session + own-X) by
# building the array once here and reusing it below.
CHROMIUM_ARGS=(
    --kiosk
    --noerrdialogs
    --disable-infobars
    --disable-translate
    --disable-features=TranslateUI,Translate
    --disable-session-crashed-bubble
    --disable-pinch
    --overscroll-history-navigation=0
    --no-first-run
    --check-for-update-interval=31536000
    --disable-dev-shm-usage
    --password-store=basic
    --user-data-dir="$PROFILE_DIR"
    --app="$FINAL_URL"
)

# Low-memory boards (Pi Zero 2 W, 512 MB): trim Chromium's footprint so it
# doesn't get OOM-killed to a black screen. Harmless on bigger Pis but only
# applied where it matters.
if [[ "$LOW_MEM" -eq 1 ]]; then
    CHROMIUM_ARGS+=(
        --enable-low-end-device-mode
        --renderer-process-limit=1
        --disable-gpu-shader-disk-cache
        --disable-features=TranslateUI,Translate,CalculateNativeWinOcclusion
    )
    echo "[kiosk-run] low-memory board — applied Chromium low-end flags"
fi

# Touchscreen support: only enable Chromium touch events + an on-screen keyboard
# when a real touch device is present, so HDMI-only setups are unaffected.
# Detection is via udev's ID_INPUT_TOUCHSCREEN, with a device-name fallback.
# Force it either way with RAGNAR_KIOSK_TOUCH=on|off|auto (default auto).
TOUCH_MODE="${RAGNAR_KIOSK_TOUCH:-auto}"
TOUCH_PRESENT=0
if [[ "$TOUCH_MODE" == "on" ]]; then
    TOUCH_PRESENT=1
elif [[ "$TOUCH_MODE" == "auto" ]]; then
    if command -v udevadm >/dev/null 2>&1; then
        for dev in /dev/input/event*; do
            [[ -e "$dev" ]] || continue
            if udevadm info --query=property --name="$dev" 2>/dev/null \
                 | grep -q '^ID_INPUT_TOUCHSCREEN=1'; then
                TOUCH_PRESENT=1; break
            fi
        done
    fi
    if [[ "$TOUCH_PRESENT" -eq 0 ]] && grep -qi 'touch' /proc/bus/input/devices 2>/dev/null; then
        TOUCH_PRESENT=1
    fi
fi
if [[ "$TOUCH_PRESENT" -eq 1 ]]; then
    # Force touch event support in the DOM (Chromium usually auto-detects, but
    # this makes tap/scroll reliable across versions and headless X starts).
    CHROMIUM_ARGS+=( --touch-events=enabled )
    echo "[kiosk-run] touchscreen detected (mode=$TOUCH_MODE) — touch events on, on-screen keyboard enabled"
else
    echo "[kiosk-run] no touchscreen detected (mode=$TOUCH_MODE) — on-screen keyboard skipped"
fi

# Launch an on-screen keyboard when a touchscreen is present. Best-effort and
# backgrounded — never blocks or fails the kiosk. Wayland uses squeekboard
# (follows text-input focus); X uses matchbox-keyboard / onboard.
launch_osk() {
    [[ "${TOUCH_PRESENT:-0}" -eq 1 ]] || return 0
    local sess="${1:-x}"
    if [[ "$sess" == "wayland" ]] && command -v squeekboard >/dev/null 2>&1; then
        echo "[kiosk-run] starting squeekboard (Wayland on-screen keyboard)"
        squeekboard >/dev/null 2>&1 &
    elif command -v matchbox-keyboard >/dev/null 2>&1; then
        echo "[kiosk-run] starting matchbox-keyboard (on-screen keyboard)"
        matchbox-keyboard >/dev/null 2>&1 &
    elif command -v onboard >/dev/null 2>&1; then
        echo "[kiosk-run] starting onboard (on-screen keyboard)"
        onboard >/dev/null 2>&1 &
    else
        echo "[kiosk-run] WARN: touchscreen present but no on-screen keyboard installed"
    fi
}

# Wait for Ragnar's web server to actually answer (max 60s).
for i in $(seq 1 60); do
    if curl -fsS --max-time 2 "$KIOSK_URL" >/dev/null 2>&1; then break; fi
    sleep 1
done

# ---------------------------------------------------------------------------
# MODE A: existing session — just launch chromium into it.
# Triggered when WAYLAND_DISPLAY or DISPLAY is already set (XDG autostart
# always sets these for us; the user can also invoke manually from a
# terminal inside their session).
# ---------------------------------------------------------------------------
if [[ -n "${WAYLAND_DISPLAY:-}" || -n "${DISPLAY:-}" ]]; then
    echo "[kiosk-run] running inside existing session — launching chromium directly"

    # Apply rotation via wlr-randr (labwc/wlroots) or xrandr (X session).
    case "$KIOSK_ROTATION" in
        90|180|270)
            if [[ -n "${WAYLAND_DISPLAY:-}" ]] && command -v wlr-randr >/dev/null 2>&1; then
                # wlr-randr's --transform takes: normal|90|180|270|flipped|flipped-90|...
                OUTPUT="$(wlr-randr 2>/dev/null | awk '/^[^ ]/ {print $1; exit}')"
                if [[ -n "$OUTPUT" ]]; then
                    echo "[kiosk-run] wlr-randr: rotating $OUTPUT to $KIOSK_ROTATION"
                    wlr-randr --output "$OUTPUT" --transform "$KIOSK_ROTATION" 2>&1 || true
                fi
            elif [[ -n "${DISPLAY:-}" ]] && command -v xrandr >/dev/null 2>&1; then
                case "$KIOSK_ROTATION" in
                    90) XROT=left ;; 180) XROT=inverted ;; 270) XROT=right ;;
                esac
                PRIMARY="$(xrandr --query 2>/dev/null | awk '/ connected/ {print $1; exit}')"
                if [[ -n "$PRIMARY" ]]; then
                    echo "[kiosk-run] xrandr: rotating $PRIMARY to $XROT"
                    xrandr --output "$PRIMARY" --rotate "$XROT" 2>&1 || true
                fi
            else
                echo "[kiosk-run] WARN: rotation requested but neither wlr-randr nor xrandr available"
            fi
            ;;
        *) : ;;  # 0 = no rotation
    esac

    if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then launch_osk wayland; else launch_osk x; fi
    exec "$BROWSER" "${CHROMIUM_ARGS[@]}"
fi

# ---------------------------------------------------------------------------
# MODE B: no session — start our own Xorg, then chromium under it.
# This is the Pi OS Lite / systemd-service path.
# ---------------------------------------------------------------------------
echo "[kiosk-run] no session env — spinning up own X server"

XORG_LOG="$LOG_DIR/kiosk-Xorg.log"
mkdir -p "$HOME/.local/share/xorg" 2>/dev/null || true
rm -f /tmp/.X0-lock 2>/dev/null || true
rm -f /tmp/.X11-unix/X0 2>/dev/null || true

export XAUTHORITY="$HOME/.Xauthority"
touch "$XAUTHORITY" 2>/dev/null || true
chmod 600 "$XAUTHORITY" 2>/dev/null || true
if command -v xauth >/dev/null 2>&1; then
    COOKIE=""
    if command -v mcookie >/dev/null 2>&1; then
        COOKIE="$(mcookie)"
    elif [[ -r /dev/urandom ]] && command -v xxd >/dev/null 2>&1; then
        COOKIE="$(head -c 16 /dev/urandom | xxd -p)"
    else
        COOKIE="$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n')"
    fi
    if [[ -n "$COOKIE" ]]; then
        xauth -f "$XAUTHORITY" add ":0" . "$COOKIE" 2>/dev/null || true
    fi
fi

SESSION_SCRIPT="$(mktemp --tmpdir ragnar-kiosk-XXXXXX.sh)"
trap 'rm -f "$SESSION_SCRIPT"' EXIT
cat > "$SESSION_SCRIPT" <<EOF
#!/bin/bash
xset s off || true
xset s noblank || true
xset -dpms || true

case "$KIOSK_ROTATION" in
    90)  ROT=left ;;
    180) ROT=inverted ;;
    270) ROT=right ;;
    *)   ROT=normal ;;
esac
PRIMARY="\$(xrandr --query 2>/dev/null | awk '/ connected/ {print \$1; exit}')"
if [[ -n "\$PRIMARY" && "\$ROT" != "normal" ]]; then
    xrandr --output "\$PRIMARY" --rotate "\$ROT" || true
fi

if command -v openbox-session >/dev/null 2>&1; then
    openbox-session &
elif command -v openbox >/dev/null 2>&1; then
    openbox &
fi

if [[ "$KIOSK_HIDE_CURSOR" == "true" ]] && command -v unclutter >/dev/null 2>&1; then
    unclutter -idle 0 -root &
fi

# On-screen keyboard for touchscreens (this path is always X, so no squeekboard).
if [[ "$TOUCH_PRESENT" -eq 1 ]]; then
    if command -v matchbox-keyboard >/dev/null 2>&1; then
        matchbox-keyboard >/dev/null 2>&1 &
    elif command -v onboard >/dev/null 2>&1; then
        onboard >/dev/null 2>&1 &
    fi
fi

# Same hardened Chromium flags as the session-mode launch (built by the parent).
$(declare -p CHROMIUM_ARGS)
exec "$BROWSER" "\${CHROMIUM_ARGS[@]}"
EOF
chmod +x "$SESSION_SCRIPT"

exec xinit "$SESSION_SCRIPT" -- /usr/bin/X :0 vt7 -nolisten tcp -auth "$XAUTHORITY" -logfile "$XORG_LOG" -keeptty

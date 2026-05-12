#!/bin/bash
# Ragnar on-screen kiosk installer (Pi Flux / generic HDMI-DSI screen).
# Idempotent: safe to re-run; only installs what's missing.
# Auto-detects whether an X server is already present and installs
# the minimal X stack only on headless (Pi OS Lite) systems.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOG_DIR="/var/log/ragnar"
LOG_FILE="$LOG_DIR/kiosk_install_$(date +%Y%m%d_%H%M%S).log"
SERVICE_FILE="/etc/systemd/system/ragnar-kiosk.service"
WRAPPER_DST="/usr/local/bin/ragnar-kiosk-run"
WRAPPER_SRC="$REPO_ROOT/scripts/ragnar_kiosk_run.sh"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[kiosk-install] starting at $(date -Iseconds)"
echo "[kiosk-install] repo root: $REPO_ROOT"

# Resolve target user — prefer 'ragnar', fall back to 'pi', else first UID 1000+ user.
detect_kiosk_user() {
    for candidate in ragnar pi; do
        if id "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done
    # First regular user
    getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}'
}

KIOSK_USER="$(detect_kiosk_user)"
if [[ -z "${KIOSK_USER:-}" ]]; then
    echo "[kiosk-install] FATAL: no regular user found for kiosk session" >&2
    exit 1
fi
echo "[kiosk-install] kiosk user: $KIOSK_USER"

# Auto-detect: do we already have X?
HAS_X=0
if command -v Xorg >/dev/null 2>&1 || command -v xinit >/dev/null 2>&1; then
    HAS_X=1
fi

# Auto-detect: do we already have a browser?
HAS_BROWSER=0
BROWSER_BIN=""
for bin in chromium-browser chromium firefox-esr; do
    if command -v "$bin" >/dev/null 2>&1; then
        HAS_BROWSER=1
        BROWSER_BIN="$bin"
        break
    fi
done

PKGS_TO_INSTALL=()
if [[ "$HAS_X" -eq 0 ]]; then
    echo "[kiosk-install] no X detected — adding minimal X stack"
    PKGS_TO_INSTALL+=(xserver-xorg xinit x11-xserver-utils openbox)
fi
if [[ "$HAS_BROWSER" -eq 0 ]]; then
    echo "[kiosk-install] no browser detected — adding chromium-browser"
    PKGS_TO_INSTALL+=(chromium-browser)
fi
# unclutter is small; install if missing (used to hide the cursor)
if ! command -v unclutter >/dev/null 2>&1; then
    PKGS_TO_INSTALL+=(unclutter)
fi
# xauth is needed to generate the X authority cookie under systemd PAM
if ! command -v xauth >/dev/null 2>&1; then
    PKGS_TO_INSTALL+=(xauth)
fi

if [[ "${#PKGS_TO_INSTALL[@]}" -gt 0 ]]; then
    echo "[kiosk-install] apt installing: ${PKGS_TO_INSTALL[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS_TO_INSTALL[@]}"
else
    echo "[kiosk-install] all required packages already present"
fi

# Re-detect browser after install
if [[ -z "$BROWSER_BIN" ]]; then
    for bin in chromium-browser chromium firefox-esr; do
        if command -v "$bin" >/dev/null 2>&1; then
            BROWSER_BIN="$bin"
            break
        fi
    done
fi
if [[ -z "$BROWSER_BIN" ]]; then
    echo "[kiosk-install] FATAL: no browser available after install" >&2
    exit 1
fi
echo "[kiosk-install] browser: $BROWSER_BIN"

# Install wrapper script
install -m 0755 "$WRAPPER_SRC" "$WRAPPER_DST"
echo "[kiosk-install] wrapper installed -> $WRAPPER_DST"

# Set up tty1 autologin for the kiosk user (only if not already configured)
AUTOLOGIN_DROPIN_DIR="/etc/systemd/system/getty@tty1.service.d"
AUTOLOGIN_DROPIN="$AUTOLOGIN_DROPIN_DIR/autologin.conf"
mkdir -p "$AUTOLOGIN_DROPIN_DIR"
cat > "$AUTOLOGIN_DROPIN" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin $KIOSK_USER --noclear %I \$TERM
EOF
echo "[kiosk-install] tty1 autologin configured for $KIOSK_USER"

# Write the systemd unit
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ragnar on-screen kiosk (Chromium fullscreen)
After=network-online.target ragnar.service
Wants=network-online.target

[Service]
Type=simple
User=$KIOSK_USER
PAMName=login
TTYPath=/dev/tty7
StandardInput=tty
StandardOutput=journal
StandardError=journal
Environment=HOME=/home/$KIOSK_USER
Environment=RAGNAR_REPO=$REPO_ROOT
Environment=RAGNAR_BROWSER=$BROWSER_BIN
# Run as root (the leading '+') to clear stale X locks. /tmp has the
# sticky bit so the kiosk user can't delete files left by a prior
# root-run Xorg attempt.
ExecStartPre=+/bin/sh -c 'rm -f /tmp/.X0-lock; rm -rf /tmp/.X11-unix/X0'
ExecStart=$WRAPPER_DST
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
echo "[kiosk-install] systemd unit installed -> $SERVICE_FILE"

systemctl daemon-reload

# Allow the kiosk user to start an X session on tty7. Debian's default
# Xwrapper.config restricts X startup to the console user; on Pi OS Lite
# the file may also be missing entirely after a fresh apt install.
mkdir -p /etc/X11
if [[ ! -f /etc/X11/Xwrapper.config ]]; then
    cat > /etc/X11/Xwrapper.config <<'XWRAP'
allowed_users=anybody
needs_root_rights=yes
XWRAP
    echo "[kiosk-install] Xwrapper.config created"
else
    if grep -q '^allowed_users=' /etc/X11/Xwrapper.config; then
        sed -i 's/^allowed_users=.*/allowed_users=anybody/' /etc/X11/Xwrapper.config
    else
        echo 'allowed_users=anybody' >> /etc/X11/Xwrapper.config
    fi
    if grep -q '^needs_root_rights=' /etc/X11/Xwrapper.config; then
        sed -i 's/^needs_root_rights=.*/needs_root_rights=yes/' /etc/X11/Xwrapper.config
    else
        echo 'needs_root_rights=yes' >> /etc/X11/Xwrapper.config
    fi
    echo "[kiosk-install] Xwrapper.config updated"
fi

# Pre-create the Xorg log directory in the kiosk user's home, in case the
# wrapper hasn't run yet. The wrapper also passes -logfile so this is belt-
# and-braces.
KIOSK_HOME="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
if [[ -n "$KIOSK_HOME" ]]; then
    install -d -o "$KIOSK_USER" -g "$KIOSK_USER" -m 0755 \
        "$KIOSK_HOME/.local" "$KIOSK_HOME/.local/share" "$KIOSK_HOME/.local/share/xorg"
fi

# Ensure /var/log/ragnar is writable by the kiosk user — the wrapper writes
# the Xorg log and its own stdout/stderr there. The directory may already
# exist from other Ragnar installers (created as root).
install -d -m 0775 /var/log/ragnar
if id -u "$KIOSK_USER" >/dev/null 2>&1; then
    chgrp "$KIOSK_USER" /var/log/ragnar 2>/dev/null || true
    chmod g+w /var/log/ragnar 2>/dev/null || true
fi

echo "[kiosk-install] done. Enable with: sudo systemctl enable --now ragnar-kiosk.service"

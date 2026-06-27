#!/usr/bin/env bash
# install_sensing.sh — Provision Ragnar's WiFi-CSI sensing backend.
#
# Ragnar bundles the sensing-server engine so it runs standalone — no separate
# RuView checkout required. Hybrid strategy:
#   * arm64 (Raspberry Pi): install the prebuilt binary vendored at bin/sensing-server.
#   * other arches OR `--rebuild`: install Rust and compile from the pinned RuView source.
# Then it installs + starts a systemd service (ragnar-sensing.service) and steps
# aside any pre-existing external RuView unit so the ports don't clash.
#
# Safe to re-run (idempotent). All output is tee'd to the install log so the
# config page can stream progress.
set -euo pipefail

# ── Paths & constants ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAGNAR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDORED_BIN="$RAGNAR_DIR/bin/sensing-server"
INSTALL_BIN="/usr/local/bin/ragnar-sensing-server"
UNIT_NAME="ragnar-sensing.service"
UNIT_PATH="/etc/systemd/system/$UNIT_NAME"
UI_PATH="$RAGNAR_DIR/web/rusense"
LOG_FILE="${SENSING_INSTALL_LOG:-$RAGNAR_DIR/data/sensing_install.log}"

# RuView source (only used for the build-from-source fallback). Pinned so a
# rebuild is reproducible and can't drift under us.
RUVIEW_REPO="${RUVIEW_REPO:-https://github.com/PierreGode/RuView.git}"
RUVIEW_PIN="${RUVIEW_PIN:-d785d490894d53e5a619ea98e96ce873cff301ec}"
RUVIEW_CRATE="wifi-densepose-sensing-server"

# Runtime tuning (matches the validated working deployment).
HTTP_PORT="${SENSING_HTTP_PORT:-3000}"
WS_PORT="${SENSING_WS_PORT:-3100}"
UDP_PORT="${SENSING_UDP_PORT:-5005}"
TICK_MS="${SENSING_TICK_MS:-500}"
SOURCE="${SENSING_SOURCE:-esp32}"
RUN_USER="${SENSING_RUN_USER:-$(stat -c '%U' "$RAGNAR_DIR")}"

REBUILD=0
[ "${1:-}" = "--rebuild" ] && REBUILD=1

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log()  { echo "[install_sensing] $*"; }
fail() { echo "[install_sensing][ERROR] $*" >&2; exit 1; }
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

log "=== Ragnar sensing backend install $(date -u +%FT%TZ) ==="
log "Ragnar dir : $RAGNAR_DIR"
log "Run user   : $RUN_USER"
log "Arch       : $(uname -m)   rebuild=$REBUILD"

# ── 1. Obtain the binary ─────────────────────────────────────────────────────
ARCH="$(uname -m)"
if [ "$REBUILD" -eq 0 ] && [ "$ARCH" = "aarch64" ] && [ -x "$VENDORED_BIN" ]; then
    log "Using vendored prebuilt binary ($ARCH)."
    as_root install -m 0755 "$VENDORED_BIN" "$INSTALL_BIN"
else
    if [ "$REBUILD" -eq 1 ]; then
        log "Rebuild requested — compiling from source."
    else
        log "No prebuilt binary for arch '$ARCH' — compiling from source."
    fi

    # Ensure a Rust toolchain (install rustup for RUN_USER if missing).
    CARGO_BIN=""
    if command -v cargo >/dev/null 2>&1; then
        CARGO_BIN="$(command -v cargo)"
    elif [ -x "/home/$RUN_USER/.cargo/bin/cargo" ]; then
        CARGO_BIN="/home/$RUN_USER/.cargo/bin/cargo"
    else
        log "Installing Rust toolchain via rustup (user: $RUN_USER)…"
        as_root -u "$RUN_USER" bash -c \
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal"
        CARGO_BIN="/home/$RUN_USER/.cargo/bin/cargo"
    fi
    [ -x "$CARGO_BIN" ] || fail "cargo not available after toolchain setup"
    log "Using cargo: $CARGO_BIN"

    # Fetch pinned source (shallow) into a build cache owned by RUN_USER.
    SRC_DIR="/home/$RUN_USER/.cache/ragnar-sensing-src"
    if [ ! -d "$SRC_DIR/.git" ]; then
        as_root -u "$RUN_USER" git clone --filter=blob:none "$RUVIEW_REPO" "$SRC_DIR"
    fi
    as_root -u "$RUN_USER" git -C "$SRC_DIR" fetch --all --tags
    as_root -u "$RUN_USER" git -C "$SRC_DIR" checkout "$RUVIEW_PIN"

    log "Compiling $RUVIEW_CRATE (this can take a while on a Pi)…"
    as_root -u "$RUN_USER" bash -c \
        "cd '$SRC_DIR/v2' && '$CARGO_BIN' build --release --package '$RUVIEW_CRATE'"

    BUILT="$SRC_DIR/v2/target/release/sensing-server"
    [ -x "$BUILT" ] || fail "build did not produce $BUILT"
    # Refresh the vendored copy too so future installs are instant.
    as_root install -m 0755 "$BUILT" "$VENDORED_BIN"
    as_root install -m 0755 "$BUILT" "$INSTALL_BIN"
    log "Built and installed from source."
fi

"$INSTALL_BIN" --help >/dev/null 2>&1 || fail "$INSTALL_BIN failed to execute"
log "Binary installed at $INSTALL_BIN"

# ── 2. Step aside any external RuView unit (port conflict) ───────────────────
# Unconditional + "|| true": harmless if the unit is absent, and avoids a
# pipefail/SIGPIPE detection pitfall (grep -q closing the pipe early). This
# frees ports $HTTP_PORT/$WS_PORT/$UDP_PORT so our unit can bind them.
log "Stopping any pre-existing ruview-sensing.service to free the sensing ports."
as_root systemctl disable --now ruview-sensing.service 2>/dev/null || true

# ── 3. Install the systemd unit ──────────────────────────────────────────────
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
HOSTNAME_SHORT="$(hostname)"
ALLOWED_HOSTS="${LAN_IP}:${HTTP_PORT},${LAN_IP},${HOSTNAME_SHORT}:${HTTP_PORT},${HOSTNAME_SHORT}.local:${HTTP_PORT}"

log "Writing $UNIT_PATH (allowed hosts: $ALLOWED_HOSTS)"
as_root tee "$UNIT_PATH" >/dev/null <<UNIT
[Unit]
Description=Ragnar WiFi-CSI sensing backend (bundled sensing-server)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$RAGNAR_DIR
Environment=RUST_LOG=info
Environment=SENSING_ALLOWED_HOSTS=$ALLOWED_HOSTS
Environment=RUVIEW_PRESENCE_FLOOR=0.25
Environment=RUVIEW_NODE_VOTE=0.80
Environment=RUVIEW_NONVOTING_NODES=1
ExecStart=$INSTALL_BIN --source $SOURCE --tick-ms $TICK_MS --ui-path $UI_PATH --http-port $HTTP_PORT --ws-port $WS_PORT --udp-port $UDP_PORT --bind-addr 0.0.0.0
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

as_root systemctl daemon-reload
as_root systemctl reset-failed "$UNIT_NAME" 2>/dev/null || true
as_root systemctl enable --now "$UNIT_NAME"

# ── 4. Verify ────────────────────────────────────────────────────────────────
sleep 2
if as_root systemctl is-active --quiet "$UNIT_NAME"; then
    log "Service active. Probing /api/v1/status…"
    if curl -s --max-time 5 "http://127.0.0.1:$HTTP_PORT/api/v1/status" | grep -q '"status"'; then
        log "Sensing backend responding on port $HTTP_PORT."
    else
        log "WARNING: service is up but /api/v1/status did not respond yet (may still be warming up)."
    fi
    log "=== INSTALL OK ==="
else
    as_root systemctl status "$UNIT_NAME" --no-pager -l | tail -20 || true
    fail "service $UNIT_NAME failed to start"
fi

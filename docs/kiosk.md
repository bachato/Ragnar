# On-Screen Kiosk Mode

Ragnar can drive a locally attached screen as a fullscreen dashboard: enable
**kiosk mode**, connect a display to the Pi's HDMI, and the Ragnar web UI comes
up fullscreen in Chromium (`--kiosk`). It launches automatically on every boot.

## Enabling

Turn on **On-screen Display** in the **Config** tab. Ragnar then:

1. Runs `scripts/install_kiosk.sh`, which auto-detects your setup and installs
   only what's missing.
2. Starts the kiosk immediately (no reboot needed) and arranges for it to launch
   on every boot.

Disable the toggle to stop and remove it.

## The two modes (auto-detected)

| Image | Mode | How it runs |
|-------|------|-------------|
| **Pi OS Desktop** (a desktop session is already running) | `autostart` | An XDG autostart entry launches Chromium inside your existing labwc/Wayland (or X) session. |
| **Pi OS Lite** / headless (no session) | `service` | A systemd unit (`ragnar-kiosk.service`) spawns its own Xorg on vt7 with openbox, then Chromium. |

The default URL is `http://localhost:8000`; rotation and cursor-hiding are read
live from the app config, so changing them only requires the kiosk to relaunch.

## Supported boards

Tested and tuned for **Pi Zero 2 W, Pi 4, and Pi 5**. The wrapper adapts to the
board at launch:

- **Low-memory boards (≤ 1 GB, e.g. Pi Zero 2 W 512 MB):** applies Chromium
  low-end flags (`--enable-low-end-device-mode`, single renderer,
  `--disable-dev-shm-usage`) so it isn't OOM-killed to a black screen.
- **Pi 5 / Bookworm service mode:** the installer pulls in `xserver-xorg-legacy`
  so the non-root Xorg the kiosk starts actually launches (Bookworm is rootless-X
  by default).
- **All boards:** the "Restore pages? Chrome didn't shut down correctly" banner
  after a power-cut is suppressed by sanitizing the profile's exit state on each
  launch; `--password-store=basic` avoids a keyring hang.

The board model and RAM are logged at startup in `/var/log/ragnar/kiosk-wrapper.log`.

## Touchscreen support

Touchscreens work automatically. When the wrapper **detects a touch device**
(via udev's `ID_INPUT_TOUCHSCREEN`, with a device-name fallback) it:

- enables Chromium touch events (`--touch-events=enabled`) so tap-to-click and
  drag-scroll are reliable, and
- launches an **on-screen keyboard** so you can type into fields (login, the Web
  Terminal, WiFi passphrases) with no physical keyboard:
  - **Wayland** (Pi OS Desktop) → `squeekboard`, which follows text-input focus.
  - **X** (Pi OS Lite) → `matchbox-keyboard` (falls back to `onboard`).

HDMI-only setups are unaffected — with no touch device detected, neither the
touch flag nor the keyboard is activated.

**Override detection** with the `RAGNAR_KIOSK_TOUCH` environment variable on the
service/autostart entry: `auto` (default), `on` (force touch + keyboard), or
`off` (disable). The on-screen keyboard packages are installed best-effort at
kiosk install time and never block the install if unavailable.

## Troubleshooting

- Wrapper log: `/var/log/ragnar/kiosk-wrapper.log` (board, RAM, touch detection,
  which OSK launched, target URL).
- Xorg log (service mode): `/var/log/ragnar/kiosk-Xorg.log`.
- Service state: `journalctl -u ragnar-kiosk` on the Pi.

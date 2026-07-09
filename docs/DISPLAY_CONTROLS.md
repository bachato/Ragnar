# Display Buttons & Joystick Reference

Ragnar's HATs carry hardware controls that change what they do depending on the
**mode** the display is in:

- **Default** — the normal Ragnar dashboard (the everyday screens).
- **Wardriving** — while the wardriving engine is running.
- **Network Diagnostic** — while `network_diagnostic_mode` is on (a standalone
  field tester; documented in full in the [Network Tools Guide](nettools.md#-e-paper-network-diagnostic-mode)).

Two HATs have controls:

- **2.7" e‑Paper HAT** — 4 keys (`KEY1`–`KEY4`).
- **1.44" ST7735S LCD HAT** — 3 keys (`KEY1`–`KEY3`) + a 5‑way joystick.

> The smaller square/OLED panels (GC9A01, SSD1306) have no onboard buttons.

---

## 2.7" e‑Paper HAT (4 keys)

GPIO pins (BCM), fixed by the HAT: `KEY1=5`, `KEY2=6`, `KEY3=13`, `KEY4=19`.
In Default and Wardriving layers the keys act **on press**.

### Default mode

| Key | Action |
|-----|--------|
| **KEY1** | Swap to/from **Pwnagotchi** (10 s cooldown) |
| **KEY2** | **Rotate / flip** the screen (0° → 90° → 180° → 270°) |
| **KEY3** | **Next page** — cycle through the Ragnar screens |
| **KEY4** | **Restart** the Ragnar service |

### Wardriving mode (engine running)

| Key | Action |
|-----|--------|
| **KEY1** | Toggle a **phone-access AP** serving the minimal wardriving page |
| **KEY2** | **Rotate / flip** the screen |
| **KEY3** | Toggle the **live e‑paper map** (GPS track + network dots) |
| **KEY4** | **Connect** to a known Wi‑Fi (wardriving keeps running) |

### Network Diagnostic mode

Each key gains a **short** and a **long** (hold ~0.6 s) press — see the full
[field‑test key pad](nettools.md#field-test-key-pad-27-hat) table.

---

## 1.44" ST7735S LCD HAT (3 keys + joystick)

GPIO pins (BCM), fixed by the HAT: `KEY1=21`, `KEY2=20`, `KEY3=16`; joystick
`Up=6 Down=19 Left=5 Right=26 Press=13`.

> **Joystick orientation:** the joystick is physically mounted 90° clockwise of
> the panel's text, so Ragnar remaps every push into the frame **you read on the
> screen** — and re‑aligns automatically when **KEY2** rotates the display.
> The directions in the tables below are always relative to the upright text.

### Default mode

| Input | Action |
|-------|--------|
| **Joystick ↑ / ←** | Previous display page |
| **Joystick ↓ / →** | Next display page |
| **Joystick press** | Restart the Ragnar service |
| **KEY1** | Swap to/from **Pwnagotchi** |
| **KEY2** | **Rotate** the screen (0° → 90° → 180° → 270°) |
| **KEY3** | **Next page** |

### Network Diagnostic mode

The joystick navigates and the keys fire tests (each key has a short/long
press) — see the full [field‑test pad](nettools.md#field-test-pad-144-lcd-hat--joystick)
table.

---

## Notes

- **Mode precedence:** Network Diagnostic mode takes over the keys/joystick while
  it's on; turning it off restores the Default (or Wardriving) behaviour.
- **Rotation:** `KEY2` cycles the screen rotation on both HATs. On the square
  128×128 LCD the panel realises two visual orientations (upright / 180°), and
  the joystick tracks whichever is shown.
- Headless installs (no display) accept the display toggles but have nothing to
  render on and no buttons to read.

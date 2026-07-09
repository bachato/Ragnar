# lcdhat_input.py - Buttons + 5-way joystick for the Waveshare 1.44" LCD HAT
# (ST7735S 128x128). Reuses EPDButtonListener's page state, netdiag test engine
# and default-mode handlers; only the GPIO wiring and the input→action mapping
# differ, because this HAT has 3 keys plus a joystick instead of 4 keys.
#
# GPIO pins (BCM), fixed by the HAT:
#   KEY1 = 21   KEY2 = 20   KEY3 = 16
#   Joystick: Up=6  Down=19  Left=5  Right=26  Press=13
#
# The joystick directions below are given as the user SEES them on the upright
# text, not as the raw GPIO pins: the HAT's joystick is mounted 90° clockwise of
# the panel's text, so a raw "down" push points to the on-screen "right". The
# listener remaps every joystick direction into this visual frame (see
# _visual_dir) and keeps it correct as KEY2 rotates the screen.
#
# Default layer (not wardriving, not net-diag):
#   Joy Up/Left   : previous display page   (as seen on the text)
#   Joy Down/Right: next display page       (as seen on the text)
#   Joy Press     : restart Ragnar service
#   KEY1          : swap to/from Pwnagotchi
#   KEY2          : rotate the screen (0→90→180→270)
#   KEY3          : next display page
#
# Network Diagnostic layer (config network_diagnostic_mode) — a field-test pad.
# The joystick navigates, the keys fire tests (a long key-press fires the
# "advanced" variant, mirroring the 2.7" HAT's short/long netdiag gestures):
#   Joy Left/Up   : previous diagnostic page   (as seen on the text)
#   Joy Right/Down: next diagnostic page       (as seen on the text)
#   Joy Press     : dismiss a shown result, else pause/resume auto-cycle
#   KEY1 short/long: ping gateway  / ping internet (8.8.8.8)
#   KEY2 short/long: locate switch port / L2 health capture (~12s)
#   KEY3 short/long: speedtest / DNS Doctor poison-hijack check

import logging

from epd_button import EPDButtonListener, PAGE_COUNT, NETDIAG_HOLD_TIME

logger = logging.getLogger(__name__)

# Number of net-diag sub-pages (LINK / IP / SWITCH / DHCP). Mirrors
# display.NETDIAG_PAGE_COUNT; kept local so this module needn't import display.py.
NETDIAG_PAGE_COUNT = 4

# Button pins
KEY1_PIN = 21
KEY2_PIN = 20
KEY3_PIN = 16

# Joystick pins
JOY_UP_PIN    = 6
JOY_DOWN_PIN  = 19
JOY_LEFT_PIN  = 5
JOY_RIGHT_PIN = 26
JOY_PRESS_PIN = 13

# (pin, logical name) for every input on the HAT.
_INPUTS = (
    (KEY1_PIN,      'key1'),
    (KEY2_PIN,      'key2'),
    (KEY3_PIN,      'key3'),
    (JOY_UP_PIN,    'up'),
    (JOY_DOWN_PIN,  'down'),
    (JOY_LEFT_PIN,  'left'),
    (JOY_RIGHT_PIN, 'right'),
    (JOY_PRESS_PIN, 'press'),
)

# Keys that support a long press in net-diag mode → advanced-test variant.
_LONG_PRESS_INPUTS = {'key1', 'key2', 'key3'}

# Joystick directions in clockwise order — used to rotate a raw pin direction
# into the frame the user reads on the panel.
_CW_ORDER = ('up', 'right', 'down', 'left')


class LCDHATInputListener(EPDButtonListener):
    """Input listener for the 1.44" LCD HAT (3 keys + 5-way joystick)."""

    def __init__(self, shared_data):
        super().__init__(shared_data)
        self._held_inputs = set()

    def start(self):
        """Claim the HAT's buttons + joystick via gpiozero."""
        try:
            from gpiozero import Button

            self._buttons = []
            for pin, name in _INPUTS:
                # Long-press only matters for the keys in net-diag mode; the
                # joystick acts immediately on press.
                btn = Button(pin, pull_up=True, bounce_time=0.15,
                             hold_time=NETDIAG_HOLD_TIME)
                btn.when_pressed  = (lambda n=name: self._on_input_press(n))
                btn.when_held     = (lambda n=name: self._on_input_held(n))
                btn.when_released = (lambda n=name: self._on_input_release(n))
                self._buttons.append(btn)

            self.available = True
            logger.info("LCD HAT input listener started (keys 21,20,16 + "
                        "joystick 6,19,5,26,13)")
        except ImportError:
            logger.info("gpiozero not available - LCD HAT input listener disabled")
        except Exception as e:
            logger.warning(f"Could not start LCD HAT input listener: {e}")

    # --- Gesture dispatch -------------------------------------------------
    # Joystick inputs fire on press. Keys fire on release (short) or hold
    # (long) while in net-diag mode so a long press never also triggers the
    # short action; elsewhere the keys act on press like the 2.7" HAT.

    def _on_input_press(self, name):
        self._held_inputs.discard(name)
        if name in _LONG_PRESS_INPUTS and self._netdiag_active():
            return  # a key in net-diag mode is decided on release/hold
        self._dispatch(name, 'short')

    def _on_input_held(self, name):
        if name not in _LONG_PRESS_INPUTS or not self._netdiag_active():
            return
        self._held_inputs.add(name)
        self._dispatch(name, 'long')

    def _on_input_release(self, name):
        if name not in _LONG_PRESS_INPUTS or not self._netdiag_active():
            return
        if name in self._held_inputs:
            self._held_inputs.discard(name)
            return  # long press already handled on hold
        self._dispatch(name, 'short')

    def _dispatch(self, name, gesture):
        if self._netdiag_active():
            self._netdiag_input(name, gesture)
        else:
            self._default_input(name)

    # --- Orientation ------------------------------------------------------
    def _visual_dir(self, name):
        """Remap a raw joystick pin direction into the direction the user sees
        on the upright text. The HAT's joystick sits 90° clockwise of the panel
        (raw 'down' points to the on-screen 'right'), and the square ST7735S
        render path only realises two orientations — 0° for a 0/90 rotation and
        180° for 180/270 — so fold KEY2's rotation to that and rotate the
        direction to match. Non-directional inputs (keys, press) pass through."""
        if name not in ('up', 'down', 'left', 'right'):
            return name
        try:
            rot = int(getattr(self.shared_data, 'screen_reversed', 0) or 0) % 360
        except (TypeError, ValueError):
            rot = 0
        eff_steps = 0 if rot < 180 else 2          # visual 0° or 180°
        offset = (3 - eff_steps) % 4               # +90° CW panel-mount offset
        idx = _CW_ORDER.index(name)
        return _CW_ORDER[(idx + offset) % 4]

    # --- Default layer (page navigation + key actions) --------------------

    def _default_input(self, name):
        name = self._visual_dir(name)
        if name in ('up', 'left'):
            self._change_page(-1)
        elif name in ('down', 'right', 'key3'):
            self._change_page(+1)
        elif name == 'press':
            self._on_key4()   # restart service
        elif name == 'key1':
            self._on_key1()   # swap Pwnagotchi (or wardriving AP)
        elif name == 'key2':
            self._on_key2()   # rotate screen

    def _change_page(self, step):
        self.current_page = (self.current_page + step) % PAGE_COUNT
        logger.info(f"LCD HAT: page -> {self.current_page}")

    # --- Network Diagnostic layer ----------------------------------------

    def _netdiag_input(self, name, gesture):
        """Map a joystick/key input to a net-diag navigation or test action."""
        self.netdiag_seq += 1   # wake the display promptly

        name = self._visual_dir(name)
        if name in ('left', 'up'):
            self._netdiag_step_page(-1)
            return
        if name in ('right', 'down'):
            self._netdiag_step_page(+1)
            return
        if name == 'press':
            # Dismiss a shown result first, else toggle the auto-cycle.
            if self.netdiag_result is not None:
                self.netdiag_result = None
            else:
                self.netdiag_frozen = not self.netdiag_frozen
                logger.info(f"Netdiag: auto-cycle "
                            f"{'PAUSED' if self.netdiag_frozen else 'resumed'}")
            return

        kind = {
            ('key1', 'short'): 'ping_gw', ('key1', 'long'): 'ping_wan',
            ('key2', 'short'): 'port',    ('key2', 'long'): 'l2',
            ('key3', 'short'): 'speedtest', ('key3', 'long'): 'dns',
        }.get((name, gesture))
        if kind:
            self._run_netdiag_test(kind)

    def _netdiag_step_page(self, step):
        """Advance/rewind the net-diag page, dismissing a shown result first."""
        if self.netdiag_result is not None:
            self.netdiag_result = None
            return
        self.netdiag_page = (self.netdiag_page + step) % NETDIAG_PAGE_COUNT

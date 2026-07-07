# epd_button.py - Hardware button support for 2.7" e-Paper HAT
# GPIO pins: KEY1=5, KEY2=6, KEY3=13, KEY4=19
# Uses gpiozero (same library as the Waveshare EPD driver) to avoid conflicts
#
# Default (not wardriving):
#   KEY1: Swap to Pwnagotchi (with 10s cooldown)
#   KEY2: Flip screen upside down (toggle)
#   KEY3: Next page - rotate through all pages
#   KEY4: Restart Ragnar service
#
# While wardriving is active the keys switch to a wardriving layer:
#   KEY1: Toggle a phone-access AP serving the minimal wardriving page
#   KEY2: Flip the display (same rotation cycle as default)
#   KEY3: Toggle the live e-paper map (GPS track + network dots)
#   KEY4: Connect to a known WiFi (wardriving keeps running)
#
# While Network Diagnostic mode is active (config network_diagnostic_mode) the
# keys become a standalone field-test pad. Each key has a short press and a
# long press (hold ~0.6s); results render on the panel until KEY1 dismisses:
#   KEY1  short: next diagnostic page    long: pause/resume auto-cycle
#   KEY2  short: locate switch port      long: L2 health capture (~12s)
#         (blink the port's link LED)         (STP/rogue-DHCP/storm/dup-IP)
#   KEY3  short: ping the gateway (LAN)  long: ping the internet (WAN, 8.8.8.8)
#   KEY4  short: speedtest               long: DNS Doctor poison/hijack check
#
# Gesture wiring: default & wardriving layers still act on press (unchanged);
# the netdiag layer defers to release (short) / hold (long) so a long press
# doesn't also fire the short action.

import logging
import threading
import time
import os
import subprocess

logger = logging.getLogger(__name__)

# GPIO pin assignments for 2.7" e-Paper HAT buttons
KEY1_PIN = 5
KEY2_PIN = 6
KEY3_PIN = 13
KEY4_PIN = 19

# Other apps that drive the same 2.7" HAT and grab these exact GPIO buttons.
# If one is running it claims the pins first and Ragnar's listener fails with
# 'GPIO busy'. Stopped on demand when wardriving starts so Ragnar can own the
# keys (see EPDButtonListener.ensure_available). Override via config key
# 'wardriving_button_reclaim_services'.
CONFLICTING_BUTTON_SERVICES = ['airprint.service']

# Network Diagnostic sub-pages that the keys cycle through (mirrors
# display.NETDIAG_PAGE_COUNT: 0=LINK, 1=IP, 2=SWITCH). Kept as a local constant
# to avoid importing display.py here (display imports this module).
NETDIAG_PAGE_COUNT = 3

# Hold time (seconds) that separates a short press from a long press in the
# netdiag layer. Comfortably above the 0.3s debounce.
NETDIAG_HOLD_TIME = 0.6

# Display pages
PAGE_MAIN = 0         # Default Ragnar display
PAGE_NETWORK = 1      # Network scanner stats
PAGE_VULN = 2         # Vulnerability scanner stats
PAGE_DISCOVERED = 3   # Discovered hosts
PAGE_ADVANCED = 4     # Advanced scan results
PAGE_TRAFFIC = 5      # Traffic analysis
PAGE_COUNT = 6        # Total number of pages


class EPDButtonListener:
    """Listens for hardware button presses on the 2.7" e-Paper HAT using gpiozero."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.current_page = PAGE_MAIN
        self.flip_screen = False
        self.available = False
        self._buttons = []
        self._swap_cooldown = 0  # timestamp of last swap to prevent double triggers
        self.wardrive_map = False  # KEY3 while wardriving: show live map page

        # --- Network Diagnostic mode state (read by display.py) ---
        self.netdiag_page = 0          # current sub-page when net-diag mode is on
        self.netdiag_frozen = False    # True = auto-cycle paused (KEY1 long)
        self.netdiag_result = None     # dict of a one-shot test result, or None
        self.netdiag_seq = 0           # bumped on any key action to wake the display
        self._netdiag_busy = False     # a test thread is running
        self._held_keys = set()        # keys whose long-press already fired

    def start(self):
        """Start the button listener using gpiozero callbacks."""
        try:
            from gpiozero import Button

            self._buttons = []
            for pin, key in ((KEY1_PIN, 1), (KEY2_PIN, 2), (KEY3_PIN, 3), (KEY4_PIN, 4)):
                btn = Button(pin, pull_up=True, bounce_time=0.3,
                             hold_time=NETDIAG_HOLD_TIME)
                # Default binding: existing single-press behaviour fires on press.
                # The netdiag layer instead classifies short (release) vs long
                # (hold); when_held/when_released are no-ops outside net-diag mode.
                btn.when_pressed = (lambda k=key: self._on_press(k))
                btn.when_held = (lambda k=key: self._on_held(k))
                btn.when_released = (lambda k=key: self._on_release(k))
                self._buttons.append(btn)

            self.available = True
            logger.info(f"EPD button listener started via gpiozero (GPIO {KEY1_PIN},{KEY2_PIN},{KEY3_PIN},{KEY4_PIN})")
        except ImportError:
            logger.info("gpiozero not available - button listener disabled")
        except Exception as e:
            logger.warning(f"Could not start button listener: {e}")

    def stop(self):
        """Stop the button listener and release GPIO."""
        for btn in self._buttons:
            try:
                btn.close()
            except Exception:
                pass
        self._buttons = []

    def ensure_available(self):
        """Make sure Ragnar owns the HAT buttons, reclaiming them if needed.

        Called when wardriving starts. If the listener never got the GPIO
        lines because another app grabbed them first (e.g. airprint.service —
        a standalone Waveshare button app), stop those services and retry once.
        Returns True if the buttons are usable afterwards.
        """
        if self.available:
            return True
        services = self.shared_data.config.get(
            'wardriving_button_reclaim_services', CONFLICTING_BUTTON_SERVICES)
        freed = False
        for svc in services or []:
            if self._stop_service(svc):
                freed = True
        if freed:
            time.sleep(0.5)   # let the kernel release the GPIO lines
            self.stop()       # drop any partial handles from the failed start
            self.start()      # retry claiming the pins
        return self.available

    @staticmethod
    def _stop_service(name):
        """Stop a systemd service holding the HAT buttons (only if active)."""
        try:
            active = subprocess.run(['systemctl', 'is-active', name],
                                    capture_output=True, text=True).stdout.strip()
            if active != 'active':
                return False
            logger.info(f"Reclaiming HAT buttons: stopping {name}")
            subprocess.run(['sudo', 'systemctl', 'stop', name],
                           capture_output=True, text=True, timeout=10)
            return True
        except Exception as e:
            logger.warning(f"Could not stop {name}: {e}")
            return False

    def _is_wardriving_active(self):
        """Return True if the wardriving engine is currently running."""
        try:
            ragnar = getattr(self.shared_data, 'ragnar_instance', None)
            engine = getattr(ragnar, '_wd_engine', None) if ragnar else None
            if engine is not None:
                return bool(getattr(engine, '_running', False))
        except Exception:
            pass
        return False

    def _wifi_manager(self):
        """Return the WiFiManager instance, or None if not reachable."""
        ragnar = getattr(self.shared_data, 'ragnar_instance', None)
        return getattr(ragnar, 'wifi_manager', None) if ragnar else None

    def _netdiag_active(self):
        """True when Network Diagnostic mode owns the keys (config toggle)."""
        try:
            return bool(self.shared_data.config.get('network_diagnostic_mode', False))
        except Exception:
            return False

    # --- Gesture dispatch -------------------------------------------------
    # gpiozero fires when_pressed on every press, when_held after the hold time,
    # and when_released on every release. Default/wardriving layers act on press
    # (as before). In net-diag mode we act on release (short) or hold (long) so a
    # long press never also triggers the short action.

    def _on_press(self, key):
        self._held_keys.discard(key)
        if self._netdiag_active():
            return  # netdiag decides on release/hold
        handler = {1: self._on_key1, 2: self._on_key2,
                   3: self._on_key3, 4: self._on_key4}.get(key)
        if handler:
            handler()

    def _on_held(self, key):
        if not self._netdiag_active():
            return
        self._held_keys.add(key)
        self._netdiag_gesture(key, 'long')

    def _on_release(self, key):
        if not self._netdiag_active():
            return
        if key in self._held_keys:
            self._held_keys.discard(key)
            return  # long press already handled on hold
        self._netdiag_gesture(key, 'short')

    def _on_key1(self):
        """KEY1: wardriving → toggle phone-access AP; else swap to Pwnagotchi."""
        now = time.time()
        if now - self._swap_cooldown < 10:
            logger.debug("KEY1 ignored - cooldown active")
            return
        self._swap_cooldown = now

        if self._is_wardriving_active():
            self._toggle_wardrive_ap()
            return

        try:
            current_mode = self.shared_data.config.get('pwnagotchi_mode', 'ragnar')
            target = 'pwnagotchi' if current_mode != 'pwnagotchi' else 'ragnar'
            logger.info(f"Button KEY1: swapping to {target}")

            from webapp_modern import _schedule_pwn_mode_switch, _write_pwn_status_file, _update_pwn_config, _emit_pwn_status_update
            _write_pwn_status_file('switching', f'Button-triggered swap to {target}', 'swap', {'target_mode': target})
            _update_pwn_config({'pwnagotchi_mode': target, 'pwnagotchi_last_status': f'Swapping to {target} (KEY1 button)'})
            _emit_pwn_status_update()
            _schedule_pwn_mode_switch(target)
        except Exception as e:
            logger.error(f"KEY1 swap trigger failed: {e}")

    def _on_key2(self):
        """KEY2: Cycle display rotation (0° → 90° → 180° → 270°)."""
        _rotations = [0, 90, 180, 270]
        current = getattr(self.shared_data, 'screen_reversed', 0) or 0
        idx = _rotations.index(current) if current in _rotations else 0
        new_rotation = _rotations[(idx + 1) % len(_rotations)]
        self.shared_data.screen_reversed = new_rotation
        logger.info(f"Button KEY2: Display rotation set to {new_rotation}°")

    def _on_key3(self):
        """KEY3: wardriving → toggle live map page; else next page."""
        if self._is_wardriving_active():
            self.wardrive_map = not self.wardrive_map
            logger.info(f"Button KEY3: wardriving map {'ON' if self.wardrive_map else 'OFF'}")
            return
        self.current_page = (self.current_page + 1) % PAGE_COUNT
        page_names = ["Main", "Network", "Vuln", "Discovered", "Advanced", "Traffic"]
        name = page_names[self.current_page] if self.current_page < len(page_names) else str(self.current_page)
        logger.info(f"Button KEY3: Next page -> {name} ({self.current_page})")

    def _on_key4(self):
        """KEY4: wardriving → connect to a known WiFi; else restart service."""
        if self._is_wardriving_active():
            logger.info("Button KEY4: connecting to known WiFi (wardriving continues)...")
            threading.Thread(target=self._connect_known_wifi, daemon=True).start()
            return
        logger.info("Button KEY4: Restarting Ragnar service...")
        threading.Thread(target=self._do_restart, daemon=True).start()

    def _toggle_wardrive_ap(self):
        """KEY1 (wardriving): toggle the phone-access AP on a spare adapter."""
        wifi = self._wifi_manager()
        if wifi is None:
            logger.warning("KEY1: wifi_manager not available; cannot toggle wardrive AP")
            return
        logger.info("Button KEY1: toggling wardriving phone-access AP...")
        threading.Thread(target=wifi.start_wardrive_ap, daemon=True).start()

    def _connect_known_wifi(self):
        """KEY4 (wardriving): connect to a known WiFi without stopping scans."""
        wifi = self._wifi_manager()
        if wifi is None:
            logger.warning("KEY4: wifi_manager not available; cannot connect")
            return
        try:
            ok = wifi.try_connect_known_networks()
            logger.info(f"KEY4: known-WiFi connect {'succeeded' if ok else 'found nothing/failed'}")
        except Exception as e:
            logger.error(f"KEY4: known-WiFi connect error: {e}")

    @staticmethod
    def _do_restart():
        """Restart the ragnar service after a short delay."""
        time.sleep(1)
        subprocess.Popen(['systemctl', 'restart', 'ragnar.service'])

    # ------------------------------------------------------------------
    # Network Diagnostic field-test pad (only while network_diagnostic_mode)
    # ------------------------------------------------------------------

    def _netdiag_gesture(self, key, gesture):
        """Map a (key, short/long) gesture to a net-diag action."""
        self.netdiag_seq += 1   # wake the display promptly
        if key == 1:
            if gesture == 'short':
                # KEY1 short: dismiss a shown result, else advance the page.
                if self.netdiag_result is not None:
                    self.netdiag_result = None
                else:
                    self.netdiag_page = (self.netdiag_page + 1) % NETDIAG_PAGE_COUNT
            else:  # long: pause / resume the auto-cycle
                self.netdiag_frozen = not self.netdiag_frozen
                logger.info(f"Netdiag: auto-cycle {'PAUSED' if self.netdiag_frozen else 'resumed'}")
            return
        action = {
            (2, 'short'): 'port', (2, 'long'): 'l2',
            (3, 'short'): 'ping_gw', (3, 'long'): 'ping_wan',
            (4, 'short'): 'speedtest', (4, 'long'): 'dns',
        }.get((key, gesture))
        if action:
            self._run_netdiag_test(action)

    _NETDIAG_TITLES = {'port': 'LOCATE PORT', 'l2': 'L2 HEALTH',
                       'ping_gw': 'PING GW', 'ping_wan': 'PING WAN',
                       'speedtest': 'SPEEDTEST', 'dns': 'DNS DOCTOR'}

    def _run_netdiag_test(self, kind):
        """Show a 'running' placeholder and run the test on a daemon thread so
        the button callback returns at once (some tests take many seconds)."""
        if self._netdiag_busy:
            logger.debug(f"Netdiag test '{kind}' ignored — another is running")
            return
        self._netdiag_busy = True
        self.netdiag_result = {'title': self._NETDIAG_TITLES.get(kind, kind.upper()),
                               'running': True, 'rows': [], 'ts': time.time()}
        self.netdiag_seq += 1
        threading.Thread(target=self._netdiag_test_worker, args=(kind,),
                         daemon=True).start()

    def _netdiag_test_worker(self, kind):
        try:
            res = self._netdiag_execute(kind)
        except Exception as e:
            logger.warning(f"Netdiag test '{kind}' failed: {e}")
            res = {'rows': [('Error', str(e)[:22])]}
        cur = self.netdiag_result or {}
        cur.update(res)
        cur['title'] = cur.get('title') or self._NETDIAG_TITLES.get(kind, kind.upper())
        cur['running'] = False
        cur['ts'] = time.time()
        self.netdiag_result = cur
        self._netdiag_busy = False
        self.netdiag_seq += 1

    def _netdiag_primary_iface(self):
        """Pick the wired NIC to test: a link-up eth*/en*, else any up, else the
        first. Mirrors display._fetch_netdiag_data's selection."""
        try:
            import network_diagnostics as nd
            eth = [i for i in nd.do_interfaces(include_virtual=False).get('interfaces', [])
                   if i.get('type') == 'ethernet'
                   and str(i.get('name', '')).startswith(('eth', 'en'))]
            for i in eth:
                if i.get('link_detected') is True:
                    return i['name']
            for i in eth:
                if str(i.get('operstate', '')).lower() == 'up':
                    return i['name']
            return eth[0]['name'] if eth else None
        except Exception:
            return None

    def _netdiag_execute(self, kind):
        """Run one diagnostic and return {rows, [verdict], [note], [title]} for
        the e-Paper result page. All calls are to network_diagnostics.py."""
        import network_diagnostics as nd

        if kind == 'port':
            iface = self._netdiag_primary_iface()
            if not iface:
                return {'rows': [('Ethernet', 'none found')]}
            # force=True: on a field tool flapping the only uplink is expected.
            r = nd.do_locate_port(iface, count=6, on_ms=800, off_ms=800, force=True)
            if r.get('success'):
                return {'rows': [('Iface', iface), ('Blink', f"{r.get('count', 6)}x ~{round(r.get('duration_s', 0))}s"),
                                 ('Watch', 'switch LINK LED')],
                        'note': 'The port whose link LED blinks in this cadence is yours.'}
            return {'rows': [('Iface', iface), ('Failed', (r.get('error') or '')[:20])]}

        if kind == 'l2':
            iface = self._netdiag_primary_iface()
            if not iface:
                return {'rows': [('Ethernet', 'none found')]}
            r = nd.do_l2_health(iface, seconds=12)
            if not r.get('success'):
                return {'rows': [('L2 health', (r.get('error') or 'failed')[:18])]}
            findings = r.get('findings') or []
            top = findings[0] if findings else {'level': 'ok', 'text': 'no issues'}
            level = {'ok': 'OK', 'info': 'INFO', 'warn': 'WARN'}.get(top.get('level'), '?')
            return {'rows': [('Packets', r.get('packets', 0)),
                             ('Bc/Mc /s', r.get('bcast_mcast_per_s', 0)),
                             ('Verdict', level)],
                    'note': top.get('text')}

        if kind in ('ping_gw', 'ping_wan'):
            if kind == 'ping_gw':
                target = nd._default_gateway()
                if not target:
                    return {'rows': [('Gateway', 'none')]}
                label = 'Gateway'
            else:
                target = '8.8.8.8'
                label = 'Internet'
            r = nd.do_ping(target, count=4)
            s = r.get('summary') or {}
            loss = s.get('loss_pct')
            rtt = s.get('rtt_avg')
            return {'rows': [(label, target),
                             ('Loss', f"{loss}%" if loss is not None else 'no reply'),
                             ('RTT avg', f"{rtt} ms" if rtt is not None else '—')]}

        if kind == 'speedtest':
            r = nd.do_speedtest()
            if not r.get('success'):
                return {'rows': [('Speedtest', (r.get('error') or 'failed')[:18])]}
            return {'rows': [('Down', f"{r.get('download_mbps', '?')} Mbps"),
                             ('Up', f"{r.get('upload_mbps', '?')} Mbps"),
                             ('Ping', f"{r.get('ping_ms', '?')} ms")]}

        if kind == 'dns':
            name = self.shared_data.config.get('netdiag_dns_test_name', 'example.com')
            r = nd.do_dns_doctor(name)
            if not r.get('success'):
                return {'rows': [('DNS', (r.get('error') or 'failed')[:18])]}
            p = r.get('poison') or {}
            verdict = p.get('verdict', 'unknown')
            big = {'clean': 'CLEAN', 'suspicious': 'SUSPECT',
                   'hijacked': 'HIJACK'}.get(verdict, verdict.upper())
            reasons = p.get('reasons') or []
            return {'rows': [('Name', name[:20])],
                    'verdict': (big, verdict),
                    'note': reasons[0] if reasons else 'No poisoning signals detected.'}

        return {'rows': [('Unknown test', kind)]}

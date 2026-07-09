# 🌐 Network Tools

The **Network** tab in the Ragnar web interface is a built-in network engineer's
toolbox — everything you'd normally reach for a laptop, a terminal and a bag of
CLI tools to do, run straight from the device that's already sitting on the
segment you care about.

It is split into three sub-tabs: **Diagnostics**, **Switch & L2/L3**, and
**Interfaces**.

> **Co-authored by [Solarflere](https://www.instagram.com/solarflere).** The
> Network Tools suite was designed and built in collaboration with Solarflere.

All tools are served under `/api/net/*` by `network_diagnostics.py`, a
self-contained module wrapped so a failure there can never take down the rest of
the web app. Every tool executes on demand when you click it — with one opt-in
exception, the [Network Integrity Monitor](#-network-integrity-monitor), which
watches for DNS poisoning and ARP spoofing in the background and can push you an
alert.

### Tool index

| Tool | Sub-tab | Endpoint |
|------|---------|----------|
| [Ping](#ping) | Diagnostics | `POST /api/net/ping` |
| [Traceroute](#traceroute) | Diagnostics | `POST /api/net/traceroute` |
| [MTR](#mtr) | Diagnostics | `POST /api/net/mtr` |
| [WHOIS](#whois) | Diagnostics | `POST /api/net/whois` |
| [DNS Doctor (poisoning check)](#dns-doctor) | Diagnostics | `POST /api/net/dns` |
| [ARP Poisoning](#arp-poisoning) | Diagnostics | `GET /api/net/arp-check`, `/arp-baseline` |
| [MAC Watch](#mac-watch) | Diagnostics | `GET /api/net/mac-watch`, `POST /api/net/mac-watch-reset` |
| [DHCP Guardian](#dhcp-guardian) | Switch & L2/L3 | `GET /api/net/dhcp-guardian`, `POST /api/net/dhcp-baseline` |
| [DHCP Snooping (inline)](#dhcp-snooping-inline) | Switch & L2/L3 | `GET /api/net/dhcp-snoop` + `/dhcp-snoop/status`, `/config`, `/setup` |
| [Network Integrity Monitor](#-network-integrity-monitor) | Diagnostics | `GET /api/net/integrity` + config |
| [Path MTU / Black-hole](#path-mtu--black-hole) | Diagnostics | `POST /api/net/pmtu` |
| [Captive Portal Check](#captive-portal-check) | Diagnostics | `GET /api/net/captive-portal` |
| [LAN Throughput (iperf3)](#lan-throughput-iperf3) | Diagnostics | `POST /api/net/iperf3`, `/iperf3-server` |
| [Speed Test](#speed-test) | Diagnostics | `POST /api/net/speedtest` |
| [Live Flow Telemetry](#live-flow-telemetry) | Diagnostics | `GET /api/net/flows` |
| [PTP Timing Detection](#ptp-timing-detection) | Diagnostics | `POST /api/net/ptp` |
| [On-Screen Network Diagnostic Mode](#-on-screen-network-diagnostic-mode) | Diagnostics (toggle) | config `network_diagnostic_mode` |
| [Switch Discovery + PoE](#switch-discovery-lldp--cdpv1v2--edp--fdp) | Switch & L2/L3 | `GET /api/net/lldp` |
| [ARP Scan](#arp-scan) | Switch & L2/L3 | `GET /api/net/arp-scan` |
| [L2 Link Health](#l2-link-health) | Switch & L2/L3 | `POST /api/net/l2-health` |
| [IGMP Watch](#igmp-watch) | Switch & L2/L3 | `GET /api/net/igmp-watch`, `POST /api/net/igmp-baseline` |
| [IPv6 First-Hop Watch](#ipv6-first-hop-watch) | Switch & L2/L3 | `GET /api/net/ipv6-watch`, `POST /api/net/ipv6-baseline` |
| [OSPF Security Scanner](#ospf-security-scanner) | Switch & L2/L3 | `GET /api/net/ospf-watch`, `POST /api/net/ospf-baseline` |
| [BGP Path Watch](#bgp-path-watch) | Switch & L2/L3 | `GET /api/net/bgp-watch`, `POST /api/net/bgp-baseline` |
| [BGP Collector & Path Asymmetry](#bgp-collector--path-asymmetry-control-plane--data-plane) | Switch & L2/L3 | `GET/POST /api/net/bgp-collector`, `/api/net/owd-reflector`, `POST /api/net/path-asymmetry` |
| [Locate Port](#locate-port) | Switch & L2/L3 | `POST /api/net/locate-port` |
| [PCAP Analyzer](#pcap-analyzer) | Switch & L2/L3 | `POST /api/net/pcap` |
| [Interfaces](#interface-list) | Interfaces | `GET /api/net/interfaces` |
| [Network Identity](#network-identity) | Interfaces | `GET /api/net/identity` |
| [ISP / WAN + VPN Detection](#isp--wan-detection) | Interfaces | `GET /api/net/isp` |
| [VPN Egress Check](#vpn-egress-check) | Interfaces | `GET /api/net/vpn-check` |

---

## One-click install for missing tools

Most of these tools shell out to standard Linux utilities (`ping`, `mtr`,
`lldpd`, `arp-scan`, …). If one isn't present, Ragnar doesn't just show a dead
error — it shows an **Install** button. Clicking it runs a whitelisted
`apt-get install` for the exact package that provides the missing binary, then
re-runs the tool automatically. The button disappears once the tool is
available.

If a previous package operation on the box was interrupted (the classic
`dpkg was interrupted, you must manually run 'dpkg --configure -a'` state),
the installer detects it, runs the recovery automatically, and retries — so the
button works without you having to drop to a shell.

Installable packages are whitelisted (`iputils-ping`, `traceroute`, `mtr-tiny`,
`whois`, `speedtest-cli`, `lldpd`, `arp-scan`, `ethtool`, `curl`, `dnsutils`,
`iperf3`, `tcpdump`), so the tool name is never interpolated into a shell
command.

**Scapy** (for the routing-scanner end-to-end self-test) is installable the same
way — the **Detector Self-Test** panel in Switch & L2/L3 has an **Install Scapy**
button that installs `python3-scapy` (falling back to `pip`). It's optional: the
IGMP / OSPF / BGP scanners work fully without it; Scapy only adds the end-to-end
leg that crafts real packets → pcap → `tcpdump` → parse to exercise the whole
capture path.

### Detector Self-Test (Switch & L2/L3)
A one-click **Run self-test** that validates the IGMP, **IPv6 first-hop**, OSPF and
BGP detectors — plus the **BGP speaker** (codec/framer/FSM/RIB) and
**path-asymmetry / OWD** engine — by running each classifier against crafted attack
captures (no root, no live traffic) and reports per-suite pass/fail. With Scapy
installed it also runs the end-to-end packet-crafting leg for the capture-based
scanners. This is how you confirm the routing-security detectors are working on a
given box without waiting for a real attack — endpoint `GET /api/net/routing-selftest`.
The same checks run headless via
`python3 network_diagnostics.py {igmp,ipv6,ospf,bgp}-selftest` and each module's
`selftest()`.

---

## 🖥️ On-Screen Network Diagnostic Mode

A toggle at the top of the Diagnostics sub-tab turns the **on-board display**
(e-Paper HAT or the 1.44" LCD HAT) into a standalone, Ethernet-focused field
tool — so you can plug the device
into a switch and read the essentials off the screen with **no laptop and no
internet**. Everything shown is gathered locally (`ip` / `ethtool` /
`lldpctl` / `resolv.conf`), so it works on an isolated or dead network.

The display auto-cycles four pages every **5 seconds**:

1. **LINK** — the physical wired port: interface, link up/down, negotiated
   speed, duplex, auto-negotiation, MAC. (Instantly spot a port that fell back
   to 100 Mbps or half-duplex.)
2. **IP** — addressing: DHCP vs static, IPv4/CIDR, default gateway (with its
   reverse-DNS name), and DNS servers.
3. **SWITCH** — the switch you're plugged into, via LLDP/CDP: switch name, the
   **exact port** (e.g. `GigabitEthernet1/0/12`), VLAN, **PoE** class/wattage,
   protocol, and management IP.
4. **DHCP** — the [DHCP Guardian](#dhcp-guardian) rogue-server watch: verdict,
   how many DHCP servers answered, the server-id and gateway it offers vs. your
   active gateway, and a **ROGUE!** count if a fake server is present. The scan
   runs in the background so the page never blocks the cycle.

It focuses on the **physical** wired NIC (`eth*` / `en*`), ignoring VPN,
tunnel, bridge and container interfaces. Toggle it off to restore the normal
Ragnar display. The setting is persisted (`network_diagnostic_mode` in the
config) and shared across sessions.

#### Field-test key pad (2.7" HAT)

On the 2.7" e-Paper HAT the four hardware keys become a **standalone field
tester** while this mode is active — so you can run live tests on the switch
with no laptop. Each key has a **short press** and a **long press** (hold
~0.6 s); a test's result stays on the panel until **KEY1** dismisses it. Outside
this mode the keys keep their normal Ragnar / wardriving behaviour (they act on
press) — the netdiag layer only takes over the keys when the toggle is on.

| Key | Short press | Long press (hold ~0.6 s) |
|-----|-------------|--------------------------|
| **KEY1** | Next diagnostic page | **Pause / resume** the auto-cycle |
| **KEY2** | **Locate port** — blink the switch link LED | **L2 health** capture (~12 s) |
| **KEY3** | **Ping the gateway** (LAN) | **Ping the internet** (`8.8.8.8`, WAN) |
| **KEY4** | **Speed test** | **DNS Doctor** — poisoning/hijack verdict |

KEY4-long resolves a preset hostname (`netdiag_dns_test_name`, default
`example.com`, since the panel has no keyboard) and shows a big
**CLEAN / SUSPECT / HIJACK** verdict. Tests run on a background thread so a key
press is never blocked, and the panel wakes immediately on a press rather than
waiting out the 5 s cycle.

#### Field-test pad (1.44" LCD HAT + joystick)

The Waveshare **1.44" LCD HAT** (ST7735S, 128×128) carries **3 keys plus a
5-way joystick**. On this HAT **KEY1 is the mode switch** — it toggles On-Screen
Network Diagnostic Mode on/off directly (no web UI needed), so the two gateway/
internet pings live on the joystick instead. Select the HAT in **Display
settings** as *"1.44" ST7735S LCD HAT + joystick"*. While the mode is on:

| Input | Action |
|-------|--------|
| **KEY1** | **Toggle the mode off** — back to the normal screens |
| **Joystick ↑ / ↓** | Previous / next diagnostic page |
| **Joystick ←** | **Ping the gateway** (LAN) |
| **Joystick →** | **Ping the internet** (`8.8.8.8`, WAN) |
| **Joystick press** | Dismiss a shown result, else **pause / resume** the auto-cycle |
| **KEY2** short / long | **Locate port** — blink the switch link LED / **L2 health** capture (~12 s) |
| **KEY3** short / long | **Speed test** / **DNS Doctor** — poisoning/hijack verdict |

The joystick arrows above are **as you read them on the screen**: the HAT's
joystick is physically mounted 90° clockwise of the panel's text, so the listener
remaps each push into the on-screen frame (and re-aligns automatically when
**KEY2** rotates the display) — up/down page, left/right ping, whichever way the
panel is turned.

Outside net-diag mode the joystick pages through the normal Ragnar screens and a
**joystick press starts/stops page autoscroll** (auto-cycle every 5 s); **KEY1**
toggles this diagnostic mode, **KEY2** rotates the screen, and **KEY3** is next
page (tap) or restart the service (hold).

> Applies to the e-Paper / LCD display. Headless installs (no display) accept
> the toggle but have nothing to render it on.

---

## 🩺 Diagnostics

Reachability, path and bandwidth testing to any target.

### Ping
ICMP echo to a host or IP. Reports the raw output plus a parsed summary
(packets transmitted/received, loss %, and RTT min/avg/max). Count is
configurable (1–15). A 100 % loss result is still reported as a successful
*run* — the summary tells the story, so you can distinguish "tool failed" from
"host is down".

- Endpoint: `POST /api/net/ping` · binary: `ping` (`iputils-ping`)

### Traceroute
Hop-by-hop path to a target (numeric, one probe per hop, bounded wait), up to a
configurable max-hops (1–30). Useful for finding where along the path a
connection breaks or slows down.

- Endpoint: `POST /api/net/traceroute` · binary: `traceroute`

### MTR
A traceroute + ping hybrid that samples every hop over several cycles and
reports **per-hop loss and latency** — the fastest way to spot which single hop
on a path is dropping packets or adding jitter. Results are shown as a table
(Hop, Host, Loss %, Avg/Best/Worst ms, Jitter) with cells colour-coded by
severity.

On a multi-homed box you can pick the **start point** — a dropdown of this
host's local IPv4 addresses — to force the probes out of a specific
interface/path (`mtr -a`). The source is validated against the host's real
addresses before use.

- Endpoint: `POST /api/net/mtr` · binary: `mtr` (`mtr-tiny`)

### WHOIS
Registration/ownership lookup for a domain or IP.

- Endpoint: `POST /api/net/whois` · binary: `whois`

### DNS Doctor
Resolves a hostname through **every system resolver plus public 1.1.1.1 /
8.8.8.8**, and reports per resolver: the **answers**, **query latency**, the
**DNSSEC AD** (authenticated) flag, and status. Also reports **DoH** (443) and
**DoT** (853) reachability. Far more than a name→IP lookup: it's a
resolver-health and **DNS-poisoning / hijack detector**.

Alongside the per-resolver table it runs active poisoning probes and returns a
`poison` verdict — **clean**, **suspicious**, or **hijacked** — with the reasons:

- **NXDOMAIN rewriting** — queries a random name that *cannot* exist; a resolver
  that synthesizes an address for it is rewriting DNS (ISP redirect / typo /
  captive page). The public resolvers act as the control.
- **Private/bogon answer for a public name** — an RFC1918 / loopback / reserved
  address returned for a public hostname (redirect, blocklist sinkhole, portal).
- **SERVFAIL / DNSSEC-bogus** — a validating resolver refusing a name others
  resolve is the signature of a tampered (DNSSEC-bogus) record.
- **Resolver divergence** — the system/ISP resolver's answer shares nothing with
  the public resolvers' (split-DNS, or a hijack if unexpected). CDN/anycast
  variance is tolerated, so this is a *soft* signal.
- **DoH cross-check** — resolves the same name over Cloudflare DoH (encrypted,
  tamper-resistant) and compares to the plaintext answer; a mismatch is a strong
  sign of on-path :53 spoofing.

Strong signals (NXDOMAIN rewrite, bogon answer, DoH mismatch) → **hijacked**;
soft signals (SERVFAIL, divergence) → **suspicious**. The verdict is shown as a
banner in the web panel, is available on the e-Paper **KEY4-long** result page,
and drives the [Network Integrity Monitor](#-network-integrity-monitor).

- Endpoint: `POST /api/net/dns` `{name}` · binaries: `dig` (`dnsutils`), `curl`

### ARP Poisoning
Detects **ARP spoofing / MITM** from the kernel neighbour table (`ip neigh`) —
no packet capture needed. Two signals, returned as a **clean / suspicious /
spoofed** verdict:

- **Gateway MAC change** — the default gateway's IP→MAC binding is compared
  against a **trusted baseline**. An attacker who ARP-replies as the gateway to
  intercept traffic changes that MAC — the classic man-in-the-middle signature →
  **spoofed**. The first check *learns* the current gateway MAC as the baseline
  (`data/arp_baseline.json`); after a legitimate router swap, **Trust current
  gateway** re-learns it.
- **Subnet impersonation** — one MAC answering for many IPs (≥4) in the
  neighbour table, i.e. a host impersonating much of the segment → **suspicious**
  (the gateway's own MAC is excluded so a router fronting its address is fine).

The result shows the verdict, the current vs. trusted gateway MAC (highlighted
on mismatch), the neighbour count, any impersonator MACs and the reasons. This
is the *active* complement to the passive duplicate-IP check in
[L2 Link Health](#l2-link-health), and it feeds the
[Network Integrity Monitor](#-network-integrity-monitor).

- Endpoints: `GET /api/net/arp-check`,
  `GET|POST /api/net/arp-baseline` `{action:reset}` · uses `ip neigh` (iproute2)

### MAC Watch
**Detection-only** MAC-spoofing + randomization monitor — it *never spoofs or
randomizes anything itself*. Passive: it reads the kernel neighbour table
(`ip neigh`) and, optionally, runs an `arp-scan` sweep to widen coverage. Three
jobs, rolled into one **clean / randomization / suspicious / spoofed** verdict:

1. **Spoofing / cloning** (current *and* past):
   - **Disguised vendor** — a registered vendor OUI wearing the
     locally-administered (LAA) bit. A real OUI can't legitimately carry that
     bit, so it's the classic MAC-spoof signature → **spoofed**. Detected by
     clearing the LAA bit and matching the underlying OUI against the vendor DB.
   - **Clone** — one MAC bound to several IPs at once (the gateway is excluded).
   - **Past spoofing** — an IP whose MAC *changed identity* over time. History
     is persisted (`data/mac_watch.json`), so identity flips survive restarts;
     a randomized↔randomized flip is treated as benign privacy rotation, not a
     spoof.
2. **Randomization** — privacy (LAA, vendor-less) MACs are reported as an
   **aggregate inventory** (count · short-lived/ephemeral · virtual/VM), not one
   finding per MAC, so a Wi-Fi segment full of iPhones doesn't bury a real
   spoof. Docker / QEMU / VirtualBox / Parallels ranges are bucketed separately.
3. **Tracking** — an IP that cycles through **≥2 randomized MACs** over time is
   one device rotating to hide; its addresses are grouped into a followable
   track so it can be traced across the MACs it hides behind.

Every MAC is classified as **Vendor** (universal/burned-in), **Spoofed**
(vendor OUI + LAA bit), **Randomized** (privacy), or **Virtual/VM**. Vendor
names come from the `arp-scan` / `nmap` OUI database
(`/usr/share/arp-scan/ieee-oui.txt`, ~35k prefixes) with a built-in seed
fallback; the table is filtered to universal prefixes only so an LAA range in a
full manuf file can't be mistaken for a real vendor. This host's own NIC MACs
are always excluded.

- **Interface selector** — *Auto (default route)* or a specific NIC
  (WiFi / LAN labelled). It targets the `arp-scan` sweep at that segment; the
  neighbour-table read is kernel-global. The result shows the exact **source**
  (`arp-scan sweep on wlan0` vs `neighbour table (all interfaces)`).
- **Scan** runs the sweep; **Quick** reads the neighbour table only (no traffic
  generated, works unprivileged); **Reset history** clears the store;
  **Export CSV** downloads every observed MAC (MAC · type · vendor · IPs · flag
  · note), the scanned interface in the filename.
- Results list all findings — spoofed, cloned, tracked devices, past MAC
  changes, the randomization inventory — plus a **full table of every MAC
  observed**, worst class first.

Cross-MAC tracking here is **IP-anchored and capture-free** — honest but
limited. True device tracking across a MAC *and* IP change needs 802.11
probe-request fingerprinting, which is monitor-mode only; MAC Watch labels its
tracking as the neighbour-table approximation.

- Endpoints: `GET /api/net/mac-watch` `?scan=0|1&interface=<if>`,
  `POST /api/net/mac-watch-reset` · store: `data/mac_watch.json` · uses
  `ip neigh` (iproute2) + optional `arp-scan`; OUI DB from `arp-scan`/`nmap`

### 🛡️ Network Integrity Monitor
The one **passive, alerting** tool in the suite (everything else is on-demand).
When enabled it runs the [DNS Doctor](#dns-doctor) poisoning check, the
[ARP Poisoning](#arp-poisoning) check and the [DHCP Guardian](#dhcp-guardian)
rogue-server check on a schedule (default **every 5 min**), derives an overall
verdict — **clean / suspicious / compromised** — and:

- Surfaces a live **dashboard chip** (Overall / DNS / ARP / DHCP) in the
  Diagnostics sub-tab, with the reasons and last-check time.
- Sends a **Pushover alert** when the verdict *worsens* into a bad state (it
  alerts on the transition, not every cycle, with a cooldown backstop).

**Off by default**, because it makes outbound DNS/DoH calls each cycle — opt in
with the toggle. When you first enable it, be on a trusted network: the first
cycle learns the gateway ARP baseline. **Check now** runs both checks
immediately (works even while the monitor is off).

- Endpoint: `GET /api/net/integrity` · config: `net_integrity_monitor_enabled`,
  `net_integrity_interval_min`, `net_integrity_check_dhcp`,
  `pushover_notify_net_integrity`, `net_integrity_notify_cooldown_s`

### Path MTU / Black-hole
Discovers the **path MTU** to a target and flags an **MTU black hole** — a hop
that silently drops full-size packets, the classic "ping works but big
transfers / HTTPS / VPN hang" fault. A PMTU below 1500 points at tunnel
overhead (PPPoE/VPN) or a misconfigured hop. Measured with a `ping -M do`
(don't-fragment) binary search — no extra tool, and it won't stall on
unresponsive hops the way a full path trace can.

- Endpoint: `POST /api/net/pmtu` `{target}` · binary: `ping`

### Captive Portal Check
Detects hotel / guest-WiFi **HTTP interception** by probing the same
connectivity-check endpoints operating systems use (`generate_204`,
`captive.apple.com`). A wrong status, a redirect, or a login page instead of the
expected body means the network is hijacking HTTP.

- Endpoint: `GET /api/net/captive-portal` · binary: `curl`

### LAN Throughput (iperf3)
Measures **real throughput to another node on your network** — the test an
internet speed test can't do, and the right way to validate that a cable, port
or switch actually delivers its rated speed. Point it at any iperf3 server (up
or download, TCP or UDP with jitter/loss), and it reports Mbps plus TCP
**retransmits** (a retransmit count above zero on a LAN is a red flag for a
duplex mismatch or a bad cable). A **built-in server** toggle lets another
device throughput-test *against* this box — it shows the addresses to point the
other end at.

- Endpoints: `POST /api/net/iperf3` `{server,duration,reverse,udp}`,
  `POST /api/net/iperf3-server` `{action:start|stop}` · binary: `iperf3`

### Speed Test
Download/upload/latency bandwidth test. Supports both the Ookla `speedtest` CLI
and the Python `speedtest-cli`, reporting download/upload in Mbps, ping in ms,
and the chosen server and ISP. If neither client is present it self-installs
`speedtest-cli` on demand so the button always works.

- Endpoint: `POST /api/net/speedtest` · binary: `speedtest-cli` or `speedtest`

### Live Flow Telemetry
Per-connection kernel stats from `ss -ti` for every established TCP flow: **RTT**,
**min-RTT**, **retransmits** and MSS. It's the dependency-free version of the
eBPF per-flow visibility the big shops run — an RTT far above a flow's min-RTT
means **bufferbloat/queuing**, and any **retransmits** mean loss. Flows are
ranked worst-first. (If `bpftrace` is installed it's reported as the engine;
otherwise the always-present `ss` path is used.)

- Endpoint: `GET /api/net/flows` · binary: `ss` (iproute2, always present)

### PTP Timing Detection
Detects **IEEE-1588 / PTPv2** on the segment — the precision-time protocol
behind AV-over-IP, financial trading and 5G fronthaul. Sniffs the PTP event/
general UDP ports and the 802.1AS ethertype and reports whether a grandmaster is
announcing, the message types, and the domain(s). This is a field "is PTP here?"
check; precise clock-offset measurement needs a running `ptp4l`. (Standardised
TWAMP/OWAMP SLA testing is a natural next step but needs a cooperating reflector
on the far end.)

- Endpoint: `POST /api/net/ptp` `{interface, seconds}` · binary: `tcpdump`

## 🔌 Switch & L2/L3

Layer-2 discovery: what switch you're plugged into, and what else is on the
segment.

### Switch Discovery (LLDP / CDPv1/v2 / EDP / FDP)
Discovers the **neighbouring switch** by listening to its link-layer discovery
announcements. Ragnar runs `lldpd` configured with `-c -e -f -s`, so in addition
to standard **LLDP** it decodes:

| Flag | Protocol | Vendor |
|------|----------|--------|
| `-c` | CDPv1 / CDPv2 | Cisco |
| `-e` | EDP | Extreme |
| `-f` | FDP | Foundry / Brocade |
| `-s` | SONMP | Nortel / Avaya |

For each local interface it shows the discovered switch **name**, the
**protocol** it was learned via, the switch **port** you're connected to, the
**VLAN** id/name, **PoE** state, and the switch's **management IP**.

Switches announce roughly every 30 seconds, so after plugging in give it up to
a minute for the first neighbour to appear. Results export to CSV.

- Endpoint: `GET /api/net/lldp` · binary: `lldpctl` (`lldpd`)

#### PoE detection
A PoE-capable switch advertises its power state in the LLDP/LLDP-MED
**Power-via-MDI TLV**, which `lldpd` decodes. Ragnar parses this into a **PoE**
column showing:

- **Device type** — PSE (the switch is sourcing power) or PD
- Whether power is **enabled / being delivered** (a green ⚡ marks a port that's
  actively powered)
- **Type** — the PoE standard: **af** (802.3af, ≤15.4 W), **at** (802.3at /
  PoE+, ≤30 W) or **bt** (802.3bt / PoE++, classes 5–8). Derived from the
  power-type field and the advertised class.
- **Mode** — **active**. An LLDP power TLV means the PSE does standards-based
  802.3 detection/classification, i.e. active PoE. Passive PoE injectors put
  voltage on the wire with no negotiation and advertise nothing, so they can't
  be confirmed from the powered device over LLDP — the tool only ever affirms
  *active*, it never falsely claims *passive*.
- **Delivery** — **endspan** (power comes from the switch itself) vs **midspan**
  (a separate power injector between switch and device). Inferred from which
  pairs carry power — data pairs / Alternative A ⇒ endspan, spare pairs /
  Alternative B ⇒ midspan. Best-effort: 802.3at/bt drive all four pairs, so
  treat this as indicative rather than definitive.
- **Power class** (e.g. class 3) and **allocated / requested wattage**

> **Note:** this reflects PoE *as advertised by the switch over LLDP*. An
> unmanaged/passive PoE injector, or a switch with LLDP-MED power TLVs turned
> off, won't advertise it — so a blank PoE column means "not advertised", not a
> guaranteed "no power".

### ARP Scan
Sweeps the local segment with ARP to enumerate **live hosts** on a chosen
interface, returning IP, MAC and (where known) NIC vendor for each responder.
The fastest way to inventory a subnet you're attached to. Results export to CSV.

- Endpoint: `GET /api/net/arp-scan?interface=<iface>` · binary: `arp-scan`

> This is an **inventory** sweep, not a security check. For ARP **spoofing /
> poisoning** detection (gateway-MAC watch + subnet impersonation), see
> [ARP Poisoning](#arp-poisoning) in the Diagnostics sub-tab.

### DHCP Guardian
**DHCP-snooping-style** monitor — the DHCP layer is the one L2 service the suite
hadn't covered, and arguably the highest-value one after DNS: whoever answers
DHCP hands you your gateway and DNS, so a rogue DHCP server is a turnkey
man-in-the-middle. **Detection-only** — it never runs a DHCP server or hands out
leases. Two signals, rolled into a **clean / rogue / starvation** verdict:

- **Rogue / fake DHCP server** — an active `broadcast-dhcp-discover` provokes
  *every* DHCP server on the segment to OFFER. More than one distinct server, a
  server that isn't the **trusted baseline**, or one offering a gateway/DNS that
  differs from the one you're actually using → **rogue** (DHCP steering). The
  first scan *learns* the current single server as trusted
  (`data/dhcp_baseline.json`); after a legitimate DHCP/router change, **Trust
  current server** re-learns it. The offered gateway is cross-checked against the
  [ARP Poisoning](#arp-poisoning) baseline, so a DHCP steer backed by ARP
  spoofing reads as one **combined DHCP+ARP MITM** finding.
- **DHCP starvation** — a short passive `tcpdump` capture counts client
  DISCOVER/REQUEST messages and the **distinct client hardware addresses**
  (chaddr) behind them; a burst of many distinct chaddrs in a few seconds is the
  pool-exhaustion signature (the classic precursor that clears the field for a
  rogue server) → **starvation**.

The result shows the verdict, every DHCP server that answered (server-id,
offered gateway/DNS, lease, and a trusted / new / rogue badge), the starvation
capture stats, and the gateway's ARP verdict. An **interface selector**
(Auto / WiFi / LAN) targets the scan at a chosen segment. It feeds the
[Network Integrity Monitor](#-network-integrity-monitor) (rogue-server check
only, so the background cycle stays fast) and adds a **DHCP page** to the
[On-Screen Network Diagnostic Mode](#-on-screen-network-diagnostic-mode).

- Endpoints: `GET /api/net/dhcp-guardian` `?interface=<if>&seconds=<n>&quick=0|1`,
  `GET|POST /api/net/dhcp-baseline` `{action:reset}` · store:
  `data/dhcp_baseline.json` · binaries: `nmap`
  (broadcast-dhcp-discover) + `tcpdump`

### DHCP Snooping (inline)
The **enterprise-grade** version of [DHCP Guardian](#dhcp-guardian), for when the
Pi has **two NICs bridged inline** (it sits between the client segment and the
uplink, so every DHCP packet transits it). This is the managed-switch *DHCP
snooping* model, and it's strictly stronger than active probing — **detection
only** (it never drops or rewrites a frame; inline blocking is a deliberate
future opt-in).

- **Trusted vs. untrusted ports** — you mark the uplink NIC (toward the real
  DHCP server) *trusted* and the client NIC *untrusted*. A DHCP **server**
  message (OFFER/ACK/NAK) that ingresses the **untrusted** port is a rogue
  server *by definition* — zero false positives, no baseline needed. Ingress
  port is read from `tcpdump -i any -Q in` (LINUX_SLL2 tags each frame with its
  interface).
- **Binding table** — every OFFER/ACK records **client-MAC ↔ assigned-IP ↔
  server ↔ lease ↔ ingress-port**, the same table a switch keeps, and the basis
  for spotting IP spoofing / feeding dynamic ARP inspection later.
- **Starvation** — distinct client hardware addresses (chaddr) flooding
  DISCOVERs are counted straight off the wire.

Bring your own bridge or SPAN/mirror port, or use the **guarded setup helper**
to enslave two wired NICs into `rgsnoop0` — it refuses the management /
default-route / wireless interface so it can't cut its own link. verdict:
**clean / rogue / starvation**.

> **Needs the inline hardware.** With no bridge the box only sees broadcast
> DISCOVERs (unicast OFFERs won't transit), so `status` reports *not inline yet*
> until two NICs share a bridge. This is the natural home for a 2-Ethernet
> (OTG-hub) build; pair it with the hardware watchdog the installer enables.

- Endpoints: `GET /api/net/dhcp-snoop` `?trusted=<if>&untrusted=<if>&seconds=<n>`,
  `GET /api/net/dhcp-snoop/status`, `GET|POST /api/net/dhcp-snoop/config`
  `{trusted,untrusted}`, `POST /api/net/dhcp-snoop/setup`
  `{action:create|destroy,iface_a,iface_b}` · store: `data/dhcp_snoop.json` ·
  binaries: `tcpdump`, `ip`

### L2 Link Health
Listens **passively** on an interface for a few seconds (`tcpdump`) and reports
what's wrong at Layer 2 — no configuration, just plug in and scan:

- **STP** — root bridge(s) seen and topology-change churn. Multiple roots or a
  flood of TCNs is the fingerprint of a **loop** or merged/segmented domains.
- **CDP / LLDP / DTP / VTP** control frames present (DTP = the port may
  auto-negotiate a trunk).
- **Broadcast / multicast rate** — a high rate flags a **broadcast storm**.
- **Rogue DHCP** — more than one DHCP server answering on the segment.
- **Rogue IPv6 RA** — more than one Router Advertisement source.
- **Duplicate IP** — the same IP claimed by different MACs (conflicting ARP).

Findings are ranked (warn / info / ok). This is the one-tap "why is this
segment misbehaving" check that normally needs a laptop and Wireshark.

- Endpoint: `POST /api/net/l2-health` `{interface, seconds}` · binary: `tcpdump`

### IGMP Watch
A **passive** IGMP-snooping security scanner for the IPv4 multicast control
plane — **detection-only**: it never joins a group, sends a query, or becomes a
querier. One short `tcpdump` window is parsed and classified into four things:

- **Storm / flood** — an IGMP report/query rate far above normal (IGMP is
  intrinsically low-volume), or a single source flooding reports. This is a real
  multicast DoS and a switch-CPU exhaustion vector.
- **Anomaly** — more than one **querier** on the segment. There must be exactly
  one; a second, lower-IP querier is the classic *"become the querier to draw
  all multicast to yourself"* attack. Also flags mixed query versions
  (a v3→v2/v1 downgrade).
- **Reconnaissance** — one host joining a wide spread of **distinct groups** —
  multicast stream enumeration.
- **Unauthorized join** — a host on an **admin-scoped** (239/8), **globally-scoped**
  or **SSM** (232/8) group it has never been seen on, measured against a learned
  baseline. Link-local control groups (224.0.0.0/24) and normal service discovery
  (mDNS, SSDP) are recognised and not flagged.

Following the passive-floor doctrine (see [MAC Watch](#mac-watch) /
[L2 Link Health](#l2-link-health)), thresholds sit above ordinary chatter so a
healthy segment reads clean. The **first scan learns** the current querier(s) and
host→group memberships as the trusted baseline (`data/igmp_watch.json`); after a
legitimate multicast/router change, click **Trust current** to re-learn. Comfortable
on a Pi Zero 2 W even off a busy SPAN, since IGMP is low-rate control traffic.

There is also a small **CLI** (no web app needed):

```
python3 network_diagnostics.py igmp-watch [--iface eth0] [--seconds 12] [--json]
python3 network_diagnostics.py igmp-selftest     # self-test the detectors, no root
```

`igmp-selftest` drives the real parser + classifier with synthetic captures
(clean / storm / rogue-querier / recon / unauthorized / v3 group-record parse),
and — when [Scapy](https://scapy.net) is installed — additionally crafts real
IGMP packets into a pcap and parses them back through `tcpdump`, exercising the
capture→parse path end to end.

- Endpoint: `GET /api/net/igmp-watch` `{interface, seconds}`,
  `POST /api/net/igmp-baseline` `{action: reset}` · binary: `tcpdump`

### IPv6 First-Hop Watch
The **most-overlooked LAN attack today**, and a genuine gap in most toolkits. Every
modern OS ships with **IPv6 enabled and _preferred_** over IPv4 — even on networks
where "nobody deploys IPv6" and nobody's watching it. So an attacker who broadcasts
a rogue **Router Advertisement** (ICMPv6 type 134) or stands up a rogue **DHCPv6**
server silently becomes the segment's **default gateway and/or DNS** — the classic
**SLAAC attack** and **mitm6** — while a tech staring at IPv4 / ARP / DHCP sees
nothing wrong. This scanner is **passive and detection-only**: it never sends an RA,
never answers a solicit, never touches routing. One short `tcpdump` window over
ICMPv6 RA/RS/Redirect + DHCPv6 (udp 546/547) is parsed and classified:

- **Rogue RA** — a Router Advertisement from a router **not in the learned baseline**
  (a new default gateway), a **second, conflicting** router, an RA that **injects a
  DNS server** (RDNSS option) or a new prefix, an RA with **`pref high`** (an
  attacker biasing host router-selection), or **router-lifetime 0** (an RA that
  *deprecates* the real router — the RA "kill" / DoS trick).
- **Rogue DHCPv6** — a DHCPv6 **ADVERTISE / REPLY / RECONFIGURE** from a server not
  in the baseline. This is **mitm6's signature**: it answers DHCPv6 solicits handing
  out the attacker as **DNS** (no gateway — it pairs with WPAD) to relay and
  NTLM-capture.
- **Storm** — a Router Advertisement **flood** (e.g. THC `fake_router6`), by rate.
- **Anomaly** — first-hop IPv6 seen where the baseline expected none, or a
  managed/other-flag change that alters how hosts get addresses.

The **first scan learns** the trusted router(s) + DHCPv6 server(s) into
`data/ipv6_watch.json`; after a legitimate IPv6 change, click **Trust current** to
re-learn. Because RAs are intrinsically rare, a healthy segment reads clean. Every
result carries a **mitigation advisory**: enable switch **RA-Guard** (RFC 6105) and
DHCPv6 snooping on access ports; if IPv6 is genuinely unused, filter ICMPv6 RA /
DHCPv6 or disable IPv6 on hosts to remove the vector entirely.

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py ipv6-watch [--iface eth0] [--seconds 12] [--json]
python3 network_diagnostics.py ipv6-selftest    # self-test the detectors, no root
```

`ipv6-selftest` drives the real parser + classifier with synthetic captures
(clean / rogue-ra / rogue-dhcpv6 / storm / anomaly / multi-line RA parse), and —
when [Scapy](https://scapy.net) is installed — crafts a real Router Advertisement
(with prefix + RDNSS options) into a pcap and parses it back through `tcpdump`,
exercising the capture→parse path end to end.

- Endpoint: `GET /api/net/ipv6-watch` `{interface, seconds}`,
  `POST /api/net/ipv6-baseline` `{action: reset}` · binary: `tcpdump`

### OSPF Security Scanner
A **passive** routing-security scanner for OSPF (the interior routing control
plane, IP proto 89 / multicast 224.0.0.5–6). **Detection-only** — it never forms
an adjacency, floods an LSA, or touches the LSDB; it just captures one short
window and classifies it. OSPF is the classic route-poisoning target: without
cryptographic auth, any host on the segment can inject LSAs and silently redirect
traffic. What it flags:

- **Weak / no authentication** — Auth Type 0 (none) or 1 (plaintext). This is the
  enabler for every injection attack and the one thing always visible on the wire;
  it surfaces a CVE/OSV advisory.
- **Anomaly** — a new/rogue OSPF router (adjacency spoofing), a **duplicate
  Router-ID** (conflict/spoof), Hello parameter mismatch, or mixed OSPF versions.
- **Injection** — an LSA whose **Advertising Router** never announced itself (a
  spoofed/injected LSA), a **MaxSequence** (0x7fffffff) or **MaxAge** fight-provoking
  LSA, **fight-back** (one LSA re-originated rapidly = the owner countering an
  active injection), or a **new AS-External (Type-5)** originator (route injection /
  default-route hijack).
- **Storm** — an LS-Update flood (control-plane DoS).

Design is inspired by **[OSPFwatcher](https://github.com/Vadims06/ospfwatcher)**
(topology-change monitoring) and **FRR-MAD** (expected-vs-observed LSDB anomaly
detection), approximated passively from the wire with a learned baseline — the
first scan learns the routers and Type-5 originators (`data/ospf_watch.json`),
**Trust current** re-learns after a legitimate change. Follows the passive-floor
doctrine so a healthy segment reads clean. Put the Pi on the **routed VLAN or a
SPAN/mirror** to observe OSPF.

**On vulnerabilities vs [OSV](https://osv.dev):** OSPF carries no software version
on the wire, so a version→CVE lookup isn't possible passively — the scanner
detects the *exposure conditions* instead (weak auth; opaque/TE LSAs, which are
the trigger for FRRouting ospfd DoS crashes such as CVE-2024-27913 /
CVE-2025-61107 / CVE-2025-61105, and equivalent Cisco ASA/FTD OSPF-LSA advisories)
and points at OSV for the version lookup. It **detects, never exploits**, and is
harmless to the network.

Small **CLI** (no web app / no root for the self-test):

```
python3 network_diagnostics.py ospf-watch [--iface eth0] [--seconds 15] [--json]
python3 network_diagnostics.py ospf-selftest
```

`ospf-selftest` drives the parser + classifier with synthetic captures (clean /
weak-auth / rogue-router / spoofed-LSA / MaxSequence / LSA-field parse) and, when
[Scapy](https://scapy.net) (`scapy.contrib.ospf`) is present, crafts a real OSPF
packet into a pcap and parses it back through `tcpdump` end to end.

- Endpoint: `GET /api/net/ospf-watch` `{interface, seconds}`,
  `POST /api/net/ospf-baseline` `{action: reset}` · binary: `tcpdump`

### BGP Path Watch
The L3-edge companion to the OSPF scanner — a **passive** BGP routing-security
scanner (TCP/179). **Detection-only**: it never opens a session or announces /
withdraws a route. BGP is where traffic gets silently redirected across the
Internet edge, so where it's visible this is the highest-value watch. It flags:

- **Injection (hijack)** — an announced prefix whose **origin AS changed** vs the
  learned baseline (prefix/origin hijack), or a **new more-specific** of a
  baseline prefix (sub-prefix hijack — the most effective real-world BGP attack).
- **Anomaly** — a new/rogue **peer** (new AS or BGP-ID), a **NOTIFICATION** /
  session reset (teardown/flap), a **bogon/martian** prefix announcement, a
  **reserved/documentation ASN** in a received path, an **AS-path loop**, or a
  **BLACKHOLE** community (65535:666).
- **Storm** — an UPDATE churn/flood, or a per-peer **prefix-count spike**
  (full-table route leak).
- **Weak session** — BGP seen but **no TCP-MD5/TCP-AO** signature (RFC 2385/5925),
  exposed to off-path session-reset attacks. Advisory only.

> **Visibility caveat:** unlike OSPF (multicast, on the broadcast domain), BGP is
> **unicast TCP/179 between routers** — the Pi must be **inline, on a SPAN/mirror,
> or a peer** to observe it. Private ASNs (RFC 6996, e.g. 65001) are treated as
> normal, since internal/DC fabric is the most likely place to see BGP passively.

The first scan learns the peers and prefix→origin map as the baseline
(`data/bgp_watch.json`); **Trust current** re-learns after a legitimate change.
As with OSPF, software-version CVEs aren't on the wire, so exposure conditions are
flagged (weak auth; malformed-UPDATE crash class — **CVE-2023-38802** /
**CERT VU#347067**) with an [OSV](https://osv.dev) pointer for the version lookup.

**ASN enrichment:** origin ASNs and peer IPs are enriched with AS **owner names**
+ country via [Team Cymru's IP-to-ASN](https://team-cymru.com/community-services/ip-asn-mapping/)
whois service, so a hijack reads `AS64500 (SOME-HOSTER, RU)` instead of a bare
number. This needs **outbound TCP/43** to `whois.cymru.com` and **fails soft** —
if your NOC egress filters it, the scan degrades to AS-number-only (a blocked
egress is negatively cached for 5 min so it doesn't add a timeout to every scan).
Results are cached for a day. Disable with `?enrich=0` on the endpoint or
`--no-enrich` on the CLI.

Small **CLI** (no web app / no root for the self-test):

```
python3 network_diagnostics.py bgp-watch [--iface eth0] [--seconds 15] [--json]
python3 network_diagnostics.py bgp-selftest
```

`bgp-selftest` drives the parser + classifier with synthetic captures (clean /
origin-hijack / sub-prefix hijack / session-reset / bogon-prefix / UPDATE parse)
and, when [Scapy](https://scapy.net) (`scapy.contrib.bgp`) is present, crafts a
real BGP packet into a pcap and parses it back through `tcpdump`.

- Endpoint: `GET /api/net/bgp-watch` `{interface, seconds}`,
  `POST /api/net/bgp-baseline` `{action: reset}` · binary: `tcpdump`

### BGP Collector & Path Asymmetry (control-plane ↔ data-plane)
Where BGP Path Watch is a passive **capture** scanner, this is the active-but-safe
pairing of **routing truth** with a **measured** data-plane symptom. Two cooperating
pieces:

**Receive-only BGP collector** (`bgp_speaker.py`) — a from-scratch BGP speaker
(RFC 4271 + 4-octet ASN RFC 6793) that opens a real session to a peer to *learn its
RIB*, but is **receive-only**: the FSM (Idle → Connect → OpenSent → OpenConfirm →
Established) sends only OPEN / KEEPALIVE and **never an UPDATE**, so it structurally
**cannot advertise or withdraw a route**. It decodes UPDATEs into an Adj-RIB-In with
per-prefix **churn/flap tracking** (a prefix changing origin/next-hop faster than a
threshold is marked *flapping*) and longest-prefix lookup. Point it at a router
configured to peer with the Pi's AS (a route-server client / passive peer works well).

**One-way-delay probe** (`path_asymmetry.py`) — a tiny UDP prober/reflector using the
OWAMP/TWAMP 4-timestamp model (T1 send, T2 remote-recv, T3 remote-send, T4 recv). It
computes forward and reverse delay separately and derives **path asymmetry**. Because
a single unsynced clock pair can't separate a constant offset from a constant
asymmetry, it uses the **Paxson min-pair estimator** (θ̂ = (min fwd − min rev)/2) to
cancel the clock offset and report *change-sensitive* asymmetry with hysteresis — so
it flags a **shift** in asymmetry without false-alarming on a static clock skew. Tick
**clocks PTP/GPS-synced** only if both ends are truly synchronized, in which case the
absolute number is trustworthy. Run the **reflector** on the far node (or here) so the
other side can measure both directions.

**Correlator** — when the collector is `Established`, each asymmetry event is
annotated with control-plane truth from the RIB: the covering prefix, origin AS,
AS-path, whether that prefix is currently flapping, and how recently it changed. The
attribution heuristic then labels the event **route-churn** (RIB is flapping — the
delay shift lines up with a real routing change), **recent path shift** (a fresh but
stable change), or **stable / data-plane** (no matching control-plane change — the
asymmetry is happening below BGP, e.g. a congested or re-routed transit leg).

> **Safety:** the collector never originates routing information, and the OWD probe is
> a handful of small UDP datagrams — neither injects state into the network. Both are
> long-lived daemons managed with start/stop/status; nothing is persisted to disk.

- Endpoints: `GET/POST /api/net/bgp-collector` `{action: start|stop|status|rib,
  peer_ip, peer_as, local_as, router_id, port, hold}`,
  `GET/POST /api/net/owd-reflector` `{action: start|stop|status, port}`,
  `POST /api/net/path-asymmetry` `{target, count, clock_synced}`
- CLI: `python3 path_asymmetry.py reflector [port]` runs a standalone reflector;
  `bgp_speaker.py` and `path_asymmetry.py` each expose `selftest()`, aggregated into
  the Detector Self-Test panel (`GET /api/net/routing-selftest`).

### Locate Port
Physically find **which switch port** the device is plugged into — the software
equivalent of a cable tester / toner probe. It **flaps the link** on the chosen
wired interface in a timed pattern (down/up, a configurable number of blinks),
so on the switch the port's **link LED** goes dark/lit in that cadence. Watch
the switch and the port blinking in sync is the one.

On a **managed** switch you don't need this — Switch Discovery already reports
the exact port over LLDP/CDP. Locate Port is the fallback for **unmanaged**
switches that only have link/activity LEDs.

Notes and safety:
- Physical Ethernet only (`eth*`/`en*`) — a link-flap only identifies a port on
  a wired link.
- It genuinely **drops the link** each cycle, so it briefly interrupts traffic
  on that port. If Ragnar is reachable *through* that port, the UI freezes until
  the sequence finishes — so the tool refuses the interface carrying the default
  route unless you confirm. It always restores the link when done, and runs in
  the background so it completes even if your session blips.

- Endpoint: `POST /api/net/locate-port` `{interface, count, force}` · uses `ip link`

### PCAP Analyzer
Upload a `.pcap` / `.pcapng` capture (from Wireshark, `tcpdump`, the L2 Link
Health scan, a SPAN/mirror port, …) and get instant triage — the Wireshark
*Statistics* menu in one click:

- **Summary** — packets, size, duration, average packet size, data rate,
  capture start/end and encapsulation (via `capinfos`).
- **Protocol hierarchy** — the full frame/byte breakdown per protocol
  (`tshark -z io,phs`), so you see at a glance what the capture is made of.
- **Top talkers** — the busiest IP conversations by exact byte count
  (aggregated from raw frame lengths, so the numbers are precise).
- **Expert info** — tshark's analysis flags grouped by severity: TCP
  **retransmissions**, **resets**, **duplicate ACKs**, zero-window, **malformed**
  packets, etc. — the fastest way to spot loss and protocol trouble.

**Wi-Fi / AP captures** get a dedicated analysis (when the capture contains
802.11 frames — i.e. a monitor-mode or AP-side capture). This is built to answer
the question field techs live with: **why are clients dropping?** It decodes:

- **Deauthentication & disassociation reason codes** (e.g. 15 = 4-way handshake
  timeout, 7 = class-3 frame from a non-associated STA, 4 = inactivity, 14 = MIC
  failure), counted and broken down **per client** so you see who's dropping.
- **Auth / association failure status codes** (e.g. 17 = AP can't handle more
  STAs / capacity).
- **EAPOL** (4-way handshake) volume, **retry rate** (RF-health proxy), and the
  **SSIDs** seen.
- Plain-language **heuristic findings** (handshake timeouts → PSK/RADIUS/timing,
  high retries → RF interference, capacity rejects, etc.) — useful even without
  AI.

**🧠 Explain with AI** — if the OpenAI integration is configured (see
[AI Integration](AI_INTEGRATION.md)), one click hands the capture summary to the
model (GPT-5-nano via the Responses API) with a senior-wireless-engineer prompt,
and it returns a **Verdict / Evidence / Other factors / Fix it** root-cause
analysis grounded in the actual reason codes and expert findings. Works for wired
captures too. If AI isn't enabled, the tool still shows the full decoded
breakdown — the AI just adds the interpretation.

The upload is size-guarded (100 MB), magic-byte validated (real pcap/pcapng
only), analyzed **read-only** with `tshark`, and the temp file is deleted
immediately after. Nothing is stored.

- Endpoints: `POST /api/net/pcap` (multipart `file`),
  `POST /api/ai/pcap` (AI interpretation) · binary: `tshark` (+ `capinfos`)

---

## 🔗 Interfaces

The physical/link truth about this device's own network interfaces, plus the
identity of the network it's attached to.

### Interface list
For every interface (Ethernet and WiFi; virtual/loopback optionally included):

- **Type** — **ethernet**, **wifi**, or **VPN**. VPN/tunnel links (WireGuard,
  Tailscale, OpenVPN in tun *and* tap mode, ZeroTier, PPP/L2TP, GRE/IPsec, …)
  are detected robustly — by the interface's tun/tap device flags and link type
  (`ip -d link`, `wg show`), not just its name — so even a custom-named tunnel
  is flagged as **VPN** rather than being mistaken for a real wired port. (VM
  tap interfaces like `vnet*`/`macvtap*` are treated as virtual, not VPN.)
- **MAC address** and **operational state** (up/down)
- **IPv4 / IPv6 addresses** (link-local `fe80::` filtered out)
- **IP method** — how the address was obtained: `dhcp`, `static`,
  `dhcp-failed` (APIPA 169.254.x.x, i.e. DHCP was attempted but no server
  answered), or `link-down`
- **Link details** (wired) via `ethtool` — negotiated **speed**, **duplex**,
  **auto-negotiation** on/off, and whether **link is detected**
- **VLAN** id and protocol when the interface is a VLAN sub-interface

This tells you at a glance whether a port negotiated at the speed/duplex you
expect (a half-duplex or 100 Mbps link where you expected gigabit is a classic
cabling/auto-neg fault), and whether an interface actually pulled a DHCP lease.

- Endpoint: `GET /api/net/interfaces` · binary: `ethtool` for link details
  (address/method info uses `ip`, always present)

### Network Identity
A best-effort summary of the network Ragnar is *attached to*, merged from
several sources (with provenance reported, since no single source is
authoritative):

- **Hostname / FQDN** of this device
- **DNS search domain(s)** and **nameservers** — pulled from
  `/etc/resolv.conf`, and when that only shows the systemd-resolved stub
  (`127.0.0.53`), the real upstream servers are recovered from
  `nmcli` / `resolvectl`
- **Default gateway** IP, with its **reverse-DNS (PTR)** name — often reveals
  the router/firewall model or naming scheme
- **Traffic via VPN** — whether this host's internet traffic is egressing
  through a VPN. Reads the IPv4 **default route**: if it leaves via a tunnel
  interface (`tun*`/`wg*`/`tailscale0`/…) the answer is **yes (via `<iface>`)**,
  even when the physical uplink is a normal `eth0`/`wlan0`. This catches
  full-tunnel VPNs / exit nodes that silently reroute everything.

- Endpoint: `GET /api/net/identity`

### ISP / WAN Detection
Detects the **public IP and ISP/ASN reached *through each interface***. On a
**multi-WAN** box (two or more uplinks to different providers) this is the fast
way to answer "which physical link goes to which ISP, and is each one actually
reaching the internet?" — invaluable when one of several uplinks is flaky or
resistant.

For each interface with a usable IPv4, Ragnar runs a lookup **bound to that
interface** (`curl --interface <iface>`, which forces egress out that link via
`SO_BINDTODEVICE` regardless of the routing table) and reports:

- **ISP** and **ASN** (e.g. `Tele2 Sverige AB` / `AS1257`)
- **Public IP** seen from the internet through that link
- **Location** (city / region / country) of that egress
- **Source** — which geo-IP service answered
- **VPN** — is this link *behind* a VPN? Flagged when the interface is itself a
  tunnel (`🔒 WireGuard`, `🔒 Tailscale`, `🔒 OpenVPN`, …), or when the public
  egress ASN belongs to a known VPN provider/backbone (`🔒 likely (mullvad)`,
  `m247`, …). The VPN **technology** is identified from the interface's link
  type (`ip -d link`) and name (Tailscale/NordVPN/Mullvad/ProtonVPN/ZeroTier/
  GRE/IPsec…), and for WireGuard the **peer endpoint** (the VPN server `IP:port`)
  is shown when the `wg` tool is available. A tunnel with no separate internet
  egress is shown as the VPN it is rather than as a failed WAN. The ASN-based
  provider match is best-effort ("likely"), since many VPNs share hosting ASNs.

Lookups use **ipinfo.io** over HTTPS first, falling back to **ip-api.com**. A
VPN tunnel with no separate internet egress is shown as the VPN it is (technology
+ endpoint); a genuinely **dead WAN** — a non-tunnel interface with no working
internet path — reports an explicit error rather than a value, which is itself
the diagnostic you're after.

> **Privacy:** this makes an outbound request to a third-party geo-IP service,
> revealing the device's public IP to it. It is **on-demand only** (triggered by
> the *Detect ISPs* button), never polled in the background.

- Endpoint: `GET /api/net/isp` (all interfaces) or
  `GET /api/net/isp?interface=<iface>` · binary: `curl`

> The **Speed Test** in Diagnostics also reports the ISP for the default path
> (from the speedtest client's own geolocation) — ISP / WAN Detection is the
> per-interface complement for multi-homed setups.

### VPN Egress Check
A focused **"is my traffic leaving through a VPN?"** verdict for one path,
combining every signal Ragnar has. It follows the **default route** by default,
or a specific `interface` if you pass one (e.g. to test the LAN path while WiFi
carries the default route). Returns **vpn / likely / no / unknown**:

- **Local tunnel** — the egress interface is itself a tunnel (WireGuard /
  Tailscale / OpenVPN / IPsec / GRE …), identified from the link type
  (`ip -d link`) and name, with the WireGuard **peer endpoint** when `wg` is
  available.
- **Known-VPN egress IP** — the public egress IP falls inside a **known
  VPN-provider range** (an ASN-derived list synced locally from
  [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) and checked offline).
  This is the signal that catches a VPN running **on the router**, where
  Ragnar's own NIC looks like an ordinary LAN port.
- **Tor exit** — the egress is confirmed a Tor exit node via the Tor Project's
  own checker (again catching Tor/VPN upstream on the router).
- **Provider ASN name** — the egress ISP/ASN name matches a commercial-VPN
  provider or VPN-hosting backbone (`mullvad`, `m247`, …) → *likely* (best-effort,
  since many VPNs share hosting ASNs).

This complements the per-interface [ISP / WAN Detection](#isp--wan-detection)
above: that answers "which link goes to which ISP", this answers "is *this* path
behind a VPN — including one running on the router that the interface heuristics
alone would miss".

> **Privacy:** makes outbound calls (geo-IP + the Tor checker) bound to the
> tested interface. On-demand only, never polled.

- Endpoint: `GET /api/net/vpn-check` or
  `GET /api/net/vpn-check?interface=<iface>` · binary: `curl`

---

## Design notes

- **Never blocks, never crashes the app.** The command runner treats a missing
  binary as exit code 127, a timeout as 124, and any other failure as a plain
  error string — no tool can hang the web UI or raise into the request handler.
- **On-demand by default.** Tools run when you ask them to; the ones that touch
  the wire (Locate Port's link-flap, L2 Link Health and PTP captures, ISP/VPN
  lookups) are always explicit, button-triggered actions. The single background
  poller is the opt-in [Network Integrity Monitor](#-network-integrity-monitor),
  which is off unless you enable it.
- **CSV export** is available for the Switch Discovery, ARP Scan, MAC Watch,
  Interfaces, Network Identity and ISP / WAN tables.
- **Offline-capable.** Everything except the internet-facing tools (Speed Test,
  ISP/WAN detection, DoH/DoT reachability) works with no internet at all —
  ping/MTR to local hosts, DNS against local resolvers, LLDP/PoE, ARP scan,
  L2 health, interfaces, PMTU, iperf3, flow telemetry, PTP and Locate Port are
  all local to the segment, which is the whole point of a field tool.

---

*Network Tools co-authored by [Solarflere](https://www.instagram.com/solarflere).*

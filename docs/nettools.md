# 🌐 Network Tools

The **Network** tab in the Ragnar web interface is a built-in network engineer's
toolbox — everything you'd normally reach for a laptop, a terminal and a bag of
CLI tools to do, run straight from the device that's already sitting on the
segment you care about.

It is split into three sub-tabs: **Diagnostics**, **Switch & L2**, and
**Interfaces**.

> **Co-authored by [Solarflere](https://www.instagram.com/solarflere).** The
> Network Tools suite was designed and built in collaboration with Solarflere.

All tools are served under `/api/net/*` by `network_diagnostics.py`, a
self-contained module wrapped so a failure there can never take down the rest of
the web app. Nothing runs as a background daemon — each tool executes on demand
when you click it.

### Tool index

| Tool | Sub-tab | Endpoint |
|------|---------|----------|
| [Ping](#ping) | Diagnostics | `POST /api/net/ping` |
| [Traceroute](#traceroute) | Diagnostics | `POST /api/net/traceroute` |
| [MTR](#mtr) | Diagnostics | `POST /api/net/mtr` |
| [WHOIS](#whois) | Diagnostics | `POST /api/net/whois` |
| [DNS Doctor](#dns-doctor) | Diagnostics | `POST /api/net/dns` |
| [Path MTU / Black-hole](#path-mtu--black-hole) | Diagnostics | `POST /api/net/pmtu` |
| [Captive Portal Check](#captive-portal-check) | Diagnostics | `GET /api/net/captive-portal` |
| [LAN Throughput (iperf3)](#lan-throughput-iperf3) | Diagnostics | `POST /api/net/iperf3`, `/iperf3-server` |
| [Speed Test](#speed-test) | Diagnostics | `POST /api/net/speedtest` |
| [Live Flow Telemetry](#live-flow-telemetry) | Diagnostics | `GET /api/net/flows` |
| [PTP Timing Detection](#ptp-timing-detection) | Diagnostics | `POST /api/net/ptp` |
| [E-Paper Network Diagnostic Mode](#-e-paper-network-diagnostic-mode) | Diagnostics (toggle) | config `network_diagnostic_mode` |
| [Switch Discovery + PoE](#switch-discovery-lldp--cdpv1v2--edp--fdp) | Switch & L2 | `GET /api/net/lldp` |
| [ARP Scan](#arp-scan) | Switch & L2 | `GET /api/net/arp-scan` |
| [L2 Link Health](#l2-link-health) | Switch & L2 | `POST /api/net/l2-health` |
| [Locate Port](#locate-port) | Switch & L2 | `POST /api/net/locate-port` |
| [PCAP Analyzer](#pcap-analyzer) | Switch & L2 | `POST /api/net/pcap` |
| [Interfaces](#interface-list) | Interfaces | `GET /api/net/interfaces` |
| [Network Identity](#network-identity) | Interfaces | `GET /api/net/identity` |
| [ISP / WAN + VPN Detection](#isp--wan-detection) | Interfaces | `GET /api/net/isp` |

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

---

## 🖥️ E-Paper Network Diagnostic Mode

A toggle at the top of the Diagnostics sub-tab turns the **e-Paper display**
into a standalone, Ethernet-focused field tool — so you can plug the device
into a switch and read the essentials off the screen with **no laptop and no
internet**. Everything shown is gathered locally (`ip` / `ethtool` /
`lldpctl` / `resolv.conf`), so it works on an isolated or dead network.

The display auto-cycles three pages every **5 seconds**:

1. **LINK** — the physical wired port: interface, link up/down, negotiated
   speed, duplex, auto-negotiation, MAC. (Instantly spot a port that fell back
   to 100 Mbps or half-duplex.)
2. **IP** — addressing: DHCP vs static, IPv4/CIDR, default gateway (with its
   reverse-DNS name), and DNS servers.
3. **SWITCH** — the switch you're plugged into, via LLDP/CDP: switch name, the
   **exact port** (e.g. `GigabitEthernet1/0/12`), VLAN, **PoE** class/wattage,
   protocol, and management IP.

It focuses on the **physical** wired NIC (`eth*` / `en*`), ignoring VPN,
tunnel, bridge and container interfaces. Toggle it off to restore the normal
Ragnar display. The setting is persisted (`network_diagnostic_mode` in the
config) and shared across sessions.

> Applies to the e-Paper display. Headless installs (no display) accept the
> toggle but have nothing to render it on.

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
**DNSSEC AD** (authenticated) flag, and status. It then tells you whether all
resolvers **agree** — a mismatch is the fingerprint of split-DNS or DNS
hijacking. Also reports **DoH** (443) and **DoT** (853) reachability. Far more
than a name→IP lookup: it's a resolver-health and integrity check.

- Endpoint: `POST /api/net/dns` `{name}` · binary: `dig` (`dnsutils`)

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

## 🔌 Switch & L2

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
  Tailscale, OpenVPN tun/tap, ZeroTier, PPP/L2TP, …) are detected by name and
  by their tunnel link type, and flagged as **VPN** rather than being lumped in
  with physical Ethernet — so a `tailscale0` or `wg0` is obvious at a glance and
  isn't mistaken for a real wired port.
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

---

## Design notes

- **Never blocks, never crashes the app.** The command runner treats a missing
  binary as exit code 127, a timeout as 124, and any other failure as a plain
  error string — no tool can hang the web UI or raise into the request handler.
- **On-demand only.** Nothing polls in the background; a tool runs when you ask
  it to. Tools that touch the wire (Locate Port's link-flap, L2 Link Health and
  PTP captures, ISP lookups) are always explicit, button-triggered actions.
- **CSV export** is available for the Switch Discovery, ARP Scan, Interfaces,
  Network Identity and ISP / WAN tables.
- **Offline-capable.** Everything except the internet-facing tools (Speed Test,
  ISP/WAN detection, DoH/DoT reachability) works with no internet at all —
  ping/MTR to local hosts, DNS against local resolvers, LLDP/PoE, ARP scan,
  L2 health, interfaces, PMTU, iperf3, flow telemetry, PTP and Locate Port are
  all local to the segment, which is the whole point of a field tool.

---

*Network Tools co-authored by [Solarflere](https://www.instagram.com/solarflere).*

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
`whois`, `speedtest-cli`, `lldpd`, `arp-scan`, `ethtool`), so the tool name is
never interpolated into a shell command.

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

### Speed Test
Download/upload/latency bandwidth test. Supports both the Ookla `speedtest` CLI
and the Python `speedtest-cli`, reporting download/upload in Mbps, ping in ms,
and the chosen server and ISP. If neither client is present it self-installs
`speedtest-cli` on demand so the button always works.

- Endpoint: `POST /api/net/speedtest` · binary: `speedtest-cli` or `speedtest`

---

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
- **Power class** (e.g. class 3)
- **Standard** — 802.3af (Type 1) or 802.3at (Type 2)
- **Allocated / requested wattage**

> **Note:** this reflects PoE *as advertised by the switch over LLDP*. An
> unmanaged PoE injector, or a switch with LLDP-MED power TLVs turned off, won't
> advertise it — so a blank PoE column means "not advertised", not a guaranteed
> "no power".

### ARP Scan
Sweeps the local segment with ARP to enumerate **live hosts** on a chosen
interface, returning IP, MAC and (where known) NIC vendor for each responder.
The fastest way to inventory a subnet you're attached to. Results export to CSV.

- Endpoint: `GET /api/net/arp-scan?interface=<iface>` · binary: `arp-scan`

---

## 🔗 Interfaces

The physical/link truth about this device's own network interfaces, plus the
identity of the network it's attached to.

### Interface list
For every interface (Ethernet and WiFi; virtual/loopback optionally included):

- **Type** — ethernet or wifi
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

- Endpoint: `GET /api/net/identity`

---

## Design notes

- **Never blocks, never crashes the app.** The command runner treats a missing
  binary as exit code 127, a timeout as 124, and any other failure as a plain
  error string — no tool can hang the web UI or raise into the request handler.
- **On-demand only.** Nothing polls in the background; a tool runs when you ask
  it to.
- **CSV export** is available for the Switch Discovery and ARP Scan tables.

---

*Network Tools co-authored by [Solarflere](https://www.instagram.com/solarflere).*
